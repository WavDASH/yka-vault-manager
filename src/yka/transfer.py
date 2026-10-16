"""Verified file-level recovery through mounted filesystems, never ciphertext paths."""
from contextlib import contextmanager, ExitStack
import ctypes
import hashlib
import msvcrt
import os
from pathlib import Path
import re
import shutil
import time
import uuid
import win32con
import win32file
import win32api
import psutil
import pywintypes
from .windows import VaultError, safe_path, pinned_parents, guarded_reader, mount_device
from .registry import path_key

CHUNK = 1024 * 1024


def copy_error(error):
    if isinstance(error, pywintypes.error):
        return {32: 'A file is in use. Close it in other programs and try again.',
                33: 'A file is locked by another program. Close it and try again.',
                5: 'Access was denied. Check the source and destination permissions.',
                112: 'The destination is full. Free some space and try again.',
                2: 'A selected file is no longer available. Choose it again.',
                3: 'A selected folder is no longer available. Check the drive and choose it again.'}.get(error.winerror,
                    'A file or folder could not be accessed. Check the drive connection and permissions, then try again.')
    return str(error) if isinstance(error, (VaultError, OSError)) else 'The copy stopped. Check both locations before trying again.'


def within(path, parent):
    return path_key(path) == path_key(parent) or path_key(parent) in [path_key(p) for p in Path(path).parents]


def identity(stream):
    stat = os.fstat(stream.fileno())
    return [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns]


def check_streams(source, paths):
    # GetVolumePathName can reject a WinFsp drive with ERROR_UNRECOGNIZED_VOLUME.
    # The checked, owned mount root is already known; query that filesystem itself.
    owner = paths.owner(source)
    volume = str(owner[0]).rstrip('\\') + '\\' if owner else win32file.GetVolumePathName(str(source))
    streams = win32file.FindStreams(str(source)) if win32api.GetVolumeInformation(volume)[3] & 0x40000 else []
    if any(name != '::$DATA' for _, name in streams):
        raise VaultError("Files with alternate data streams are not supported.")


class Paths:
    """Only the exact owned WinFsp mount root may be a reparse point."""
    def __init__(self, manager):
        with manager.session_mutex:
            self.mounts = [(Path(os.path.abspath(point)), session.mount_device) for _, session, point in manager.sessions.values() if session.process.poll() is None]

    def owner(self, path):
        return next(((point, device) for point, device in self.mounts if within(path, point)), None)

    def checked(self, path, *, must_exist=False):
        path = Path(os.path.abspath(path)); owner = self.owner(path)
        if not owner: return safe_path(path, must_exist=must_exist)
        point, device = owner
        if mount_device(str(point)) != device: raise VaultError('The mounted filesystem changed. Transfer stopped.')
        # Validate names using a non-mounted anchor, then inspect children without
        # following arbitrary links. The known mount junction itself is deliberate.
        from .archive import entry_path
        relative = path.relative_to(point)
        if str(relative) != '.': entry_path('files/' + relative.as_posix())
        if point.parent != point: safe_path(point.parent, must_exist=True)
        for candidate in [path, *path.parents]:
            if candidate == point: break
            try:
                if candidate.lstat().st_file_attributes & 0x400: raise VaultError('Links inside a transfer path are not supported.')
            except FileNotFoundError:
                if candidate == path and must_exist: raise VaultError('A transfer file or folder is unavailable.')
        if must_exist and not path.exists(): raise VaultError('A transfer file or folder is unavailable.')
        return path

    def validate_handle(self, handle, path):
        owner = self.owner(path)
        if owner:
            actual = win32file.GetFinalPathNameByHandle(handle, 2).casefold().rstrip('\\')
            expected = owner[1].casefold().rstrip('\\')
            if actual != expected and not actual.startswith(expected + '\\'):
                raise VaultError('The opened file belongs to a different mounted filesystem.')

    @contextmanager
    def parents(self, path):
        path = self.checked(path); handles = []
        try:
            for parent in reversed(path.parents):
                owner = self.owner(parent)
                flags = 0x02000000 | (0 if owner and parent == owner[0] else 0x00200000)
                handle = win32file.CreateFile(str(parent), win32con.GENERIC_READ,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None, win32con.OPEN_EXISTING, flags, None)
                handles.append(handle)
                if win32file.GetFileInformationByHandle(handle)[0] & 0x400: raise VaultError('A transfer parent is a link.')
                self.validate_handle(handle, parent)
            yield path
        finally:
            for handle in handles: handle.Close()


@contextmanager
def locked_file(path, paths, *, writable=False):
    with paths.parents(path):
        access = win32con.GENERIC_READ | (win32con.GENERIC_WRITE if writable else 0)
        handle = win32file.CreateFile(str(paths.checked(path, must_exist=True)), access, win32con.FILE_SHARE_READ,
            None, win32con.OPEN_EXISTING, win32con.FILE_FLAG_SEQUENTIAL_SCAN | 0x00200000, None)
        info = win32file.GetFileInformationByHandle(handle)
        if info[0] & (0x400 | win32con.FILE_ATTRIBUTE_DIRECTORY) or info[7] > 1:
            handle.Close(); raise VaultError('Transfer supports regular files without links only.')
        try: paths.validate_handle(handle, path)
        except BaseException: handle.Close(); raise
        with os.fdopen(msvcrt.open_osfhandle(handle.Detach(), os.O_RDWR if writable else os.O_RDONLY), 'r+b' if writable else 'rb') as stream:
            yield stream


def remove_partial(path, paths):
    """Delete the checked file handle, without following links or resolving it again."""
    from ctypes import wintypes
    with paths.parents(path):
        try:
            handle = win32file.CreateFile(str(path), win32con.DELETE | win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ, None, win32con.OPEN_EXISTING, 0x00200000 | 0x02000000, None)
        except pywintypes.error as error:
            if error.winerror == 2: return  # Already renamed or cleaned on an earlier attempt.
            raise
        try:
            info = win32file.GetFileInformationByHandle(handle)
            if info[0] & (0x400 | win32con.FILE_ATTRIBUTE_DIRECTORY) or info[7] > 1:
                raise VaultError('A transfer temporary file was replaced by a link or folder.')
            paths.validate_handle(handle, path)
            delete = ctypes.c_ubyte(1)
            function = ctypes.WinDLL('kernel32', use_last_error=True).SetFileInformationByHandle
            function.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
            function.restype = wintypes.BOOL
            if not function(int(handle), 4, ctypes.byref(delete), ctypes.sizeof(delete)):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            handle.Close()


class Transfer:
    def __init__(self, manager):
        self.manager = manager; self.store = manager.jobs
        self.paths = Paths(manager)
        self.last_progress = 0; self.started = time.monotonic(); self.copied = 0

    def check(self):
        if self.manager.cancel.is_set() or self.manager.security_pending.is_set():
            raise VaultError('Copy cancelled.')
        for point, device in getattr(self, 'bindings', []):
            if mount_device(point) != device: raise VaultError('The vault disconnected or its mount changed. Mount it again before retrying.')

    def digest(self, stream):
        stream.seek(0); hashed = hashlib.sha256()
        while chunk := stream.read(CHUNK): self.check(); hashed.update(chunk)
        return hashed.hexdigest()

    def cleanup_partials(self, task, index, item, target):
        # Never scan a folder or accept arbitrary paths from a saved journal.
        pattern = rf'\.yka-transfer-{re.escape(task["id"])}-{index}-[0-9a-f]{{32}}\.partial'
        partials = [Path(value) for value in item.get('partials', [])]
        for partial in partials:
            if (not partial.is_absolute() or path_key(partial.parent) != path_key(target.parent)
                    or not re.fullmatch(pattern, partial.name)):
                raise VaultError('The saved transfer temporary-file path is invalid. No files were removed.')
        for partial in partials:
            self.check()
            try:
                remove_partial(partial, self.paths)
            except (OSError, pywintypes.error, VaultError) as error:
                raise VaultError('The file was copied, but its temporary files could not be removed. ' + copy_error(error)) from None
        item['partials'] = []

    def endpoints(self, paths, expected=None):
        records = self.manager.registry.records(); bindings = []; saved = []
        for path in paths:
            for record in records:
                if within(path, record['path']): raise VaultError('Choose the mounted folder, not a vault encrypted-data folder.')
            match = None
            with self.manager.session_mutex:
                for root, (_, session, point) in self.manager.sessions.items():
                    if within(path, point):
                        if session.process.poll() is not None or mount_device(point) != session.mount_device:
                            raise VaultError('Vault ownership is not confirmed. Resolve its mount status first.')
                        match = self.manager.registry.by_path(root)
                        bindings.append((point, session.mount_device))
                        saved.append(dict(path=str(path), record_id=match['id'], uuid=match['uuid'], signing_public=match['signing_public'], relative=os.path.relpath(path, point)))
            if match is None:
                for record in records:
                    point = (record.get('last_mount') or {}).get('mount_point') or record.get('mount_point')
                    if point and within(path, point): raise VaultError('This saved mount is not managed by the current worker. Mount it normally before transferring.')
                saved.append(dict(path=str(path), record_id=None, device=mount_device(str(path if Path(path).is_dir() else Path(path).parent))))
        self.validate_direction(saved)
        if expected and saved != expected: raise VaultError('Transfer endpoints changed. Restore the original paths and vault identities before resuming.')
        self.bindings = list(set(bindings))
        return saved

    @staticmethod
    def validate_direction(endpoints):
        destination = endpoints[-1]
        for source in endpoints[:-1]:
            if not source.get('record_id') and not destination.get('record_id'):
                raise VaultError('Choose a mounted vault as the source or destination.')
            if source.get('record_id') and destination.get('record_id'):
                if (source['record_id'] == destination['record_id'] or
                    (source.get('uuid'), source.get('signing_public')) ==
                    (destination.get('uuid'), destination.get('signing_public'))):
                    raise VaultError('Choose a different vault or a Windows folder.')

    def plan(self, args):
        sources = [self.paths.checked(p, must_exist=True) for p in args['sources']]
        destination = self.paths.checked(args['destination'], must_exist=True)
        if not sources or len(sources) > 1000 or not destination.is_dir(): raise VaultError('Choose files or folders and an existing destination folder.')
        if args.get('mode', 'copy') != 'copy': raise VaultError('Move is no longer supported. Start a new copy instead.')
        if not isinstance(args.get('verify', True), bool): raise VaultError('Choose whether to verify copied files.')
        self.validate_selection(args, sources, destination)
        for source in sources:
            if within(destination, source): raise VaultError('The destination cannot be inside a source folder.')
        endpoints = self.endpoints([*sources, destination])
        interrupted = [t for t in self.store.records()
            if t.get('action') == 'transfer' and t.get('mode', 'copy') == 'copy'
            and t.get('state') in ('Cancelled', 'Failed', 'Interrupted')
            and t.get('sources') == [str(p) for p in sources]
            and t.get('destination') == str(destination)]
        if interrupted:
            if len(interrupted) != 1:
                raise VaultError('More than one interrupted copy matches these locations. Choose a new destination folder.')
            task = self.store.load(interrupted[0]['id'])
            if task.get('endpoints') != endpoints:
                raise VaultError('The original transfer locations or vault identities changed. Choose a new destination folder.')
            if task.get('verify', True) != args.get('verify', True):
                raise VaultError('Use the same Verify copied files setting as the interrupted copy, or choose a new destination folder.')
            # Do not silently omit files added after the original folder selection.
            expected = {(str(self.paths.checked(f['source'])), 'file') for f in task['files']}
            expected.update((str(destination / d), 'directory') for d in task['directories'])
            actual = set()
            def collect(path, relative):
                self.check(); path = self.paths.checked(path, must_exist=True)
                if path.is_dir():
                    actual.add((str(destination / relative), 'directory'))
                    for child in path.iterdir(): collect(child, relative / child.name)
                else: actual.add((str(path), 'file'))
                if len(actual) > 100000: raise VaultError('Split this transfer into fewer than 100,000 entries.')
            for source in sources: collect(source, Path(source.name))
            if actual != expected:
                raise VaultError('The source file list changed since the interrupted copy. Choose a new destination folder.')
            task['last_resumed'] = time.time()
            self.manager.progress('An interrupted copy was found. Checking completed files before continuing…')
            return task
        files = []; directories = []; names = set()
        def add(source, relative):
            self.check(); self.paths.checked(source, must_exist=True)
            key = relative.as_posix().casefold()
            if key in names: raise VaultError('Two selected items have the same destination name.')
            names.add(key)
            if len(names) > 100000: raise VaultError('Split this transfer into fewer than 100,000 entries.')
            if source.is_dir():
                directories.append(str(relative))
                for child in sorted(source.iterdir()): add(child, relative / child.name)
            else:
                with locked_file(source, self.paths) as stream:
                    check_streams(source, self.paths)
                    st = identity(stream)
                target = self.paths.checked(destination / relative)
                if target.exists(): raise VaultError(f'A file named {relative} already exists in the destination folder. Choose another location.')
                files.append(dict(source=str(source), relative=str(relative), original=st, state='Pending', size=st[2]))
        for source in sources: add(source, Path(source.name))
        return self.store.start('transfer', sources=[str(p) for p in sources], destination=str(destination),
            mode='copy', verify=args.get('verify', True), endpoints=endpoints, files=files, directories=directories,
            total_bytes=sum(f['size'] for f in files), completed_files=0, total_files=len(files))

    def validate_selection(self, args, sources, destination):
        # Optional UI selection pins: direct recovery clients retain path-based use.
        selections = args.get('selections', [])
        if not selections: return
        if len(selections) != len(sources) + 1: raise VaultError('Choose the source and destination again.')
        actual = self.endpoints([*sources, destination])
        for path, chosen, owner in zip([*sources, destination], selections, actual):
            if chosen.get('record_id'):
                record = self.manager.registry.get(chosen['record_id'])
                if (not owner or owner.get('record_id') != chosen['record_id'] or
                    owner.get('uuid') != chosen.get('uuid') or not within(path, chosen.get('mount_point', '')) or
                    not any(point == chosen['mount_point'] for point, _ in self.bindings)):
                    raise VaultError('The selected vault is no longer mounted at this location. Choose it again.')
            elif owner and owner.get('record_id'):
                raise VaultError('This location is a mounted vault. Choose that vault from the list first.')

    def run(self, args):
        try: return self._run(args)
        except pywintypes.error as error: raise VaultError(copy_error(error)) from None

    def _run(self, args):
        task = self.store.load(args['task_id']) if args.get('task_id') else self.plan(args)
        if task.get('action') != 'transfer': raise VaultError('This task cannot be resumed as a copy.')
        if task.get('mode', 'copy') != 'copy':
            raise VaultError("This older Move task cannot be resumed. Review its files and start a new copy.")
        verify_content = task.get('verify', True)  # Older copy tasks always verified.
        if not isinstance(verify_content, bool): raise VaultError('The saved verification setting is invalid.')
        self.endpoints([*task['sources'], task['destination']], task['endpoints'])
        from .windows import VaultGuard
        lease = self.store.directory / task['id']; lease.mkdir(exist_ok=True)
        with VaultGuard(lease), ExitStack() as pins:
            task.update(state='Running', pid=os.getpid(), process_started=psutil.Process().create_time())
            if args.get('task_id'): task['last_resumed'] = time.time()
            task.pop('ended', None)
            self.store.save(task)
            try:
                destination = self.paths.checked(task['destination'], must_exist=True)
                pins.enter_context(self.paths.parents(destination / '.yka-transfer-pin'))
                for relative in task['directories']:
                    target = self.paths.checked(destination / relative)
                    if not within(target, destination): raise VaultError('Invalid task destination.')
                    with self.paths.parents(target): target.mkdir(exist_ok=True)
                processed = 0
                for index, item in enumerate(task['files']):
                    task['_dirty_file'] = (index, item)
                    self.check()
                    source = self.paths.checked(item['source'])
                    if not any(within(source, selected) for selected in task['sources']): raise VaultError('Invalid source in task journal.')
                    target = self.paths.checked(destination / item['relative'])
                    if not within(target, destination) or target == destination: raise VaultError('Invalid task destination.')
                    self.manager.progress(f"Checking {item['relative']} — {index}/{len(task['files'])} files completed.")
                    with locked_file(source, self.paths) as original:
                        check_streams(source, self.paths)
                        if identity(original) != item['original']: raise VaultError(f"The source changed: {item['relative']}. Start a new copy to another folder.")
                        if target.exists():
                            if not verify_content:
                                raise VaultError("This copy was not verified and already has destination files. Start a new copy to an empty folder.")
                            if not item.get('digest') or item['state'] not in ('Publishing', 'Verified'):
                                raise VaultError('The destination already contains this file. Choose another folder.')
                            expected = self.digest(original)
                            with locked_file(target, self.paths, writable=True) as copied_file:
                                os.fsync(copied_file.fileno())
                                if expected != item['digest'] or self.digest(copied_file) != expected: raise VaultError('Source or completed destination content changed. Resume stopped. Start a new copy to another folder.')
                            item['state'] = 'Verified'
                        else:
                            if verify_content and item.get('digest') and self.digest(original) != item['digest']: raise VaultError('Source content changed since the previous attempt.')
                            if shutil.disk_usage(destination).free < item['size'] + 4 * CHUNK: raise VaultError('Not enough free destination space. Free some space and try again.')
                            temporary = target.with_name(f'.yka-transfer-{task["id"]}-{index}-{uuid.uuid4().hex}.partial')
                            item.setdefault('partials', []).append(str(temporary)); item['state'] = 'Copying'; self.store.save(task)
                            hashed = hashlib.sha256() if verify_content else None
                            original.seek(0); copied = 0
                            with self.paths.parents(temporary), temporary.open('xb') as output:
                                self.paths.validate_handle(msvcrt.get_osfhandle(output.fileno()), temporary)
                                while chunk := original.read(CHUNK):
                                    self.check(); output.write(chunk)
                                    if hashed is not None: hashed.update(chunk)
                                    copied += len(chunk); self.copied += len(chunk)
                                    now = time.monotonic()
                                    if now - self.last_progress >= .25:
                                        self.manager.progress(f"Copying {item['relative']} — {index}/{len(task['files'])} files completed ({(processed+copied)*100//max(task['total_bytes'],1)}%) · {self.copied/1024**2/max(now-self.started,.01):.1f} MiB/s")
                                        self.last_progress = now
                                output.flush(); os.fsync(output.fileno())
                            if copied != item['size'] or identity(original) != item['original']: raise VaultError('The source changed during copying. Start a new copy to another folder.')
                            if verify_content:
                                self.manager.progress(f"Verifying {item['relative']}…")
                                with locked_file(temporary, self.paths) as copied_file:
                                    if self.digest(copied_file) != hashed.hexdigest(): raise VaultError('The copied file does not match its source. Start a new copy to another folder.')
                                item['digest'] = hashed.hexdigest()
                            item['state'] = 'Publishing'; self.store.save(task)
                            self.check()
                            with self.paths.parents(target): os.rename(temporary, target)
                            with locked_file(target, self.paths, writable=True) as copied_file:
                                os.fsync(copied_file.fileno())
                                if identity(copied_file)[2] != item['size']: raise VaultError('The destination file has the wrong size. Start a new copy to another folder.')
                                if verify_content and self.digest(copied_file) != item['digest']: raise VaultError('The copied file does not match its source. Start a new copy to another folder.')
                            item['state'] = 'Verified' if verify_content else 'Copied'
                    self.cleanup_partials(task, index, item, target)
                    processed += item['size']; task['completed_files'] = index + 1; self.store.save(task)
                count = len(task['files'])
                message = f"{count} file{'s were' if count != 1 else ' was'} copied" + (' and verified successfully.' if verify_content else ' successfully. Content verification was skipped.')
                self.store.finish(task, 'Completed', message)
                return dict(task_id=task['id'], completed_files=count, verified=verify_content, path=task['destination'], message=message)
            except BaseException as error:
                state = 'Cancelled' if self.manager.cancel.is_set() or self.manager.security_pending.is_set() else 'Failed'
                reason = copy_error(error)
                detail = f"{task.get('completed_files', 0)} of {len(task['files'])} files completed. {reason}"
                self.store.finish(task, state, detail)
                if isinstance(error, (VaultError, OSError, pywintypes.error)): raise VaultError(detail) from None
                raise
