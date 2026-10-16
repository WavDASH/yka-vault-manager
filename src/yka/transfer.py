"""Stateless file copying through mounted filesystems, never ciphertext paths."""
from contextlib import contextmanager, ExitStack, closing
import ctypes
import hashlib
import msvcrt
import os
from pathlib import Path
import shutil
import time
import uuid
import win32con
import win32file
import win32api
import pywintypes
from .windows import VaultError, safe_path, mount_device

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


def canonical_path(path):
    """Resolve DOS aliases once, including existing parents of a new destination.

    Do not memoize candidate paths: their aliases can change between operations.
    This is a name comparison only; checked() and opened handles enforce safety.
    """
    path = str(path)
    if len(path) == 2 and path[1] == ':': path += '\\'
    original = os.path.abspath(path); candidate = Path(original); suffix = []
    while True:
        try:
            long = win32api.GetLongPathName(str(candidate))
            return os.path.normcase(os.path.join(long, *reversed(suffix)))
        except pywintypes.error:
            if candidate.parent == candidate: return os.path.normcase(original)
            suffix.append(candidate.name); candidate = candidate.parent


def inside(path, parent):
    return path == parent or path.startswith(parent.rstrip('\\') + '\\')


def within(path, parent):
    return inside(canonical_path(path), canonical_path(parent))


def identity(stream):
    stat = os.fstat(stream.fileno())
    return [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns]


def check_streams(source, paths):
    # GetVolumePathName can reject a WinFsp drive with ERROR_UNRECOGNIZED_VOLUME.
    # The checked, owned mount root is already known; query that filesystem itself.
    owner = paths.owner(source)
    volume = str(owner[0]).rstrip('\\') + '\\' if owner else win32file.GetVolumePathName(str(source))
    if volume not in paths.stream_support:
        paths.stream_support[volume] = bool(win32api.GetVolumeInformation(volume)[3] & 0x40000)
    streams = win32file.FindStreams(str(source)) if paths.stream_support[volume] else []
    if any(name != '::$DATA' for _, name in streams):
        raise VaultError("Files with alternate data streams are not supported.")


class Paths:
    """Only the exact owned WinFsp mount root may be a reparse point."""
    def __init__(self, manager):
        with manager.session_mutex:
            self.mounts = [(Path(os.path.abspath(point)), session.mount_device) for _, session, point in manager.sessions.values() if session.process.poll() is None]
        self.mount_keys = [(point, device, canonical_path(point)) for point, device in self.mounts]
        # Entries live only as long as their no-delete-sharing directory handle.
        # This is not a persistent path/alias cache.
        self.pinned = {}; self.stream_support = {}
        self.mount_interval = 0; self.mount_checks = {}

    @staticmethod
    def key(path): return os.path.normcase(os.path.abspath(path))

    def ensure_mount(self, point, device, *, force=False):
        key = (str(point), device); now = time.monotonic()
        if force or now >= self.mount_checks.get(key, 0):
            if mount_device(str(point)) != device:
                raise VaultError('The vault disconnected or its mount changed. Transfer stopped.')
            self.mount_checks[key] = now + self.mount_interval

    def owner(self, path):
        pin = self.pinned.get(self.key(path))
        if pin is not None: return pin[1]
        if not self.mount_keys: return None
        for point, device, _ in self.mount_keys:
            if self.key(path) == self.key(point): return point, device
        pin = self.pinned.get(self.key(Path(path).parent))
        if pin is not None: return pin[1]
        key = canonical_path(path)
        return next(((point, device) for point, device, parent in self.mount_keys if inside(key, parent)), None)

    def checked(self, path, *, must_exist=False):
        path = Path(os.path.abspath(path))
        owner = self.owner(path)
        if not owner: return safe_path(path, must_exist=must_exist)
        point, device = owner
        self.ensure_mount(point, device)
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
    def parents(self, path, *, enumeration=False):
        path = Path(path)
        # A size estimate is not authorization for later I/O. During counting,
        # new directory handles reject links; the actual copy still revalidates
        # the full path, including mutable attributes on pinned ancestors.
        if not enumeration or self.key(path.parent) not in self.pinned:
            path = self.checked(path)
        opened = []
        if self.key(path.parent) in self.pinned:
            yield path; return
        try:
            for parent in reversed(path.parents):
                key = self.key(parent)
                if key in self.pinned: continue
                owner = self.owner(parent)
                flags = 0x02000000 | (0 if owner and parent == owner[0] else 0x00200000)
                handle = win32file.CreateFile(str(parent), win32con.GENERIC_READ,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None, win32con.OPEN_EXISTING, flags, None)
                opened.append((key, handle))
                if win32file.GetFileInformationByHandle(handle)[0] & 0x400: raise VaultError('A transfer parent is a link.')
                self.validate_handle(handle, parent)
                self.pinned[key] = (handle, owner)
            yield path
        finally:
            for key, handle in reversed(opened):
                self.pinned.pop(key, None); handle.Close()

    @contextmanager
    def directory(self, path, *, enumeration=False):
        """Pin only the new directory; ancestor pins are shared by the DFS stack."""
        path = Path(path); key = self.key(path)
        if key in self.pinned:
            yield path; return
        with self.parents(path, enumeration=enumeration):
            owner = self.owner(path)
            flags = 0x02000000 | (0 if owner and path == owner[0] else 0x00200000)
            handle = win32file.CreateFile(str(path), win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None, win32con.OPEN_EXISTING, flags, None)
            try:
                attributes = win32file.GetFileInformationByHandle(handle)[0]
                if attributes & 0x400 or not attributes & win32con.FILE_ATTRIBUTE_DIRECTORY:
                    raise VaultError('A transfer folder is unavailable or is a link.')
                self.validate_handle(handle, path)
                self.pinned[key] = (handle, owner)
                yield path
            finally:
                self.pinned.pop(key, None); handle.Close()


@contextmanager
def locked_file(path, paths, *, writable=False):
    with paths.parents(path) as checked:
        access = win32con.GENERIC_READ | (win32con.GENERIC_WRITE if writable else 0)
        handle = win32file.CreateFile(str(checked), access, win32con.FILE_SHARE_READ,
            None, win32con.OPEN_EXISTING, win32con.FILE_FLAG_SEQUENTIAL_SCAN | 0x00200000, None)
        info = win32file.GetFileInformationByHandle(handle)
        if info[0] & (0x400 | win32con.FILE_ATTRIBUTE_DIRECTORY) or info[7] > 1:
            handle.Close(); raise VaultError('Transfer supports regular files without links only.')
        try: paths.validate_handle(handle, path)
        except BaseException: handle.Close(); raise
        with os.fdopen(msvcrt.open_osfhandle(handle.Detach(), os.O_RDWR if writable else os.O_RDONLY), 'r+b' if writable else 'rb') as stream:
            yield stream


@contextmanager
def output_file(path, paths):
    # CREATE_NEW, no write/delete sharing: nobody can modify or replace the
    # temporary file between verification and handle-based publication.
    handle = win32file.CreateFile(str(path), win32con.GENERIC_READ | win32con.GENERIC_WRITE | win32con.DELETE,
        win32con.FILE_SHARE_READ, None, win32con.CREATE_NEW, win32con.FILE_FLAG_SEQUENTIAL_SCAN, None)
    try:
        paths.validate_handle(handle, path)
        # The kernel removes this unfinished file if the worker exits without
        # running Python cleanup. Publication explicitly clears disposition.
        delete_open_file(int(handle))
    except BaseException:
        try: delete_open_file(int(handle))
        finally: handle.Close()
        raise
    with os.fdopen(msvcrt.open_osfhandle(handle.Detach(), os.O_RDWR), 'w+b') as stream:
        stream._yka_disposable = True
        try: yield stream
        finally:
            if not getattr(stream, '_yka_published', False):
                try: delete_open_file(msvcrt.get_osfhandle(stream.fileno()))
                except OSError:
                    raise VaultError(f'The copy stopped, but its temporary file could not be removed: {path}. Check the drive connection and remove this file after closing YKA.') from None


def delete_open_file(handle, delete=True):
    """Delete only the current, still-owned temporary file on handle close."""
    from ctypes import wintypes as W
    delete = ctypes.c_ubyte(bool(delete))
    function = ctypes.WinDLL('kernel32', use_last_error=True).SetFileInformationByHandle
    function.argtypes = [W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD]; function.restype = W.BOOL
    if not function(handle, 4, ctypes.byref(delete), ctypes.sizeof(delete)):
        raise ctypes.WinError(ctypes.get_last_error())


def publish_file(stream, target, *, replace):
    from ctypes import wintypes as W
    name = str(target).encode('utf-16-le')
    class RenameInfo(ctypes.Structure):
        _fields_ = [('ReplaceIfExists', W.BOOLEAN), ('RootDirectory', W.HANDLE),
                    ('FileNameLength', W.DWORD), ('FileName', W.WCHAR * (len(name) // 2 + 1))]
    info = RenameInfo(); info.ReplaceIfExists = replace; info.FileNameLength = len(name)
    ctypes.memmove(ctypes.addressof(info) + RenameInfo.FileName.offset, name, len(name))
    function = ctypes.WinDLL('kernel32', use_last_error=True).SetFileInformationByHandle
    function.argtypes = [W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD]; function.restype = W.BOOL
    handle = msvcrt.get_osfhandle(stream.fileno())
    disposable = getattr(stream, '_yka_disposable', False)
    if disposable: delete_open_file(handle, False)
    if not function(handle, 3, ctypes.byref(info), ctypes.sizeof(info)):
        error = ctypes.WinError(ctypes.get_last_error())
        if disposable: delete_open_file(handle)
        raise error
    stream._yka_published = True


class Transfer:
    def __init__(self, manager):
        self.manager = manager; self.paths = Paths(manager)
        self.paths.mount_interval = .25
        self.last_progress = 0; self.copied = 0; self.completed = 0
        self.skipped = 0; self.overwritten = 0; self.work = 0
        self.total_bytes = None; self.total_files = 0; self.total_folders = 0
        self.phase = None; self.phase_started = time.monotonic()
        self.phase_bytes = {'Copying': 0, 'Verifying': 0}; self.phase_seconds = {}
        self.weight = 1
        self.next_mount_check = 0; self.next_space_check = 0; self.space_remaining = 0

    def report(self, phase, relative='', *, force=False, complete=False):
        now = time.monotonic()
        if phase != self.phase:
            if self.phase is not None:
                self.phase_seconds[self.phase] = self.phase_seconds.get(self.phase, 0) + now-self.phase_started
            self.phase = phase; self.phase_started = now
        if not force and now - self.last_progress < .2: return
        self.last_progress = now
        if phase == 'Counting':
            current = 'Calculating total size…'
            summary = f'{self.total_files:,} files · {self.total_folders:,} folders · {self.counted_bytes/1024**3:.2f} GiB found'
            percent = None
        else:
            current = f'{phase}: {relative}' if relative else phase
            speed = self.phase_bytes.get(phase, 0) / 1024**2 / max(self.phase_seconds.get(phase, 0) + now-self.phase_started, .01)
            summary = f'{self.completed:,} copied · {self.skipped:,} skipped · {self.overwritten:,} overwritten · {speed:.1f} MiB/s'
            percent = 100 if complete else min(99, int(self.work * 100 / max((self.total_bytes or 0) * self.weight, 1)))
        self.manager.progress(dict(kind='transfer', current=current, summary=summary, percent=percent))

    def check(self):
        if self.manager.cancel.is_set() or self.manager.security_pending.is_set(): raise VaultError('Copy cancelled.')
        if time.monotonic() >= self.next_mount_check: self.check_mounts()

    def check_mounts(self):
        for point, device in getattr(self, 'bindings', []):
            self.paths.ensure_mount(point, device, force=True)
        self.next_mount_check = time.monotonic() + .25

    def reserve_space(self, parent, size):
        now = time.monotonic()
        if now >= self.next_space_check or self.space_remaining < size + 4 * CHUNK:
            self.space_remaining = shutil.disk_usage(parent).free
            self.next_space_check = now + 1
        if self.space_remaining < size + 4 * CHUNK:
            raise VaultError('Not enough free destination space. Free some space and try again.')
        self.space_remaining -= size

    def digest(self, stream, relative):
        stream.seek(0); hashed = hashlib.sha256()
        self.report('Verifying', relative)
        while chunk := stream.read(CHUNK):
            self.check(); hashed.update(chunk); self.work += len(chunk); self.phase_bytes['Verifying'] += len(chunk)
            self.report('Verifying', relative)
        return hashed.hexdigest()

    def endpoints(self, paths):
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

    def prepare(self, args):
        self.check()
        sources = [self.paths.checked(p, must_exist=True) for p in args['sources']]
        destination = self.paths.checked(args['destination'], must_exist=True)
        if not sources or len(sources) > 1000 or not destination.is_dir():
            raise VaultError('Choose files or folders and an existing destination folder.')
        if args.get('mode', 'copy') != 'copy': raise VaultError('Move is no longer supported. Start a new copy instead.')
        if not isinstance(args.get('verify', True), bool): raise VaultError('Choose whether to verify copied files.')
        if args.get('conflict', 'skip') not in ('skip', 'overwrite'):
            raise VaultError('Choose whether to skip or overwrite existing files.')
        self.validate_selection(args, sources, destination)
        names = set()
        for source in sources:
            if within(destination, source): raise VaultError('The destination cannot be inside a source folder.')
            if source.name.casefold() in names: raise VaultError('Two selected items have the same destination name.')
            names.add(source.name.casefold())
        self.endpoints([*sources, destination])
        return sources, destination

    def measure(self, sources):
        # Separate metadata-only pass. No per-file path canonicalization, mount
        # query or content open. Directory pins bound link/replacement races;
        # retain only one enumerator/handle per directory depth.
        self.counted_bytes = 0; self.report('Counting', force=True)
        frames = []
        def descend(path):
            scope = ExitStack()
            try:
                scope.enter_context(self.paths.directory(path, enumeration=True))
                entries = scope.enter_context(os.scandir(path))
                frames.append((entries, scope))
            except BaseException:
                scope.close(); raise
        try:
            for source in sources:
                self.check()
                source = self.paths.checked(source, must_exist=True)
                if source.is_dir():
                    self.total_folders += 1; descend(source)
                else:
                    self.total_files += 1; self.counted_bytes += source.stat().st_size
                while frames:
                    self.check()
                    entries, scope = frames[-1]
                    entry = next(entries, None)
                    if entry is None:
                        frames.pop(); scope.close(); continue
                    info = entry.stat(follow_symlinks=False)
                    if info.st_file_attributes & 0x400:
                        raise VaultError('Links inside a transfer path are not supported.')
                    if info.st_file_attributes & win32con.FILE_ATTRIBUTE_DIRECTORY:
                        self.total_folders += 1; descend(entry.path)
                    else:
                        self.total_files += 1; self.counted_bytes += info.st_size
                    self.report('Counting')
        finally:
            for _, scope in reversed(frames): scope.close()
        self.check(); self.check_mounts()
        self.total_bytes = self.counted_bytes

    def walk(self, sources, *, metadata=False):
        """Depth-first enumeration, with only one iterator per directory depth.

        The consumer sends False to prune a skipped directory. Directory handles
        prevent path replacement while enumerating; files are checked at open.
        """
        frames = [(iter((Path(s), Path(Path(s).name), None, None) for s in sources), None)]
        try:
            while frames:
                self.check()
                iterator, scope = frames[-1]
                try: source, relative, directory, size = next(iterator)
                except StopIteration:
                    frames.pop()
                    if scope: scope.close()
                    continue
                if directory is None:
                    source = self.paths.checked(source, must_exist=True)
                    directory = source.is_dir()
                    size = source.stat().st_size if metadata and not directory else 0
                descend = yield source, relative, directory, size
                if directory and descend:
                    scope = ExitStack()
                    try:
                        scope.enter_context(self.paths.directory(source))
                        entries = scope.enter_context(os.scandir(source))
                        # Bind relative now; generator closures must not use the next loop's path.
                        def children(entries, parent):
                            for entry in entries:
                                directory = entry.is_dir(follow_symlinks=False)
                                size = entry.stat(follow_symlinks=False).st_size if metadata and not directory else 0
                                yield Path(entry.path), parent / entry.name, directory, size
                        frames.append((children(entries, relative), scope))
                    except BaseException:
                        scope.close(); raise
        finally:
            for _, scope in reversed(frames):
                if scope: scope.close()

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
        except (OSError, pywintypes.error) as error: raise VaultError(copy_error(error)) from None

    def _run(self, args):
        sources, destination = self.prepare(args)
        verify = args.get('verify', True); policy = args.get('conflict', 'skip')
        self.weight = 2 if verify else 1
        self.measure(sources)
        with self.paths.directory(destination), closing(self.walk(sources, metadata=True)) as walker:
            target_stack = []
            try:
                entry = next(walker, None)
                while entry is not None:
                    source, relative, directory, size = entry
                    self.check()
                    candidate = destination / relative
                    while target_stack and target_stack[-1][0] not in candidate.parents:
                        _, scope = target_stack.pop(); scope.close()
                    target = self.paths.checked(candidate)
                    if not target.is_relative_to(destination) or target == destination: raise VaultError('Invalid copy destination.')
                    descend = True
                    if directory:
                        self.report('Preparing folder', str(relative))
                        with self.paths.parents(target):
                            if target.exists() and not target.is_dir():
                                self.skipped += 1; descend = False
                            else:
                                target.mkdir(exist_ok=True)
                                scope = ExitStack()
                                try: scope.enter_context(self.paths.directory(target))
                                except BaseException:
                                    scope.close(); raise
                                target_stack.append((target, scope))
                    else:
                        self.copy_file(source, target, str(relative), size, verify, policy)
                    try: entry = walker.send(descend)
                    except StopIteration: entry = None
            finally:
                for _, scope in reversed(target_stack): scope.close()
        self.check(); self.check_mounts(); self.report('Copy complete', complete=True, force=True)
        message = f"{self.completed:,} file{'s were' if self.completed != 1 else ' was'} copied" + (' and verified successfully.' if verify else ' successfully. Content verification was skipped.')
        if self.skipped: message += f' {self.skipped:,} existing items were skipped.'
        if self.overwritten: message += f' {self.overwritten:,} existing files were overwritten.'
        return dict(completed_files=self.completed, skipped_items=self.skipped, overwritten_files=self.overwritten,
                    verified=verify, path=str(destination), message=message)

    def copy_file(self, source, target, relative, listed_size, verify, policy):
        self.report('Copying', relative)
        exists = target.exists()
        if exists and (policy == 'skip' or target.is_dir()):
            self.skipped += 1; self.work += listed_size * self.weight
            self.report('Skipping', relative); return
        self.check(); self.check_mounts()
        with locked_file(source, self.paths) as original:
            check_streams(source, self.paths)
            stamp = identity(original); size = stamp[2]
            self.reserve_space(target.parent, size)
            temporary = target.with_name(f'.yka-transfer-{uuid.uuid4().hex}.partial')
            hashed = hashlib.sha256() if verify else None
            copied = 0; work_before = self.work
            with self.paths.parents(temporary), output_file(temporary, self.paths) as output:
                while chunk := original.read(CHUNK):
                    self.check(); output.write(chunk)
                    if hashed is not None: hashed.update(chunk)
                    copied += len(chunk); self.copied += len(chunk); self.work += len(chunk); self.phase_bytes['Copying'] += len(chunk)
                    self.report('Copying', relative)
                output.flush(); os.fsync(output.fileno())
                if copied != size or identity(original) != stamp:
                    raise VaultError('The source changed during copying. Copy stopped.')
                if verify and self.digest(output, relative) != hashed.hexdigest():
                    raise VaultError('The copied file does not match its source. Copy stopped.')
                self.check(); self.check_mounts(); self.paths.checked(target)
                # The verified temporary stays exclusively open until publication.
                # Try no-replace first, so the overwrite counter reflects actual
                # replacements even if a new destination appeared during copying.
                try: publish_file(output, target, replace=False)
                except OSError as error:
                    if error.winerror not in (80, 183, 5): raise
                    self.paths.checked(target)
                    if not target.exists(): raise
                    if policy == 'skip' or target.is_dir():
                        self.skipped += 1; self.work = work_before + size * self.weight
                        return
                    publish_file(output, target, replace=True)
                    self.overwritten += 1
                os.fsync(output.fileno()); self.completed += 1
            self.report('Copying', relative)
