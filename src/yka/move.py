"""Verified ciphertext moves with a durable publication/cleanup journal."""
import ctypes
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import time
import uuid
from contextlib import closing, contextmanager
import win32con
import win32file
from . import archive
from .registry import path_key
from .storage import read_header
from .windows import (VaultError, VaultGuard, safe_path, private_directory,
                      pinned_parents, guarded_reader, new_file)


def within(path, parent):
    return path_key(path) == path_key(parent) or path_key(parent) in [path_key(p) for p in Path(path).parents]


def entries(root):
    stack = [root]; count = 0
    while stack:
        directory = stack.pop()
        with pinned_parents(directory / 'unused'), os.scandir(directory) as listing:
            for item in listing:
                if directory == root and item.name == '.manager.lock': continue
                path = safe_path(directory / item.name, must_exist=True); st = path.lstat()
                name = path.relative_to(root).as_posix(); archive.entry_path(name, archive_names=False)
                count += 1
                if count > archive.MAX_ENTRIES: raise VaultError('Too many files to move.')
                if stat.S_ISDIR(st.st_mode):
                    yield name, 'directory', st; stack.append(path)
                elif stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
                    yield name, 'file', st
                else: raise VaultError('Links and special files cannot be moved.')


def no_streams(path):
    # Do not silently drop NTFS alternate streams when moving between volumes.
    import win32api
    volume = win32file.GetVolumePathName(str(path))
    if win32api.GetVolumeInformation(volume)[3] & 0x40000:
        if any(name != '::$DATA' for _, name in win32file.FindStreams(str(path))):
            raise VaultError('Files with alternate data streams cannot be moved by YKA.')


def digest(stream, cancel=lambda: False):
    result = hashlib.sha256()
    while chunk := stream.read(archive.CHUNK):
        archive.check_cancel(cancel); result.update(chunk)
    return result.hexdigest()


def delete_handle(handle):
    from ctypes import wintypes
    function = ctypes.WinDLL('kernel32', use_last_error=True).SetFileInformationByHandle
    function.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    function.restype = wintypes.BOOL
    disposition = ctypes.c_ubyte(1)
    if not function(int(handle), 4, ctypes.byref(disposition), 1): raise ctypes.WinError(ctypes.get_last_error())


@contextmanager
def deletable_reader(path):
    """Read/hash and delete the same opened file, denying concurrent writes/renames."""
    import msvcrt
    with pinned_parents(path):
        path = safe_path(path, must_exist=True)
        handle = win32file.CreateFile(str(path), win32con.GENERIC_READ | win32con.DELETE,
            win32con.FILE_SHARE_READ, None, win32con.OPEN_EXISTING, 0x00200000, None)
        try:
            info = win32file.GetFileInformationByHandle(handle)
            if info[0] & (0x400 | win32con.FILE_ATTRIBUTE_DIRECTORY) or info[7] != 1:
                raise VaultError('The source file changed. It was not deleted.')
            no_streams(path)
            fd = msvcrt.open_osfhandle(handle.Detach(), os.O_RDONLY)
            with os.fdopen(fd, 'rb') as source: yield source, msvcrt.get_osfhandle(source.fileno())
        finally: handle.Close()


def checked_transaction(registry, record):
    tx = record['move_transaction']
    source = safe_path(tx['source']); destination = safe_path(tx['destination']); stage = safe_path(tx['stage'])
    manifest = safe_path(tx['manifest'])
    if (stage.parent != destination.parent or not stage.name.startswith('.yka-moving-')
        or manifest.parent != registry.directory / 'moves' or manifest.suffix != '.sqlite'
        or path_key(record['path']) != path_key(destination if tx.get('committed') else source)
        or within(source, destination) or within(destination, source)):
        raise VaultError('The saved move locations could not be verified.')
    uuid.UUID(manifest.stem)
    return tx, source, destination, stage, manifest


def cleanup(registry, record, cancel=lambda: False, progress=lambda _: None):
    tx, source, destination, stage, manifest = checked_transaction(registry, record)
    with VaultGuard(destination) as target:
        target.reserve(registry.locks, 'identity:' + record['uuid'])
        if list(target.root_identity) != tx['new_id'] or read_header(destination)['keyring_sha256'] != tx['keyring_sha256']:
            raise VaultError('The moved vault changed. Remaining source files were kept.')
        if source.exists():
            with guarded_reader(manifest) as listing:
                if digest(listing) != tx['manifest_sha256']: raise VaultError('The move verification record changed. Source files were kept.')
                with closing(sqlite3.connect(manifest.as_uri() + '?mode=ro', uri=True)) as db:
                    with VaultGuard(source) as original:
                        if list(original.root_identity) != tx['old_id']: raise VaultError('The original folder changed. It was not deleted.')
                        # Unknown additions stop cleanup; never recursively erase the source.
                        for name, kind, _ in entries(source):
                            if db.execute('select kind from files where path=?', (name,)).fetchone() != (kind,):
                                raise VaultError('The source contains new files. Remaining source files were kept.')
                        progress('Removing verified source copies…')
                        for name, expected in db.execute("select path,digest from files where kind='file' order by case when path='.yka-key' then 1 else 0 end,path"):
                            archive.check_cancel(cancel); archive.entry_path(name, archive_names=False)
                            old = source / Path(name); new = destination / Path(name)
                            if not old.exists(): continue
                            with guarded_reader(new) as saved, deletable_reader(old) as (stream, handle):
                                if digest(saved, cancel) != expected or digest(stream, cancel) != expected:
                                    raise VaultError('A file changed after verification. Remaining source files were kept.')
                                delete_handle(handle)
                        for (name,) in db.execute("select path from files where kind='directory' order by length(path) desc"):
                            archive.entry_path(name, archive_names=False); path = safe_path(source / Path(name))
                            if path.exists():
                                with pinned_parents(path): path.rmdir()
                        original.handle.Close(); original.handle = None
                        safe_path(source / '.manager.lock').unlink(missing_ok=True)
                        original.prepare_rename(); delete_handle(original.root_handle)
        # Keep the recovery record until the manifest is gone. A retry after
        # deletion can finish without the manifest only when source is absent.
        if manifest.exists():
            with deletable_reader(manifest) as (_, handle): delete_handle(handle)
        registry.move_journal(record['id'], None)


def recover(registry, record, *, cancel=lambda: False, progress=lambda _: None):
    tx, source, destination, stage, manifest = checked_transaction(registry, record)
    if tx.get('committed'):
        cleanup(registry, record, cancel, progress); return
    # Before commit the original tree has never been deleted or modified.
    with VaultGuard(source) as original, pinned_parents(destination):
        original.reserve(registry.locks, 'identity:' + record['uuid'])
        if list(original.root_identity) != tx['old_id']: raise VaultError('The original folder changed. Move recovery stopped.')
        for candidate in (stage, destination):
            if not candidate.exists(): continue
            with VaultGuard(candidate) as copied:
                if list(copied.root_identity) != tx['new_id']:
                    if candidate == destination: continue  # Unrelated destination appeared; leave it alone.
                    raise VaultError('The move staging folder changed. It was not removed.')
                # Exact created directory, checked absolute parent and identity;
                # never traverse a replacement junction during staging rollback.
                if candidate.parent.resolve() != destination.parent.resolve(): raise VaultError('Move staging path changed.')
                copied.handle.Close(); copied.handle = None
                try: shutil.rmtree(candidate)
                except PermissionError:
                    if list(candidate.iterdir()): raise
            if candidate.exists(): candidate.rmdir()
        if manifest.exists():
            with deletable_reader(manifest) as (_, handle): delete_handle(handle)
        registry.move_journal(record['id'], None)


def check_destination(manager, args):
    record = manager.registry.get(args['record_id'])
    if record.get('move_transaction'): raise VaultError('Finish the interrupted move first.')
    source = safe_path(record['path'], must_exist=True); destination = safe_path(args['destination'])
    if within(source, destination) or within(destination, source): raise VaultError('Choose a new folder outside the current vault.')
    if destination.exists(): raise VaultError('The destination already exists. Choose a new folder.')
    if manager.registry.by_path(destination): raise VaultError('The destination is already registered.')
    origin = manager.registry.origin(destination)
    if origin and origin.get('pending'): raise VaultError('The destination has an unfinished import.')
    for saved in manager.registry.records():
        if within(destination, Path(saved['path'])):
            raise VaultError('Choose a destination outside other encrypted vault folders.')
        point = (saved.get('last_mount') or {}).get('mount_point')
        if point and within(destination, Path(point + '\\' if len(point) == 2 else point)):
            raise VaultError('Choose a destination outside mounted vaults.')
    if not destination.parent.is_dir(): raise VaultError('The destination parent folder does not exist.')
    return record, source, destination


def run(manager, args):
    record, source, destination = check_destination(manager, args)
    stage = destination.with_name('.yka-moving-' + uuid.uuid4().hex)
    manifest = None; stage_identity = None
    try:
        with VaultGuard(source) as original, pinned_parents(destination):
            manager._idle(source)
            original.reserve(manager.registry.locks, 'identity:' + record['uuid'])
            original.reserve(manager.registry.locks, 'move:' + path_key(destination))
            manager.progress('Authenticating the vault before moving it…')
            verified = manager._verified(source, args, original)
            archive.check_cancel(manager.cancel.is_set)
            private_directory(stage)
            with VaultGuard(stage) as incoming:
                stage_identity = list(incoming.root_identity)
                folder = manager.registry.directory / 'moves'
                if not folder.exists(): private_directory(folder)
                manifest = folder / (uuid.uuid4().hex + '.sqlite')
                tx = dict(source=str(source), destination=str(destination), stage=str(stage), manifest=str(manifest),
                    old_id=list(original.root_identity), new_id=list(incoming.root_identity), committed=False,
                    keyring_sha256=verified['keyring_sha256'])
                manager.registry.move_journal(record['id'], tx)
                with closing(sqlite3.connect(manifest)) as db:
                    db.execute('create table files(path text primary key,kind text,size integer,mtime integer,inode integer,digest text)')
                    for name, kind, st in entries(source):
                        archive.check_cancel(manager.cancel.is_set)
                        db.execute('insert into files values(?,?,?,?,?,null)', (name,kind,st.st_size if kind=='file' else 0,st.st_mtime_ns,st.st_ino))
                    db.commit()
                    total = db.execute('select coalesce(sum(size),0) from files').fetchone()[0]
                    if shutil.disk_usage(destination.parent).free < total + 16*1024*1024: raise VaultError('There is not enough free space at the destination.')
                    for (name,) in db.execute("select path from files where kind='directory' order by length(path)"):
                        safe_path(stage / Path(name)).mkdir()
                    copied = 0; tick = 0
                    for name,size,mtime,inode in db.execute("select path,size,mtime,inode from files where kind='file'"):
                        archive.check_cancel(manager.cancel.is_set)
                        with guarded_reader(source / Path(name)) as stream, new_file(stage / Path(name)) as output:
                            no_streams(source / Path(name)); actual=os.fstat(stream.fileno())
                            if (actual.st_size,actual.st_mtime_ns,actual.st_ino)!=(size,mtime,inode): raise VaultError('The source changed. Move stopped.')
                            hashed=hashlib.sha256()
                            while chunk := stream.read(archive.CHUNK):
                                archive.check_cancel(manager.cancel.is_set); output.write(chunk); hashed.update(chunk); copied+=len(chunk)
                                if time.monotonic()-tick>.25:
                                    manager.progress(f'Moving encrypted files: {copied:,} of {total:,} bytes ({copied*100//max(1,total)}%).'); tick=time.monotonic()
                            output.flush(); os.fsync(output.fileno())
                        db.execute('update files set digest=? where path=?',(hashed.hexdigest(),name))
                    db.commit()
                    manager.progress('Verifying the copied files and checking the source…')
                    for root in (source,stage):
                        count=0
                        for name,kind,st in entries(root):
                            archive.check_cancel(manager.cancel.is_set); count+=1
                            expected=db.execute('select kind,size,digest from files where path=?',(name,)).fetchone()
                            if not expected or expected[0]!=kind: raise VaultError('The vault files changed during the move.')
                            if kind=='file':
                                with guarded_reader(root / Path(name)) as stream:
                                    no_streams(root / Path(name))
                                    if st.st_size!=expected[1] or digest(stream,manager.cancel.is_set)!=expected[2]: raise VaultError('File verification failed. The original vault was kept.')
                        if count!=db.execute('select count(*) from files').fetchone()[0]: raise VaultError('A vault file is missing. The original vault was kept.')
                    if read_header(stage)['keyring_sha256']!=verified['keyring_sha256']: raise VaultError('The vault key changed during the move.')
                with guarded_reader(manifest) as stream: tx['manifest_sha256']=digest(stream)
                manager.registry.move_journal(record['id'],tx)
                archive.check_cancel(manager.cancel.is_set)
                incoming.prepare_rename(); incoming.rename_to(destination)
                manager.registry.commit_move(record['id'],tx)
        manager.metadata_cache.pop(path_key(source),None)
        manager.metadata_cache[path_key(destination)] = dict(verified)
        try:
            cleanup(manager.registry,manager.registry.get(record['id']),manager.cancel.is_set,manager.progress)
        except Exception:
            return {'path':str(destination),'cleanup_pending':True,
                'message':'The verified vault is at its new location. Some original files remain. Use Finish Move before mounting.'}
        return {'path':str(destination),'cleanup_pending':False,'message':'The vault was moved and verified. Its saved location was updated.'}
    except BaseException:
        saved=manager.registry.get(record['id'])
        if saved.get('move_transaction') and not saved['move_transaction'].get('committed'):
            try: recover(manager.registry,saved)
            except Exception: manager.progress('The original vault was kept. Use Recover Move to clean up the interrupted copy.')
        elif not saved.get('move_transaction') and stage_identity is not None:
            try:
                from .residuals import discard_tree
                discard_tree(stage, stage_identity)
            except (OSError, VaultError):
                manager.progress('The move stopped. Its temporary folder could not be removed: ' + str(stage))
        raise
