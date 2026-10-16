"""Authenticated, handle-bound deletion. No secrets or data backups in the journal."""
import hashlib
import os
from pathlib import Path
from contextlib import contextmanager
import win32con
import win32file
from . import archive
from .move import delete_handle, within
from .native import native_call
from .registry import path_key
from .storage import read_header
from .windows import VaultError, VaultGuard, safe_path, pin_directory

INCOMPLETE = ('Deletion could not be completed. Some files may already have been deleted. '
              'Check the drive connection and permissions, close any programs using this folder, then try again.')
RECORDS_FAILED = ('The encrypted folder was deleted, but some saved records could not be removed. '
                  'Try again to finish cleanup.')
CONTROL_FILES = ('.config.pb', '.yka-key')


@contextmanager
def file_handle(path):
    # The caller pins every parent; open the leaf itself, never a link target.
    handle = win32file.CreateFile(str(path), win32con.GENERIC_READ | win32con.DELETE,
        win32con.FILE_SHARE_READ, None, win32con.OPEN_EXISTING, 0x00200000, None)
    try:
        info = win32file.GetFileInformationByHandle(handle)
        if info[0] & (0x400 | win32con.FILE_ATTRIBUTE_DIRECTORY) or info[7] != 1:
            raise VaultError('Links and special files cannot be deleted by this operation.')
        yield handle
    finally: handle.Close()


@contextmanager
def parent_handle(path):
    handle = pin_directory(path)
    try: yield handle
    finally: handle.Close()


def file_digest(handle):
    result = hashlib.sha256()
    while True:
        _, chunk = win32file.ReadFile(handle, 1024 * 1024)
        if not chunk: return result.hexdigest()
        result.update(chunk)


def remove_contents(root):
    """Bounded-memory walk, with directory handles held until children are gone."""
    stack = [(root, None, os.scandir(root))]
    try:
        while stack:
            directory, handle, listing = stack[-1]
            item = next(listing, None)
            if item is None:
                listing.close()
                if handle is not None: delete_handle(handle); handle.Close()
                stack.pop(); continue
            if directory == root and item.name.casefold() in (*CONTROL_FILES, '.manager.lock'): continue
            path = directory / item.name
            attributes = item.stat(follow_symlinks=False).st_file_attributes
            if attributes & 0x400: raise VaultError('Links and junctions cannot be deleted by this operation.')
            if attributes & win32con.FILE_ATTRIBUTE_DIRECTORY:
                child = pin_directory(path, rename=True)
                try: iterator = os.scandir(path)
                except BaseException: child.Close(); raise
                stack.append((path, child, iterator))
            else:
                with file_handle(path) as opened: delete_handle(opened)
    finally:
        for _, handle, listing in reversed(stack):
            listing.close()
            if handle is not None: handle.Close()


def check_idle(manager, record, root):
    if record.get('move_transaction') or record.get('restore_transaction') or record.get('last_mount'):
        raise VaultError('Unmount this vault and finish any pending operations before deleting it.')
    with manager.session_mutex:
        if path_key(root) in {path_key(p) for p in manager.sessions}:
            raise VaultError('Unmount this vault and finish any pending operations before deleting it.')
    if root.exists() and (root / '.mount-state.json').exists():
        raise VaultError('Unmount this vault and finish any pending operations before deleting it.')


def run(manager, args):
    if args.get('confirmed') is not True: raise VaultError('Confirm vault deletion before continuing.')
    record = manager.registry.get(args['record_id'])
    root = safe_path(record['path'])
    if (path_key(args.get('expected_path', '')) != path_key(root)
        or args.get('expected_uuid') != record['uuid'] or args.get('expected_public') != record['signing_public']):
        raise VaultError('The saved vault changed. Review its location before deleting it.')
    if root == Path(root.anchor) or within(manager.registry.directory, root):
        raise VaultError('This folder cannot be deleted by YKA.')
    for other in manager.registry.records():
        if other['id'] != record['id'] and (within(Path(other['path']), root) or within(root, Path(other['path']))):
            raise VaultError('Another saved vault uses this folder. Its files were not deleted.')
        point = (other.get('last_mount') or {}).get('mount_point')
        if point and (within(root, Path(point + '\\' if len(point) == 2 else point)) or within(Path(point), root)):
            raise VaultError('A recorded mount uses this location. Confirm unmount before deleting it.')
    # Retain an identity lease even after the encrypted root has been removed.
    check_idle(manager, record, root)
    with VaultGuard(manager.registry.locks) as lease:
        try: lease.reserve(manager.registry.locks, 'identity:' + record['uuid'])
        except Exception:
            raise VaultError('Unmount this vault and finish any pending operations before deleting it.') from None
        current = manager.registry.get(record['id'])
        if any(current[k] != record[k] for k in ('path', 'uuid', 'signing_public')):
            raise VaultError('The saved vault changed. Review its location before deleting it.')
        record = current
        check_idle(manager, record, root)
        tx = record.get('delete_transaction')
        if tx and (tx.get('path') != str(root) or tx.get('uuid') != record['uuid']
                   or tx.get('signing_public') != record['signing_public'] or tx.get('phase') not in ('files', 'finalizing')):
            raise VaultError('The saved deletion state could not be verified. No further files were deleted.')
        if not root.exists():
            # Only a previously authenticated terminal commit permits record cleanup.
            # A missing/offline root during ordinary deletion is never success.
            if not tx or tx['phase'] != 'finalizing': raise VaultError(INCOMPLETE)
            with parent_handle(root.parent) as parent:
                info = win32file.GetFileInformationByHandle(parent)
                if list((info[4], info[8], info[9])) != tx['parent_id']: raise VaultError(INCOMPLETE)
        else:
            if tx:
                with parent_handle(root) as opened:
                    info = win32file.GetFileInformationByHandle(opened)
                    if [info[4], info[8], info[9]] != tx.get('root_id'):
                        raise VaultError('The vault folder changed. It was not deleted.')
            with VaultGuard(root) as guard:
                check_idle(manager, record, root)
                if tx and list(guard.root_identity) != tx.get('root_id'):
                    raise VaultError('The vault folder changed. It was not deleted.')
                if not tx or tx['phase'] == 'files':
                    manager.progress('Authenticating the vault…')
                    if tx:
                        if read_header(root)['keyring_sha256'] != tx['controls']['.yka-key']:
                            raise VaultError('The vault key changed. It was not deleted.')
                        # Data/provenance may already be partially deleted. Still decrypt
                        # the original key and verify its config and cryptographic identity.
                        verified = native_call(dict(action='verify', root=str(root), **manager._auth(args),
                            expected_uuid=record['uuid'], expected_public=record['signing_public']),
                            guard=guard, pin=args.get('pin'), progress=manager.progress, cancel=manager.cancel.is_set)
                    else:
                        verified = manager._verified(root, args, guard)
                    if (verified['uuid'], verified['signing_public']) != (record['uuid'], record['signing_public']):
                        raise VaultError('Vault authentication was not confirmed.')
                    archive.check_cancel(manager.cancel.is_set)
                    check_idle(manager, manager.registry.get(record['id']), root)
                    if not tx:
                        controls = {}
                        for name in CONTROL_FILES:
                            with file_handle(root / name) as opened: controls[name] = file_digest(opened)
                        header = read_header(root)
                        if (controls['.yka-key'] != verified['keyring_sha256'] or header['keyring_sha256'] != controls['.yka-key']
                            or controls['.config.pb'] != header['config_sha256']):
                            raise VaultError('The vault key changed. It was not deleted.')
                        with parent_handle(root.parent) as parent:
                            info = win32file.GetFileInformationByHandle(parent)
                            parent_id = [info[4], info[8], info[9]]
                        tx = dict(path=str(root), uuid=record['uuid'], signing_public=record['signing_public'],
                            root_id=list(guard.root_identity), parent_id=parent_id, controls=controls, phase='files')
                        manager.registry.deletion_journal(record, tx)
                    # Once destructive work starts, cancellation cannot restore files.
                    try:
                        manager.progress('Deleting encrypted files…')
                        remove_contents(root)
                        tx = dict(tx, phase='finalizing')
                        manager.registry.deletion_journal(record, tx)
                    except Exception: raise VaultError(INCOMPLETE) from None
                try:
                    # Durable terminal intent authorizes only these exact metadata files.
                    # It permits cleanup after a crash between deleting the key and root.
                    if any(p.name.casefold() not in (*CONTROL_FILES, '.manager.lock') for p in root.iterdir()):
                        raise VaultError(INCOMPLETE)
                    for name in CONTROL_FILES:
                        if not (root / name).exists(): continue
                        with file_handle(root / name) as opened:
                            if file_digest(opened) != tx['controls'][name]: raise VaultError(INCOMPLETE)
                            delete_handle(opened)
                    guard.prepare_rename()  # DELETE handle excludes any new cooperating root guard.
                    guard.handle.Close(); guard.handle = None
                    with file_handle(root / '.manager.lock') as opened: delete_handle(opened)
                    delete_handle(guard.root_handle)  # Fails if any concurrent addition remains.
                except Exception: raise VaultError(INCOMPLETE) from None
        manager.progress('Removing saved records…')
        try:
            manager.jobs.remove_vault(record)
            manager.registry.finish_deletion(record, tx)
        except Exception: raise VaultError(RECORDS_FAILED) from None
        manager.metadata_cache.pop(path_key(root), None)
        return {'removed': True, 'data_deleted': True}
