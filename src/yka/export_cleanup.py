"""Owned export temporaries: kernel cleanup first, private journal as fallback."""
from contextlib import contextmanager
import msvcrt
import os
import re
import tempfile
import win32con
import win32file
from .windows import VaultError, VaultGuard, safe_path, pinned_parents, pin_directory, output_identity
from .transfer import delete_open_file, publish_file
from .residuals import discard_tree


def file_id(stream):
    st = os.fstat(stream.fileno())
    return [st.st_dev, st.st_ino, st.st_birthtime_ns]


def directory_id(handle):
    info = win32file.GetFileInformationByHandle(handle)
    return [info[4], info[8], info[9]]


@contextmanager
def disposable_output(path, retain_on_error, on_retain):
    with pinned_parents(path):
        handle = win32file.CreateFile(str(path), win32con.GENERIC_READ | win32con.GENERIC_WRITE | win32con.DELETE,
            win32con.FILE_SHARE_READ, None, win32con.CREATE_NEW, 0x00200000 | win32con.FILE_FLAG_SEQUENTIAL_SCAN, None)
        try:
            delete_open_file(int(handle))
            fd = msvcrt.open_osfhandle(int(handle), os.O_RDWR)
        except BaseException:
            handle.Close(); raise
        handle.Detach()
        try: stream = os.fdopen(fd, 'w+b')
        except BaseException:
            os.close(fd); raise
        with stream:
            stream._yka_disposable = True
            try: yield stream
            except BaseException as error:
                try: keep = bool(retain_on_error(error))
                except Exception: keep = True
                if not getattr(stream, '_yka_published', False) and keep:
                    # Persist the exception to automatic cleanup BEFORE clearing
                    # the kernel deletion flag. Do not silently lose that policy.
                    on_retain()
                    delete_open_file(msvcrt.get_osfhandle(stream.fileno()), False)
                raise


def publish(stream, output, replace_existing):
    safe_path(output)
    if replace_existing is not None and output_identity(output) != replace_existing:
        raise VaultError('The destination file changed after you selected it. Save again to confirm which file to replace.')
    # Same open handle, same directory, no close/reopen race. The transfer helper
    # clears deletion only for publication and restores it if rename fails.
    publish_file(stream, output, replace=replace_existing is not None)


def remember(manager, original, verified, partial, output, stream, scratch):
    task = getattr(manager.task_context, 'task', None)
    if task is None: return
    parent = pin_directory(partial.parent)
    try:
        with VaultGuard(scratch) as temporary:
            task['export_stage'] = dict(root=str(original.root), root_id=list(original.root_identity),
                uuid=verified['uuid'], signing_public=verified['signing_public'], partial=str(partial),
                output=str(output), file_id=file_id(stream), parent_id=directory_id(parent), retain=False,
                scratch=str(scratch), scratch_id=list(temporary.root_identity))
            manager.jobs.save(task)
    finally: parent.Close()


def retain(manager):
    task = getattr(manager.task_context, 'task', None)
    if task and task.get('export_stage'):
        task['export_stage']['retain'] = True
        manager.jobs.save(task)


def cleanup_task(manager, ident, *, cancel=lambda: False, task=None):
    from .archive import check_cancel
    from .restore_cleanup import owner_finished, _overlap
    from .registry import path_key
    from .storage import read_header
    from .move import deletable_reader, delete_handle
    check_cancel(cancel)
    task = task or manager.jobs.load(ident)
    if task.get('action') != 'export' or not task.get('export_stage') or not owner_finished(task): return
    saved = task['export_stage']
    partial = safe_path(saved['partial']); output = safe_path(saved['output']); scratch = safe_path(saved['scratch'])
    if (partial.parent != output.parent or
        not re.fullmatch(re.escape(output.name) + r'\.[0-9a-f]{32}\.partial', partial.name) or
        path_key(scratch.parent) != path_key(tempfile.gettempdir()) or
        not re.fullmatch(r'yka-export-[a-z0-9_]{8}', scratch.name)):
        raise VaultError('Export cleanup ownership could not be verified.')
    protected = [manager.registry.directory]
    for record in manager.registry.records():
        protected.extend([record['path'], (record.get('last_mount') or {}).get('mount_point')])
    if any(_overlap(p, target) for p in (partial, scratch) for target in protected if target): return
    # Scratch data is independently owned and can be removed even while the
    # external destination is offline or a recovery partial must be retained.
    discard_tree(scratch, saved['scratch_id'], cancel=cancel)
    check_cancel(cancel)
    with pinned_parents(partial):
        parent = pin_directory(partial.parent)
        try:
            # A disconnected/replaced disk is not evidence that the file is gone.
            if directory_id(parent) != saved['parent_id']: return
            if partial.exists():
                if saved.get('retain') is not False: return
                root = safe_path(saved['root'], must_exist=True)
                with VaultGuard(root) as original:
                    original.reserve(manager.registry.locks, 'identity:' + saved['uuid'])
                    manager._idle(root, cleanup=False)
                    if list(original.root_identity) != saved['root_id']: return
                    body = read_header(root)
                    if (body['uuid'], body['signing_public']) != (saved['uuid'], saved['signing_public']): return
                    with deletable_reader(partial) as (stream, handle):
                        if file_id(stream) != saved['file_id']: return
                        check_cancel(cancel); delete_handle(handle)
            if partial.exists(): return
        finally: parent.Close()
    manager.jobs.forget(task)
