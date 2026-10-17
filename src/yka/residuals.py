"""Discard only disposable artifacts whose filesystem identity we own."""
import os
import shutil
import uuid
import msvcrt
import win32con
import win32file
from contextlib import contextmanager
from .windows import VaultError, VaultGuard, pinned_parents


def file_identity(stream):
    st = os.fstat(stream.fileno())
    return st.st_dev, st.st_ino


def discard_file(path, expected):
    from .move import deletable_reader, delete_handle
    if not path.exists(): return
    with deletable_reader(path) as (stream, handle):
        if file_identity(stream) != expected:
            raise VaultError('The temporary file changed. It was not removed.')
        delete_handle(handle)


@contextmanager
def temporary_output(path, *, retain_on_error=None):
    # The caller closes the stream before atomic publication on Windows. Keep
    # parents pinned and check the original file ID before exceptional cleanup.
    with pinned_parents(path):
        expected = None; retain = False
        try:
            handle = win32file.CreateFile(str(path), win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                win32con.FILE_SHARE_READ, None, win32con.CREATE_NEW, 0x00200000, None)
            try: fd = msvcrt.open_osfhandle(int(handle), os.O_RDWR)
            except BaseException:
                handle.Close(); raise
            handle.Detach()
            try: stream = os.fdopen(fd, 'w+b')
            except BaseException:
                os.close(fd); raise
            with stream:
                expected = file_identity(stream)
                try: yield stream
                except BaseException as error:
                    if retain_on_error is not None:
                        try: retain = bool(retain_on_error(error))
                        except Exception: retain = True  # Unavailable storage is not proof of redundancy.
                    raise
        finally:
            if expected is not None and not retain: discard_file(path, expected)


def discard_tree(path, expected, *, cancel=None):
    if not path.exists(): return
    with VaultGuard(path) as guard:
        if list(guard.root_identity) != list(expected):
            raise VaultError('The temporary folder changed. It was not removed.')
        if cancel is not None:
            _discard_contents(guard.root, cancel)
            from .archive import check_cancel
            from .move import deletable_reader, delete_handle
            check_cancel(cancel)
            guard.handle.Close(); guard.handle = None
            with deletable_reader(path / '.manager.lock') as (_, handle): delete_handle(handle)
            guard.prepare_rename(); delete_handle(guard.root_handle)
            return
        guard.handle.Close(); guard.handle = None
        try: shutil.rmtree(path)
        except PermissionError:
            if list(path.iterdir()): raise
        # Delete the pinned directory itself, never resolve its path again.
        from .move import delete_handle
        guard.prepare_rename()
        delete_handle(guard.root_handle)


def _discard_contents(root, cancel):
    """Bounded-memory deletion; yield to foreground work between entries.

    Parent directories stay pinned, links are rejected, and directory deletion
    checks the opened file ID again after acquiring a DELETE handle.
    """
    from .archive import check_cancel
    from .windows import pin_directory
    from .move import deletable_reader, delete_handle
    stack = [(root, None, None, os.scandir(root))]
    try:
        while stack:
            check_cancel(cancel)
            path, pin, expected, entries = stack[-1]
            entry = next(entries, None)
            if entry is None:
                entries.close()
                if pin is not None:
                    pin.Close(); stack[-1] = (path, None, expected, entries)
                    handle = pin_directory(path, rename=True)
                    try:
                        info = win32file.GetFileInformationByHandle(handle)
                        if (info[4], info[8], info[9]) != expected:
                            raise VaultError('The temporary folder changed. It was not removed.')
                        delete_handle(handle)
                    finally: handle.Close()
                stack.pop(); continue
            if path == root and entry.name == '.manager.lock': continue
            child = path / entry.name
            if entry.is_dir(follow_symlinks=False):
                pin = pin_directory(child)
                try:
                    info = win32file.GetFileInformationByHandle(pin)
                    listing = os.scandir(child)
                except BaseException:
                    pin.Close(); raise
                stack.append((child, pin, (info[4], info[8], info[9]), listing))
            else:
                with deletable_reader(child) as (_, handle): delete_handle(handle)
    finally:
        for _, pin, _, entries in reversed(stack):
            entries.close()
            if pin is not None: pin.Close()


def prune_private_partials(directory, prefix=''):
    """Caller holds the private state directory lease; no writer can be active."""
    from .move import deletable_reader, delete_handle
    for path in directory.glob(prefix + '*.partial'):
        suffix = path.name.removeprefix(prefix).removesuffix('.partial')
        try:
            if uuid.UUID(suffix).hex != suffix: continue
            with deletable_reader(path) as (_, handle): delete_handle(handle)
        except (OSError, ValueError, VaultError): continue


def discard_empty_vault(path, expected):
    """A rejected creation may leave only its empty lease file. Keep all data."""
    from .move import deletable_reader, delete_handle
    with VaultGuard(path) as guard:
        if list(guard.root_identity) != list(expected): return
        if {p.name for p in path.iterdir()} != {'.manager.lock'}: return
        guard.handle.Close(); guard.handle = None
        with deletable_reader(path / '.manager.lock') as (stream, handle):
            if stream.read(1): return
            delete_handle(handle)
        # Nonrecursive disposition fails safely if any file appeared meanwhile.
        guard.prepare_rename(); delete_handle(guard.root_handle)
