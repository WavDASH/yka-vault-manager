"""Public per-record preferences, separate from live mount ownership."""
from pathlib import Path
from .windows import VaultError, safe_path, available_drives


def prepare_empty_folder(point):
    """Delete only the opened, empty directory; the kernel rejects nonempty ones.

    The caller pins its parents and reserves this mount location throughout startup.
    """
    import ctypes
    from ctypes import wintypes
    import win32file
    import win32con
    import pywintypes
    path = safe_path(point, must_exist=True)
    try:
        handle = win32file.CreateFile(str(path), win32con.DELETE | 0x80,  # FILE_READ_ATTRIBUTES
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None, win32con.OPEN_EXISTING, 0x02200000, None)
    except pywintypes.error:
        raise VaultError('The mount folder is in use or cannot be accessed. Close programs using it, or choose another empty folder.') from None
    try:
        flags = win32file.GetFileInformationByHandle(handle)[0]
        if flags & 0x400 or not flags & win32con.FILE_ATTRIBUTE_DIRECTORY:
            raise VaultError('The mount folder changed. Choose an empty folder again.')
        remove = ctypes.WinDLL('kernel32', use_last_error=True).SetFileInformationByHandle
        remove.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        remove.restype = wintypes.BOOL
        disposition = ctypes.c_ubyte(1)
        if not remove(int(handle), 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
            raise VaultError('The mount folder is not empty or is in use. Close programs using it, then choose an empty folder.')
    finally: handle.Close()


def validate_settings(value):
    if not isinstance(value, dict) or set(value) - {'mount_point', 'volume_label', 'unlock'}:
        raise VaultError('Invalid mount preferences. Credentials cannot be saved here.')
    if not all(isinstance(value.get(k, ''), str) for k in ('mount_point', 'volume_label')):
        raise VaultError('Mount point and volume label must be text.')
    point = value.get('mount_point', '').strip()
    label = value.get('volume_label', '').strip()
    if not point: raise VaultError('Choose a mount drive or folder.')
    if len(label.encode('utf-16-le')) > 64 or any(ord(c) < 32 or c in ',\\/:*?"<>|' for c in label):
        raise VaultError('Use a volume label of at most 32 characters without commas or Windows path symbols.')
    unlock = value.get('unlock', {'method': 'automatic'})
    if not isinstance(unlock, dict) or set(unlock) - {'method', 'serial', 'slot', 'public_key'}:
        raise VaultError('Only public unlock identifiers may be saved.')
    if unlock.get('method') not in ('automatic', 'recovery', 'piv'): raise VaultError('Unknown unlock preference.')
    if unlock['method'] == 'piv':
        if not isinstance(unlock.get('serial'), int) or not isinstance(unlock.get('slot'), int) or not isinstance(unlock.get('public_key'), str):
            raise VaultError('Select an authorized public key.')
    elif set(unlock) != {'method'}: raise VaultError('Unexpected unlock preference fields.')
    return dict(mount_point=point, volume_label=label, unlock=dict(unlock))


def available_point(point, root):
    if len(point) == 2 and point[1] == ':' and point[0].isascii() and point[0].isalpha():
        if point.upper() not in available_drives(): raise VaultError('The preferred drive is in use. Choose another mount location.')
        return point.upper()
    path = safe_path(point); vault = safe_path(root)
    if path == vault or vault in path.parents or path in vault.parents:
        raise VaultError('Choose a mount folder outside the encrypted vault and its parent folders.')
    if path.exists():
        if not path.is_dir(): raise VaultError('Choose an empty folder, not a file.')
        if next(path.iterdir(), None) is not None: raise VaultError('The mount folder is not empty. Choose an empty folder to keep its existing files safe.')
    if not path.parent.is_dir(): raise VaultError('The mount parent folder is unavailable.')
    return str(path)
