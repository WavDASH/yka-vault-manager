"""Kernel-owned per-directory guards. A path alias opens the same lock file."""
import os
import ctypes
import hashlib
from contextlib import contextmanager
from pathlib import Path
import win32api
import win32con
import win32file
import win32security
from win32com.shell import shellcon


class VaultError(RuntimeError):
    pass


def available_drives():
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    buffer = ctypes.create_unicode_buffer(32768)
    return [f'{chr(65+i)}:' for i in range(3, 26) if not mask & (1 << i)
        and not ctypes.windll.kernel32.QueryDosDeviceW(f'{chr(65+i)}:', buffer, len(buffer))]


def safe_path(path, *, must_exist=False):
    path = Path(os.path.abspath(path))
    if str(path).upper().startswith(('\\\\.\\', '\\\\?\\GLOBALROOT\\')):
        raise VaultError('Windows device paths are not supported.')
    reserved = {'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$',
        *(f'{prefix}{n}' for prefix in ('COM', 'LPT') for n in '123456789¹²³')}
    for part in path.parts[1:]:
        if ':' in part or part.rstrip(' .').split('.')[0].rstrip(' ').upper() in reserved:
            raise VaultError('Alternate data streams and reserved Windows file names are not supported.')
    # Refuse junctions and symlinks rather than following them during security operations.
    exists = False
    for candidate in [path, *path.parents]:
        try:
            stat = candidate.lstat()
        except FileNotFoundError:
            continue
        if candidate == path: exists = True
        if stat.st_file_attributes & 0x400:
            raise VaultError('Links and junctions are not supported.')
    if must_exist and not exists:
        raise VaultError('File or folder does not exist.')
    return path


def private_directory(path):
    path = safe_path(path)
    path.mkdir()
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    sid_text = win32security.ConvertSidToStringSid(sid)
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid_text})', win32security.SDDL_REVISION_1)
    win32security.SetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION,
                                 descriptor)
    return path


def output_identity(path):
    """Bind a save-dialog replacement to the existing regular file."""
    path = safe_path(path)
    if not path.exists(): return None
    with guarded_reader(path) as source:
        st = os.fstat(source.fileno())
        return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def reject_named_streams(path):
    """Ordinary ciphertext backup/move cannot silently discard NTFS streams."""
    volume = win32file.GetVolumePathName(str(path))
    if win32api.GetVolumeInformation(volume)[3] & 0x40000:
        if any(name != '::$DATA' for _, name in win32file.FindStreams(str(path))):
            raise VaultError('Files with alternate data streams are not supported.')


def publish_output(partial, output, replace_existing=None):
    # Caller pins the parent directories. Never truncate the old backup first.
    safe_path(output)
    if replace_existing is None:
        os.rename(partial, output)  # Windows refuses an existing destination.
    else:
        if output_identity(output) != replace_existing:
            raise VaultError('The destination file changed after you selected it. Save again to confirm which file to replace.')
        os.replace(partial, output)


class VaultGuard:
    def __init__(self, root, *, rename=False):
        self.root = safe_path(root, must_exist=True)
        self.pins = []
        self.extra = []
        self.handle = None
        self.root_identity = None
        self.rename_enabled = rename
        self.root_handle = None
        try:
            # Deny directory rename/delete for the lifetime of the operation. Open
            # reparse points themselves and inspect the opened object, not just lstat.
            for path in reversed([self.root, *self.root.parents]):
                pinned = pin_directory(path, rename=rename and path == self.root); self.pins.append(pinned)
                if path == self.root:
                    self.root_handle = pinned
                    info = win32file.GetFileInformationByHandle(pinned)
                    self.root_identity = (info[4], info[8], info[9])
            safe_path(self.root / '.manager.lock')
            self.handle = win32file.CreateFile(str(self.root / '.manager.lock'),
                win32con.GENERIC_READ | win32con.GENERIC_WRITE, 0, None,
                win32con.OPEN_ALWAYS, win32con.FILE_ATTRIBUTE_HIDDEN | 0x00200000, None)
            info = win32file.GetFileInformationByHandle(self.handle)
            if info[0] & 0x400 or info[7] > 1:
                raise VaultError('Lock is a reparse point.')
        except Exception:
            self.close()
            raise VaultError('Vault is busy in another process, or its lock is unavailable.') from None

    @property
    def handles(self): return [self.handle, *self.pins, *self.extra]

    def borrow(self):
        """Retain the same kernel lease for a read-only task, independently of unmount."""
        return BorrowedGuard(self.handles)

    def reserve(self, directory, identity):
        path = directory / (hashlib.sha256(identity.encode()).hexdigest() + '.lock')
        pins = []; handle = None
        try:
            safe_path(path)
            for parent in reversed(path.parents): pins.append(pin_directory(parent))
            handle = win32file.CreateFile(str(path), win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                0, None, win32con.OPEN_ALWAYS, win32con.FILE_ATTRIBUTE_HIDDEN | 0x00200000, None)
            info = win32file.GetFileInformationByHandle(handle)
            if info[0] & (0x400 | win32con.FILE_ATTRIBUTE_DIRECTORY) or info[7] != 1:
                raise VaultError('The volume lease is not a regular private lock file.')
        except BaseException:
            if handle is not None: handle.Close()
            for pinned in pins: pinned.Close()
            raise
        self.extra.append(handle); self.pins.extend(pins)

    def same_root(self):
        try:
            handle = pin_directory(self.root, share_delete=self.rename_enabled)
            try:
                info = win32file.GetFileInformationByHandle(handle)
                return self.root_identity == (info[4], info[8], info[9])
            finally: handle.Close()
        except Exception: return False

    def prepare_rename(self):
        if self.rename_enabled: return
        self.pins.remove(self.root_handle); self.root_handle.Close()
        self.root_handle = pin_directory(self.root, rename=True)
        self.pins.append(self.root_handle); self.rename_enabled = True
        info = win32file.GetFileInformationByHandle(self.root_handle)
        if self.root_identity != (info[4], info[8], info[9]):
            raise VaultError('The vault folder changed before restore commit.')

    def rename_to(self, destination):
        if not self.rename_enabled: raise VaultError('Directory rename was not reserved.')
        destination = safe_path(destination)
        if destination.parent != self.root.parent: raise VaultError('Restore must stay in the same parent folder.')
        if self.handle is not None:
            self.handle.Close(); self.handle = None
        # Rename the opened directory itself, never a path resolved a second time.
        from ctypes import wintypes
        class RenameInfo(ctypes.Structure):
            _fields_ = [('flags', wintypes.DWORD), ('root', wintypes.HANDLE),
                        ('length', wintypes.DWORD), ('name', wintypes.WCHAR * 1)]
        raw = str(destination).encode('utf-16-le')
        buffer = ctypes.create_string_buffer(RenameInfo.name.offset + len(raw) + 2)
        info = RenameInfo.from_buffer(buffer); info.length = len(raw)
        ctypes.memmove(ctypes.addressof(buffer) + RenameInfo.name.offset, raw, len(raw))
        function = ctypes.WinDLL('kernel32', use_last_error=True).SetFileInformationByHandle
        function.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        function.restype = wintypes.BOOL
        if not function(int(self.root_handle), 3, buffer, len(buffer)):
            raise ctypes.WinError(ctypes.get_last_error())
        self.root = destination

    def close(self):
        if self.handle is not None:
            self.handle.Close()
            self.handle = None
        for handle in self.extra + self.pins: handle.Close()
        self.extra.clear(); self.pins.clear()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


class BorrowedGuard:
    def __init__(self, handles):
        self.handles = []
        process = win32api.GetCurrentProcess()
        try:
            for handle in handles:
                self.handles.append(win32api.DuplicateHandle(process, handle, process, 0, False, win32con.DUPLICATE_SAME_ACCESS))
        except BaseException: self.close(); raise
    def close(self):
        for handle in self.handles: handle.Close()
        self.handles.clear()
    def __enter__(self): return self
    def __exit__(self, *args): self.close()


def pin_directory(path, *, rename=False, share_delete=False):
    handle = win32file.CreateFile(str(path), win32con.GENERIC_READ | (win32con.DELETE if rename else 0), win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | (win32con.FILE_SHARE_DELETE if share_delete else 0),
        None, win32con.OPEN_EXISTING, 0x02000000 | 0x00200000, None)
    attributes = win32file.GetFileInformationByHandle(handle)[0]
    if attributes & 0x400 or not attributes & win32con.FILE_ATTRIBUTE_DIRECTORY:
        handle.Close(); raise VaultError('Unsafe directory.')
    return handle


@contextmanager
def pinned_parents(path):
    pins = []
    try:
        path = safe_path(path)
        for parent in reversed(path.parents): pins.append(pin_directory(parent))
        safe_path(path)
        yield path
    finally:
        for handle in pins: handle.Close()


@contextmanager
def new_file(path, *, paths=None):
    with (pinned_parents(path) if paths is None else paths.parents(path)) as checked:
        with checked.open('xb') as output: yield output


@contextmanager
def guarded_reader(path):
    """Deny writes/deletes while this file is being streamed; not a tree-wide snapshot."""
    import msvcrt
    path = safe_path(path, must_exist=True); pins = []
    try:
        for parent in reversed(path.parents): pins.append(pin_directory(parent))
        handle = win32file.CreateFile(str(path), win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ, None, win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_SEQUENTIAL_SCAN | 0x00200000, None)
        info = win32file.GetFileInformationByHandle(handle)
        if info[0] & 0x400 or info[7] > 1:
            handle.Close(); raise VaultError('Links are not supported.')
        with os.fdopen(msvcrt.open_osfhandle(handle.Detach(), os.O_RDONLY), 'rb') as stream: yield stream
    finally:
        for handle in pins: handle.Close()


def mount_state(backend, point):
    import subprocess
    result = subprocess.run([str(backend), 'ismount', point], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW, timeout=10)
    if result.returncode not in (0, 1):
        raise VaultError('Mount status unknown. Operation stopped.')
    return result.returncode == 0


def mount_device(point):
    point = point + '\\' if len(point) == 2 else point
    handle = win32file.CreateFile(point, 0, 7, None, win32con.OPEN_EXISTING, 0x02000000, None)
    try: return win32file.GetFinalPathNameByHandle(handle, 2)
    finally: handle.Close()
