"""Short filesystem errors; only fixed categories and numeric codes leave worker."""
import errno
import sqlite3
from .windows import VaultError

MESSAGES = {
    'disk_full': 'The drive is full. Free some space and try again.',
    'drive_unavailable': 'The drive is unavailable. Check its connection and try again.',
    'file_in_use': 'A file or folder is in use. Close it and try again.',
    'permission_denied': 'Access was denied. Check the folder permissions.',
    'path_missing': 'A file or folder is no longer available. Check its location.',
    'io_failed': 'The drive could not read or write the files. Check the drive and try again.',
}


def error_info(error):
    if isinstance(error, VaultError): return str(error), getattr(error, 'diagnostic', {})
    win = getattr(error, 'winerror', None)
    posix = getattr(error, 'errno', None)
    code = None
    if type(win) is int:
        groups = {
            'disk_full': {39, 112}, 'file_in_use': {32, 33}, 'permission_denied': {5, 19, 1314},
            'path_missing': {2, 3}, 'drive_unavailable': {15, 21, 53, 55, 64, 67, 1167, 1231},
            'io_failed': {23, 27, 29, 30, 31, 1117},
        }
        code = next((name for name, values in groups.items() if win in values), None)
    elif isinstance(error, OSError):
        groups = {'disk_full': {errno.ENOSPC}, 'file_in_use': {errno.EBUSY},
                  'permission_denied': {errno.EACCES, errno.EPERM, errno.EROFS},
                  'path_missing': {errno.ENOENT, errno.ENOTDIR},
                  'drive_unavailable': {errno.ENODEV, errno.ENXIO}, 'io_failed': {errno.EIO}}
        code = next((name for name, values in groups.items() if posix in values), None)
    elif isinstance(error, sqlite3.Error):
        primary = getattr(error, 'sqlite_errorcode', 0) & 255
        code = {sqlite3.SQLITE_FULL: 'disk_full', sqlite3.SQLITE_IOERR: 'io_failed',
                sqlite3.SQLITE_BUSY: 'file_in_use', sqlite3.SQLITE_LOCKED: 'file_in_use'}.get(primary)
    diagnostic = dict(code=code or 'filesystem_failed', stage='filesystem')
    number = win if type(win) is int else posix
    if type(number) is int and 0 <= number <= 65535: diagnostic['system_error'] = number
    if code: return MESSAGES[code], diagnostic
    if isinstance(error, (OSError, sqlite3.Error)) or type(win) is int:
        return 'A file or folder could not be accessed. Check Diagnostics for details.', diagnostic
    return 'The operation failed. See Diagnostics for details.', dict(code='operation_failed', stage='request')
