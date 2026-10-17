"""Conservative workspace estimates, without reading file contents."""
import os
from pathlib import Path
import shutil
import tempfile
from .windows import VaultError

MIB = 1024 * 1024


def volume_key(path):
    return os.stat(path).st_dev


def index_space(manifest_bytes, entries):
    # SQLite stores paths in the table and two indexes; leave page overhead.
    return 4 * manifest_bytes + entries * 1024 + 8 * MIB


def check_space(destination, destination_bytes, temporary_bytes):
    temporary = Path(tempfile.gettempdir())
    destination = Path(destination)
    same = volume_key(destination) == volume_key(temporary)
    if same:
        if shutil.disk_usage(destination).free < destination_bytes + temporary_bytes + 64 * MIB:
            raise VaultError('Not enough free space for the backup and temporary files.')
    else:
        if shutil.disk_usage(destination).free < destination_bytes + 64 * MIB:
            raise VaultError('Not enough free space on the destination drive.')
        if shutil.disk_usage(temporary).free < temporary_bytes + 16 * MIB:
            raise VaultError('Not enough free space on the temporary-files drive.')


def check_restore_space(destination, total, manifest_bytes, entries):
    check_space(Path(destination).parent, total + manifest_bytes + 8 * MIB,
                index_space(manifest_bytes, entries))
