"""Advisory encrypted-folder size. Never used for authentication or file writes."""
import json
import os
from pathlib import Path
import sys
import threading
import time
from datetime import datetime

from .windows import VaultError, safe_path
from .storage import KEY_FILE, MAX_KEY, parse_header


def binding(record):
    return [record['id'], record['path'], record['uuid'], record['signing_public'], record.get('size_revision', 0)]


def cache(record):
    value = record.get('size_cache')
    if (not isinstance(value, dict) or not isinstance(value.get('binding'), list) or len(value['binding']) != 5
        or any(not isinstance(v, str) for v in value['binding'][:4])
        or type(value['binding'][4]) is not int or value['binding'][4] < 0
        or value['binding'][:4] != binding(record)[:4]
        or type(value.get('bytes')) is not int or not 0 <= value['bytes'] < 2**63
        or type(value.get('measured_at')) is not int or not 0 < value['measured_at'] <= time.time() + 86400):
        return None
    return value


def display(record):
    value = cache(record); state = record.get('size_status', '')
    if value:
        size = value['bytes']; unit = 'B'
        for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'):
            if size < 1024 or unit == 'PiB': break
            size /= 1024
        text = f'{size:,} B' if unit == 'B' else f'{size:.2f} {unit}'
        if value['binding'] != binding(record) or record.get('state') != 'Unmounted' or state == 'unavailable': text = '~' + text
    else: text = 'Calculating…' if state == 'calculating' else 'Unavailable' if state == 'unavailable' else 'Not measured'
    detail = 'Encrypted-folder file sizes, including vault metadata. This is not disk space allocated.'
    if value:
        detail += '\nLast measured: ' + datetime.fromtimestamp(value['measured_at']).strftime('%Y-%m-%d %H:%M:%S')
        detail += f"\n{value['bytes']:,} bytes. Files may have changed since this measurement."
    if state == 'calculating': detail += '\nCalculating the current size…'
    elif state == 'unavailable': detail += '\n' + record.get('size_error', 'The size could not be measured. Use Refresh Size to try again.')
    if record.get('state') == 'Offline': detail += '\nThe vault is offline. The last measurement is shown when available.'
    return text, detail


def directory_identity(path):
    stat = path.stat(follow_symlinks=False)
    if stat.st_file_attributes & 0x400 or not stat.st_file_attributes & 0x10:
        raise VaultError('The size could not be measured because a folder is a link or is unavailable.')
    return stat.st_dev, stat.st_ino


def header(root):
    # Read only the public, signed bootstrap. No credentials, native crypto worker,
    # registry writes or no-delete-sharing pins in this disposable size process.
    key = root / KEY_FILE
    if key.stat(follow_symlinks=False).st_file_attributes & 0x400:
        raise VaultError('The vault key file is a link.')
    with key.open('rb') as stream: return parse_header(stream.read(MAX_KEY + 1))


def measure(record, cancelled=lambda: False):
    root = safe_path(record['path'], must_exist=True)
    original = directory_identity(root); before = header(root)
    if (before['uuid'], before['signing_public']) != (record['uuid'], record['signing_public']):
        raise VaultError('The folder no longer matches this vault. Check its saved location.')
    total = 0; frames = []
    def descend(path):
        stamp = directory_identity(path)
        frames.append((path, stamp, os.scandir(path)))
    try:
        descend(root)
        while frames:
            if cancelled(): raise VaultError('Size calculation cancelled.')
            path, stamp, entries = frames[-1]
            item = next(entries, None)
            if item is None:
                if directory_identity(path) != stamp:
                    raise VaultError('The folder changed during measurement. Refresh its size again.')
                frames.pop(); entries.close(); continue
            stat = item.stat(follow_symlinks=False)
            if stat.st_file_attributes & 0x400:
                raise VaultError('The folder contains a link. Its size was not saved.')
            if stat.st_file_attributes & 0x10: descend(Path(item.path))
            else: total += stat.st_size
        after = header(root)
        if directory_identity(root) != original or before['keyring_sha256'] != after['keyring_sha256']:
            raise VaultError('The vault changed during measurement. Refresh its size again.')
        return dict(binding=binding(record), bytes=total, measured_at=int(time.time()))
    finally:
        for _, _, entries in reversed(frames): entries.close()


def main():
    raw = sys.stdin.readline(65537)
    if len(raw) > 65536: return
    # If the GUI crashes, pipe EOF ends this read-only helper even if its scan is
    # blocked in a device call. The OS releases its enumeration handles.
    def parent_closed():
        sys.stdin.read(); os._exit(0)
    threading.Thread(target=parent_closed, daemon=True).start()
    try: result = {'size': measure(json.loads(raw))}
    except VaultError as error: result = {'error': str(error)}
    except Exception: result = {'error': 'The size could not be measured. Check the drive connection and permissions, then use Refresh Size.'}
    print(json.dumps(result), flush=True)


if __name__ == '__main__': main()
