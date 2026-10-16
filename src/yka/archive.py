"""Streaming, Store-only ZIP64 version 2 format; signed manifest; bounded disk index."""
import base64
from contextlib import closing, nullcontext
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import stat
import struct
import tempfile
import time
import unicodedata
import uuid
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .windows import VaultError, safe_path, guarded_reader, private_directory, VaultGuard, pinned_parents, new_file, output_identity, publish_output

DOMAIN = b'YKA-ARCHIVE-2\x00'
from .storage import KEY_FILE, internal_file, parse_header
CHUNK = 1024 * 1024
MAX_METADATA = 4 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024 * 1024
MAX_ENTRIES = 120_000
MAX_CENTRAL = 32 * 1024 * 1024
RESERVED = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)),
            *(f'LPT{i}' for i in range(1, 10))}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def check_cancel(cancel):
    if cancel(): raise VaultError('Cancelled. No result committed.')


def unique_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise VaultError('Duplicate metadata fields.')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def preflight(path, *, stream=None):
    """Bound ZIP central-directory allocation before zipfile constructs its entry objects."""
    with (guarded_reader(path) if stream is None else nullcontext(stream)) as stream:
        length = os.fstat(stream.fileno()).st_size
        if length < 22: raise VaultError('Archive is truncated.')
        stream.seek(max(0, length - 65557)); tail = stream.read(65557)
        offset = tail.rfind(b'PK\x05\x06')
        if offset < 0 or offset + 22 > len(tail): raise VaultError('ZIP end record missing.')
        _, disk, central_disk, disk_entries, count, size, start, comment = struct.unpack_from('<4s4H2IH', tail, offset)
        eocd = length - len(tail) + offset
        if disk or central_disk or offset + 22 + comment != len(tail):
            raise VaultError('Split ZIP or trailing data is not supported.')
        if count == 0xFFFF or size == 0xFFFFFFFF or start == 0xFFFFFFFF:
            if eocd < 20: raise VaultError('ZIP64 locator missing.')
            stream.seek(eocd - 20); locator = stream.read(20)
            magic, locator_disk, position, disks = struct.unpack('<4sIQI', locator)
            if magic != b'PK\x06\x07' or locator_disk or disks != 1: raise VaultError('Invalid ZIP64 locator.')
            stream.seek(position); record = stream.read(56)
            if len(record) != 56: raise VaultError('ZIP64 record is truncated.')
            magic, record_size, _, _, disk, central_disk, disk_entries, count, size, start = struct.unpack('<4sQ2H2I4Q', record)
            if magic != b'PK\x06\x06' or record_size != 44 or disk or central_disk or position + 56 != eocd - 20:
                raise VaultError('Invalid ZIP64 end record.')
            limit = position
        else: limit = eocd
        if disk_entries != count or count > MAX_ENTRIES + 2 or size > MAX_CENTRAL or start + size != limit:
            raise VaultError('ZIP directory is invalid or too large.')
        stream.seek(start); scanned = 0
        while stream.tell() < limit:
            fixed = stream.read(46)
            if len(fixed) != 46 or fixed[:4] != b'PK\x01\x02': raise VaultError('Invalid ZIP directory.')
            name_len, extra_len, comment_len = struct.unpack_from('<3H', fixed, 28)
            if not name_len or name_len > 32000: raise VaultError('ZIP filename too long.')
            next_entry = stream.tell() + name_len + extra_len + comment_len
            if next_entry > limit: raise VaultError('ZIP directory record out of bounds.')
            stream.seek(next_entry); scanned += 1
            if scanned > MAX_ENTRIES + 2: raise VaultError('Too many archive entries.')
        if scanned != count: raise VaultError('ZIP entry count mismatch.')


def entry_path(name, is_dir=False, *, archive_names=True):
    if not isinstance(name, str) or len(name) > 32000 or '\\' in name or '\x00' in name:
        raise VaultError('Invalid archive path.')
    trimmed = name[:-1] if is_dir and name.endswith('/') else name
    parts = trimmed.split('/')
    if not trimmed or len(parts) > 128 or (archive_names and (internal_file(parts[0]) or parts[0].casefold() in ('manifest.jsonl', 'manifest.sig'))):
        raise VaultError('Archive contains a reserved or invalid path.')
    for component in parts:
        if not component or component in ('.', '..') or component[-1:] in ('.', ' '):
            raise VaultError('Unsafe archive path.')
        if any(c in component for c in ':<>"|?*') or any(ord(c) < 32 for c in component):
            raise VaultError('Invalid Windows path characters.')
        if unicodedata.normalize('NFKC', component.split('.')[0]).upper().rstrip(' ') in RESERVED:
            raise VaultError('Reserved Windows filename.')
    return trimmed, unicodedata.normalize('NFC', trimmed).casefold()


def tree(root):
    for required in (KEY_FILE, '.config.pb'):
        if not safe_path(root / required, must_exist=True).is_file(): raise VaultError('Vault files are missing.')
    stack = [root]
    while stack:
        directory = stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                if directory == root and internal_file(entry.name): continue
                current = (directory / entry.name).lstat()
                if current.st_file_attributes & 0x400 or entry.is_symlink(): raise VaultError('Source contains links or reparse points.')
                relative = (directory / entry.name).relative_to(root).as_posix(); entry_path(relative)
                if stat.S_ISDIR(current.st_mode):
                    yield relative, 'directory', current; stack.append(directory / entry.name)
                elif stat.S_ISREG(current.st_mode):
                    if current.st_nlink > 1: raise VaultError('Hard links are not supported.')
                    from .windows import reject_named_streams
                    reject_named_streams(directory / entry.name)
                    yield relative, 'file', current
                else: raise VaultError('Unsupported source file type.')


def index_source(db, root, cancel):
    db.execute('create table files(path text primary key, kind text, size integer, mtime integer, inode integer, digest text)')
    for count, (name, kind, st) in enumerate(tree(root), 1):
        check_cancel(cancel)
        if count > MAX_ENTRIES: raise VaultError('Too many source entries.')
        db.execute('insert into files values(?,?,?,?,?,null)',
                   (name, kind, st.st_size if kind == 'file' else 0, st.st_mtime_ns, st.st_ino))
    db.commit()


def export_archive(root, output, sign, *, progress=lambda _: None, cancel=lambda: False, replace_existing=None, on_residual=lambda _: None):
    root = safe_path(root, must_exist=True)
    output = safe_path(output)
    if output == root or root in output.parents: raise VaultError('Save the archive outside this vault.')
    if output.exists() and replace_existing is None: raise VaultError('Output already exists. Choose a new file.')
    if replace_existing is not None and output_identity(output) != replace_existing:
        raise VaultError('The destination file changed. Save again to confirm its replacement.')
    if not output.parent.is_dir(): raise VaultError('Output parent folder does not exist.')
    partial = output.with_name(output.name + '.' + uuid.uuid4().hex + '.partial')
    on_residual(partial)
    from .residuals import temporary_output
    def retain_interrupted(error):
        # Source loss/change can make even incomplete ciphertext valuable for
        # recovery. Cancelled or invalid exports with an available source are
        # disposable; uncertain storage failures are not.
        return (isinstance(error, OSError) or str(error).startswith('Source ')
                or not (root / KEY_FILE).is_file() or not (root / '.config.pb').is_file())
    try:
        with temporary_output(partial, retain_on_error=retain_interrupted) as staged, tempfile.TemporaryDirectory(prefix='yka-index-') as scratch, closing(sqlite3.connect(str(Path(scratch) / 'index.sqlite'))) as db:
            progress('Scanning encrypted source...')
            index_source(db, root, cancel)
            total = db.execute('select coalesce(sum(size),0) from files').fetchone()[0]
            if shutil.disk_usage(output.parent).free < total + 64 * 1024 * 1024:
                raise VaultError('Not enough free disk space.')
            header = {'type': 'YKA', 'schema': '2', 'compression': 'store',
                'source_consistency': 'unconfirmed', 'source_detection': 'before-after-stat-and-hash',
                'experimental': True}
            manifest = Path(scratch) / 'manifest.jsonl'
            progress('Exporting encrypted files...')
            processed = 0; last_progress = time.monotonic()
            hashed = hashlib.sha256(DOMAIN)
            with manifest.open('xb') as listing, zipfile.ZipFile(staged, 'w', compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                raw = canonical({'header': header}) + b'\n'; listing.write(raw); hashed.update(raw)
                for number, (name, kind, size, mtime, inode, _) in enumerate(db.execute('select * from files order by path'), 1):
                    check_cancel(cancel)
                    record = {'path': name, 'kind': kind, 'size': size}
                    if kind == 'directory': archive.writestr(name + '/', b'')
                    else:
                        digest = hashlib.sha256()
                        copied = 0
                        with guarded_reader(root / Path(name)) as source, archive.open(name, 'w', force_zip64=True) as dest:
                            before = os.fstat(source.fileno())
                            if (before.st_size, before.st_mtime_ns, before.st_ino) != (size, mtime, inode):
                                raise VaultError('Source changed. Export stopped.')
                            while chunk := source.read(CHUNK):
                                check_cancel(cancel)
                                digest.update(chunk); dest.write(chunk); copied += len(chunk); processed += len(chunk)
                                if time.monotonic() - last_progress >= 0.5:
                                    progress(f'Exporting encrypted files: {processed:,} of {total:,} bytes ({processed * 100 // max(total, 1)}%).')
                                    last_progress = time.monotonic()
                            after = os.fstat(source.fileno())
                            if copied != size or (after.st_size, after.st_mtime_ns, after.st_ino) != (size, mtime, inode):
                                raise VaultError('Source changed during reading. Export stopped.')
                        record['sha256'] = digest.hexdigest()
                        db.execute('update files set digest=? where path=?', (record['sha256'], name))
                    raw = canonical(record) + b'\n'; listing.write(raw); hashed.update(raw)
                    if listing.tell() > MAX_MANIFEST: raise VaultError('Manifest exceeds size limit.')
                    if number % 5000 == 0: progress(f'Exported {number:,} entries.')
                listing.flush(); os.fsync(listing.fileno())
            # A second tree/content sweep detects ordinary concurrent changes; it is not a snapshot guarantee.
            progress('Checking source changes...')
            seen = 0
            for name, kind, st in tree(root):
                check_cancel(cancel)
                expected = db.execute('select kind,size,mtime,inode,digest from files where path=?', (name,)).fetchone()
                if expected is None or expected[:4] != (kind, st.st_size if kind == 'file' else 0, st.st_mtime_ns, st.st_ino):
                    raise VaultError('Source directory changed. Export stopped.')
                if kind == 'file':
                    digest = hashlib.sha256()
                    with guarded_reader(root / Path(name)) as source:
                        while chunk := source.read(CHUNK):
                            check_cancel(cancel); digest.update(chunk)
                    if digest.hexdigest() != expected[4]: raise VaultError('Source content changed. Export stopped.')
                seen += 1
            if seen != db.execute('select count(*) from files').fetchone()[0]:
                raise VaultError('Source file removed. Export stopped.')
            signature = sign(hashed.digest())
            with zipfile.ZipFile(staged, 'a', compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                archive.write(manifest, 'manifest.jsonl')
                archive.writestr('manifest.sig', canonical({'algorithm': 'Ed25519', 'signature': signature['signature']}))
            staged.flush(); os.fsync(staged.fileno())
            # Reopen and hash every archived byte, including exact entry coverage, before publishing.
            progress('Verifying archive...')
            preflight(partial, stream=staged)
            _validate_archive_stream(staged, signature['signing_public'], cancel)
            check_cancel(cancel)
            staged.close()
            publish_output(partial, output, replace_existing)
            db.close()
        progress('Exported. Signature verified; source consistency unconfirmed.')
        return {'path': str(output), 'authenticated': True, 'source_consistency': 'unconfirmed', 'experimental': True}
    finally:
        if partial.exists(): progress('Export did not complete. Recovery data remains at ' + str(partial) + '. It is not a verified backup.')



def _prepare(archive, db, cancel=lambda: False):
    db.execute('create table entries(path text primary key, folded text unique, kind text, size integer, digest text)')
    infos = archive.infolist()  # stdlib ZIP central directory costs O(entry count); enforced limits below.
    if len(infos) > MAX_ENTRIES + 2: raise VaultError('Too many archive entries.')
    names = set()
    for info in infos:
        check_cancel(cancel)
        if info.filename in names: raise VaultError('Duplicate archive entries.')
        names.add(info.filename)
        mode = info.external_attr >> 16
        if info.flag_bits & 1 or info.compress_type != zipfile.ZIP_STORED or stat.S_ISLNK(mode):
            raise VaultError('Encrypted ZIP, compression, or links are not supported.')
        if info.file_size < 0 or info.compress_size != info.file_size:
            raise VaultError('Invalid archive size.')
    if not {'manifest.jsonl', 'manifest.sig'} <= names: raise VaultError('Authentication manifest missing.')
    if archive.getinfo('manifest.jsonl').file_size > MAX_MANIFEST or archive.getinfo('manifest.sig').file_size > 8192:
        raise VaultError('Archive metadata too large.')
    signature = unique_json(archive.read('manifest.sig'))
    if signature.get('algorithm') != 'Ed25519': raise VaultError('Unsupported signature algorithm.')
    hasher = hashlib.sha256(DOMAIN)
    header = None
    with archive.open('manifest.jsonl') as lines:
        for number in range(MAX_ENTRIES + 2):
            check_cancel(cancel)
            raw = lines.readline(MAX_METADATA + 1)
            if not raw: break
            if len(raw) > MAX_METADATA or not raw.endswith(b'\n'): raise VaultError('Invalid manifest record.')
            hasher.update(raw); record = unique_json(raw)
            if number == 0:
                header = record.get('header')
                if not isinstance(header, dict) or header.get('schema') != '2' or header.get('type') != 'YKA':
                    raise VaultError('Unsupported archive version.')
                if header.get('compression') != 'store' or header.get('source_consistency') != 'unconfirmed':
                    raise VaultError('Unsupported archive consistency or compression mode.')
                continue
            name, folded = entry_path(record.get('path'), record.get('kind') == 'directory')
            kind = record.get('kind'); size = record.get('size')
            if kind not in ('file', 'directory') or not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise VaultError('Invalid manifest type or size.')
            if kind == 'directory' and size != 0: raise VaultError('Invalid directory entry size.')
            digest = record.get('sha256')
            if kind == 'file' and (not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest)):
                raise VaultError('Invalid manifest hash.')
            zipname = name + '/' if kind == 'directory' else name
            if zipname not in names or archive.getinfo(zipname).file_size != size:
                raise VaultError('Manifest does not match archive entries.')
            db.execute('insert into entries values(?,?,?,?,?)', (name, folded, kind, size, digest))
        else: raise VaultError('Too many manifest entries.')
    if db.execute('select count(*) from entries').fetchone()[0] + 2 != len(names):
        raise VaultError('Unlisted archive files.')
    for name, kind in db.execute('select path,kind from entries'):
        check_cancel(cancel)
        parent = PurePosixPath(name).parent
        while str(parent) != '.':
            row = db.execute('select kind from entries where path=?', (str(parent),)).fetchone()
            if row != ('directory',): raise VaultError('Conflicting paths or missing parent directory.')
            parent = parent.parent
    if not db.execute("select 1 from entries where path='.yka-key' and kind='file'").fetchone():
        raise VaultError('Keyring missing. Vault recovery is unavailable.')
    if db.execute("select size from entries where path='.yka-key'").fetchone()[0] > MAX_METADATA:
        raise VaultError('Keyring too large.')
    if not db.execute("select 1 from entries where path='.config.pb' and kind='file'").fetchone():
        raise VaultError('SecureFS configuration is missing.')
    return header, signature, hasher.digest()


def validate_archive(path, *, signing_public=None, cancel=lambda: False):
    with guarded_reader(path) as stream:
        preflight(path, stream=stream)
        return _validate_archive_stream(stream, signing_public, cancel)


def _validate_archive_stream(stream, signing_public, cancel):
    with tempfile.TemporaryDirectory(prefix='yka-verify-') as scratch, zipfile.ZipFile(stream) as archive, closing(sqlite3.connect(str(Path(scratch) / 'index.sqlite'))) as db:
        header, signature, digest = _prepare(archive, db)
        for name, kind, size, expected in db.execute('select path,kind,size,digest from entries'):
            check_cancel(cancel)
            if kind == 'directory': continue
            hashed = hashlib.sha256(); actual = 0
            with archive.open(name) as source:
                while chunk := source.read(CHUNK):
                    check_cancel(cancel); hashed.update(chunk); actual += len(chunk)
                    if actual > size: raise VaultError('Archive content exceeds declared size.')
            if actual != size or hashed.hexdigest() != expected: raise VaultError('Archive is damaged or content does not match.')
        if signing_public:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(signing_public, validate=True)).verify(
                base64.b64decode(signature['signature'], validate=True), digest)
        db.close()
        return dict(header, authenticated=bool(signing_public))


def authentication_metadata(stream, cancel=lambda: False):
    """Read bounded encrypted metadata only; never extract or ask for credentials."""
    with zipfile.ZipFile(stream) as source:
        metadata = {}
        for name, field in (('.yka-key', 'archive_keyring'), ('.config.pb', 'archive_config')):
            matches = [entry for entry in source.infolist() if entry.filename == name]
            if len(matches) != 1: raise VaultError('Missing or duplicate backup metadata.')
            entry = matches[0]
            if entry.file_size > MAX_METADATA or entry.compress_type != zipfile.ZIP_STORED or entry.flag_bits & 1:
                raise VaultError('Unsupported backup metadata.')
            check_cancel(cancel)
            metadata[field] = base64.b64encode(source.read(entry)).decode()
        if len(json.dumps(metadata).encode()) > MAX_METADATA - 65536:
            raise VaultError('Backup metadata exceeds the authentication size limit.')
        return metadata


def check_restore_identity(metadata, expected):
    """Public signature/identity precheck; final Rust authentication is still required."""
    body = parse_header(base64.b64decode(metadata['archive_keyring'], validate=True))
    if (body['uuid'], body['signing_public']) != (expected['uuid'], expected['signing_public']):
        raise VaultError('This backup belongs to a different vault. Choose a backup of the selected vault.')
    config = base64.b64decode(metadata['archive_config'], validate=True)
    if hashlib.sha256(config).hexdigest() != body['config_sha256']:
        raise VaultError('The backup configuration does not match its signed vault identity. Choose an intact backup.')
    return body


def public_precheck(stream, *, destination=None, expected=None, cancel=lambda: False):
    """Reject malformed public data without secrets or extracted/staging files.

    A self-signed header proves consistency, not authority. Rust must still
    decrypt the selected channel, and extraction must still verify every byte.
    """
    preflight(None, stream=stream)
    metadata = authentication_metadata(stream, cancel)
    body = parse_header(base64.b64decode(metadata['archive_keyring'], validate=True))
    check_restore_identity(metadata, expected or body)
    with zipfile.ZipFile(stream) as source, closing(sqlite3.connect(':memory:')) as db:
        _, signature, digest = _prepare(source, db, cancel)
        check_cancel(cancel)
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(body['signing_public'], validate=True)).verify(
                base64.b64decode(signature['signature'], validate=True), digest)
        except Exception: raise VaultError('Archive is damaged or content does not match.') from None
        for name, field in (('.yka-key', 'archive_keyring'), ('.config.pb', 'archive_config')):
            raw = base64.b64decode(metadata[field], validate=True)
            if db.execute('select digest from entries where path=?', (name,)).fetchone() != (hashlib.sha256(raw).hexdigest(),):
                raise VaultError('Archive is damaged or content does not match.')
        total = db.execute('select coalesce(sum(size),0) from entries').fetchone()[0]
        if destination is not None and shutil.disk_usage(Path(destination).parent).free < total + 64 * 1024 * 1024:
            raise VaultError('Not enough free disk space.')
    return metadata, body


def import_archive(path, destination, verify, *, authenticated=False, cancel=lambda: False, progress=lambda _: None, before_publish=lambda *_: None, on_residual=lambda _: None, authenticate_first=False):
    path = safe_path(path, must_exist=True)
    destination = safe_path(destination)
    if destination.exists(): raise VaultError('Import folder already exists. Choose a new folder.')
    if not destination.parent.is_dir(): raise VaultError('Import parent folder does not exist.')
    # Keep the same deny-write/delete handle from preflight through extraction.
    with guarded_reader(path) as stream, pinned_parents(Path(destination)):
        preflight(path, stream=stream)
        verified = None
        if authenticate_first:
            if not authenticated: raise VaultError('Backup authentication is required.')
            # Read only bounded encrypted metadata. No destination, staging
            # directory, disk index or extracted files exist at this point.
            metadata, _ = public_precheck(stream, destination=destination, cancel=cancel)
            progress('Unlocking the backup. Complete the YubiKey prompt if requested…')
            verified = verify(metadata)
            check_cancel(cancel)
            progress('Checking the backup signature and all file hashes. Your current vault has not been changed…')
            _validate_archive_stream(stream, verified['signing_public'], cancel)
        return _import_archive_stream(stream, destination, verify, authenticated, cancel, progress, before_publish, on_residual, verified)


def _import_archive_stream(stream, destination, verify, authenticated, cancel, progress, before_publish, on_residual, verified=None):
    destination = safe_path(destination)
    if destination.exists(): raise VaultError('Import folder already exists. Choose a new folder.')
    if not destination.parent.is_dir(): raise VaultError('Import parent folder does not exist.')
    stage = destination.with_name('.' + destination.name + '.' + uuid.uuid4().hex + '.staging')
    on_residual(stage)
    private_directory(stage)
    stage_identity = None; publishing = False
    try:
        with VaultGuard(stage) as stage_guard, tempfile.TemporaryDirectory(prefix='yka-import-') as scratch, zipfile.ZipFile(stream) as archive, closing(sqlite3.connect(str(Path(scratch) / 'index.sqlite'))) as db:
            stage_identity = list(stage_guard.root_identity)
            progress('Checking archive index...')
            header, signature, digest = _prepare(archive, db)
            total = db.execute('select coalesce(sum(size),0) from entries').fetchone()[0]
            if shutil.disk_usage(stage).free < total + 64 * 1024 * 1024: raise VaultError('Not enough free disk space.')
            progress('Restoring encrypted files...')
            processed = 0; last_progress = time.monotonic()
            for number, (name, kind, size, expected) in enumerate(db.execute('select path,kind,size,digest from entries order by length(path),path'), 1):
                check_cancel(cancel)
                target = safe_path(stage / Path(name))
                if stage not in target.parents: raise VaultError('Archive path escapes the import folder.')
                if kind == 'directory':
                    with pinned_parents(target): target.mkdir()
                    continue
                hashed = hashlib.sha256(); copied = 0
                with archive.open(name) as source, new_file(target) as output:
                    while chunk := source.read(CHUNK):
                        check_cancel(cancel); copied += len(chunk)
                        if copied > size: raise VaultError('Archive size limit exceeded.')
                        hashed.update(chunk); output.write(chunk); processed += len(chunk)
                        if time.monotonic() - last_progress >= 0.5:
                            progress(f'Restoring encrypted files: {processed:,} of {total:,} bytes ({processed * 100 // max(total, 1)}%).')
                            last_progress = time.monotonic()
                    output.flush(); os.fsync(output.fileno())
                if copied != size or hashed.hexdigest() != expected: raise VaultError('Restored content verification failed.')
                if number % 5000 == 0: progress(f'Restored {number:,} entries.')
            proof = {'signature': signature['signature'], 'digest': base64.b64encode(digest).decode(),
                     'source_consistency': header.get('source_consistency', 'unconfirmed')}
            with archive.open('manifest.jsonl') as source, (stage / '.import-manifest.jsonl').open('xb') as output:
                shutil.copyfileobj(source, output, CHUNK)
            (stage / '.import-proof.json').write_bytes(canonical(proof))
            # Check the original manifest signature before publishing even a
            # keyless import. Credential authentication remains a separate step.
            with guarded_reader(stage / '.yka-key') as source:
                keyring = parse_header(source.read(MAX_METADATA + 1))
            Ed25519PublicKey.from_public_bytes(base64.b64decode(keyring['signing_public'], validate=True)).verify(
                base64.b64decode(signature['signature'], validate=True), digest)
            if authenticated:
                progress('Verifying restored identity and content...')
                result = verified if verified is not None else verify(stage)
                verify_restored(stage, result['signing_public'], cancel=cancel)
            db.close()
        check_cancel(cancel)
        publishing = True  # The callback may commit durable recovery records.
        before_publish(stage, destination, proof)
        os.rename(stage, destination)
    except BaseException:
        if not publishing and stage_identity is not None:
            try:
                from .residuals import discard_tree
                discard_tree(stage, stage_identity)
            except (OSError, VaultError): pass
        if stage.exists():
            progress('Import did not complete. Recovery files remain at ' + str(stage) + '.')
        raise
    return {'path': str(destination), 'authenticated': authenticated,
            'source_consistency': header.get('source_consistency', 'unconfirmed'), 'experimental': True}


def verify_restored(root, signing_public, *, cancel=lambda: False):
    proof_path = safe_path(root / '.import-proof.json')
    if not proof_path.exists():
        if (root / '.import-manifest.jsonl').exists() and not (root / '.verified-import-proof.json').exists():
            raise VaultError('Import proof missing. Re-import the original archive.')
        return
    with guarded_reader(proof_path) as source: raw = source.read(MAX_METADATA + 1)
    if len(raw) > MAX_METADATA: raise VaultError('Import proof exceeds size limit.')
    proof = unique_json(raw); hasher = hashlib.sha256(DOMAIN)
    with guarded_reader(root / '.import-manifest.jsonl') as source:
        first = True
        count = 0
        expected_paths = set()  # Current prototype limit; documented, bounded by MAX_ENTRIES.
        for raw in iter(lambda: source.readline(MAX_METADATA + 1), b''):
            check_cancel(cancel)
            if len(raw) > MAX_METADATA: raise VaultError('Recovery manifest record too large.')
            hasher.update(raw)
            if first: first = False; continue
            count += 1
            if count > MAX_ENTRIES: raise VaultError('Too many recovery manifest entries.')
            record = unique_json(raw); name, _ = entry_path(record['path']); expected_paths.add(name)
            path = safe_path(root / Path(name), must_exist=True)
            if record['kind'] == 'directory':
                if not path.is_dir(): raise VaultError('Restored directory missing.')
                continue
            digest = hashlib.sha256(); actual = 0
            with guarded_reader(path) as content:
                while chunk := content.read(CHUNK):
                    check_cancel(cancel); digest.update(chunk); actual += len(chunk)
            if actual != record['size'] or digest.hexdigest() != record['sha256']:
                raise VaultError('Restored data has changed.')
    if {name for name, _, _ in tree(root)} != expected_paths: raise VaultError('Restored file list has changed.')
    if base64.b64encode(hasher.digest()).decode() != proof['digest']: raise VaultError('Recovery manifest digest mismatch.')
    Ed25519PublicKey.from_public_bytes(base64.b64decode(signing_public, validate=True)).verify(
        base64.b64decode(proof['signature'], validate=True), hasher.digest())
