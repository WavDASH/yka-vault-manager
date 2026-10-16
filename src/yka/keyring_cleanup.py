"""Retire old encrypted Keyrings only after authenticating and committing the current one."""
import hashlib
import uuid
from .storage import KEY_FILE, MAX_KEY, parse_header
from .windows import VaultError, guarded_reader
from .move import deletable_reader, delete_handle

WARNING = ('Old keyring files could not be removed. Previous unlock methods may still work through them. '
           'Close programs using the vault folder and mount the vault again to retry cleanup.')


def cleanup(root, verified, guard):
    """Return True if cleanup remains pending; never turn a committed update into failure.

    The owner must have committed its Registry changes and hold the root lease.
    A successful Test Unlock intentionally does not call this mutating function.
    """
    pending = False
    try:
        candidates = []
        for path in root.glob('.yka-key*'):
            if path.name == '.yka-key.partial':
                candidates.append(path); continue
            if path.name.startswith('.yka-key-rollback-'):
                suffix = path.name.removeprefix('.yka-key-rollback-')
            elif path.name.startswith('.yka-key-') and path.name.endswith('.partial'):
                suffix = path.name.removeprefix('.yka-key-').removesuffix('.partial')
            else: continue
            try:
                identifier = uuid.UUID(suffix)
                allowed = (str(identifier), identifier.hex) if path.name.endswith('.partial') else (str(identifier),)
                if suffix not in allowed: continue
            except ValueError: continue
            candidates.append(path)
        if not candidates: return False
        if guard.root != root or not guard.same_root(): raise VaultError('Vault folder changed.')
        # Keep both authenticated metadata files read-locked throughout cleanup.
        with guarded_reader(root / KEY_FILE) as key, guarded_reader(root / '.config.pb') as config:
            raw = key.read(MAX_KEY + 1); current = parse_header(raw)
            identity = (verified['uuid'], verified['signing_public'])
            if ((current['uuid'], current['signing_public']) != identity
                or current['keyring_sha256'] != verified['keyring_sha256']
                or hashlib.sha256(config.read(MAX_KEY + 1)).hexdigest() != current['config_sha256']):
                raise VaultError('Authenticated metadata changed.')
            for path in candidates:
                try:
                    # Validate and delete the very same opened file. Never follow
                    # a junction, symlink, hardlink, or a replaced path.
                    with deletable_reader(path) as (stream, handle):
                        old = parse_header(stream.read(MAX_KEY + 1))
                        if (old['uuid'], old['signing_public']) != identity:
                            raise VaultError('Unrelated rollback file.')
                        delete_handle(handle)
                except FileNotFoundError: continue
                except Exception: pending = True
    except Exception: pending = True
    return pending
