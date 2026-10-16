"""Public bootstrap validation only. Metadata decryption stays in Rust."""
import base64
import hashlib
import json
import struct
import uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .windows import VaultError, guarded_reader, safe_path

KEY_FILE = '.yka-key'
MAGIC = b'YKAK\x00\x02\r\n'
DOMAIN = b'YKA-KEYRING-CONTAINER-2\x00'
MAX_KEY = 4 * 1024 * 1024


def read_header(root):
    with guarded_reader(Path(root) / KEY_FILE) as stream: raw = stream.read(MAX_KEY + 1)
    return parse_header(raw)


def parse_header(raw):
    from .archive import unique_json
    try:
        if len(raw) > MAX_KEY or len(raw) < 12 or raw[:8] != MAGIC or struct.unpack('<I', raw[8:12])[0] != len(raw)-12:
            raise ValueError()
        signed = unique_json(raw[12:]); body = signed['body']
        fields = ('schema', 'uuid', 'mode', 'config_sha256', 'signing_public', 'channels', 'recovery', 'sealed')
        if set(signed) != {'body','signature'} or set(body) != set(fields) or body['schema'] != 2: raise ValueError()
        if body['mode'] not in ('lite','full') or str(uuid.UUID(body['uuid'])) != body['uuid']: raise ValueError()
        if len(body['config_sha256']) != 64 or len(bytes.fromhex(body['config_sha256'])) != 32: raise ValueError()
        if not isinstance(body['channels'], list) or len(body['channels']) > 32: raise ValueError()
        tags = set(); channels = []
        for item in body['channels']:
            if set(item) != {'key_tag','encrypted'} or len(item['key_tag']) != 64 or len(bytes.fromhex(item['key_tag'])) != 32 or item['key_tag'] in tags: raise ValueError()
            base64.b64decode(item['encrypted'], validate=True); tags.add(item['key_tag'])
            channels.append(dict(key_tag=item['key_tag'], encrypted=item['encrypted']))
        if body['recovery'] is not None: base64.b64decode(body['recovery'], validate=True)
        if not channels and body['recovery'] is None: raise ValueError()
        base64.b64decode(body['sealed'], validate=True)
        ordered = {k: (channels if k == 'channels' else body[k]) for k in fields}
        Ed25519PublicKey.from_public_bytes(base64.b64decode(body['signing_public'], validate=True)).verify(
            base64.b64decode(signed['signature'], validate=True), DOMAIN + json.dumps(ordered, ensure_ascii=False, separators=(',',':')).encode())
        return dict(uuid=body['uuid'], mode=body['mode'], signing_public=body['signing_public'],
            config_sha256=body['config_sha256'], key_tags=sorted(tags), key_count=len(channels), recovery=body['recovery'] is not None,
            keyring_sha256=hashlib.sha256(raw).hexdigest(), devices=[], generation=None)
    except Exception as error:
        raise VaultError('This vault key file is damaged or uses an unsupported format. Restore a trusted .yka backup.') from error


def selected_root(path):
    selected = safe_path(path, must_exist=True)
    if selected.name.casefold() != KEY_FILE or not selected.is_file():
        raise VaultError('Select the .yka-key file inside your encrypted vault folder.')
    root = selected.parent
    read_header(root)
    with guarded_reader(root / '.config.pb'): pass
    return root


def internal_file(name):
    """Local runtime/provenance and rollback files never travel as live data."""
    name = name.casefold()
    return (name in ('.manager.lock', '.mount-state.json', '.verified-import-proof.json', '.import-proof.json', '.import-manifest.jsonl')
        or name.startswith(('.mount-state-', '.yka-key-rollback-'))
        or (name.startswith('.yka-key') and name.endswith('.partial')))
