"""Advisory, secret-free checks. Execution must retain its own locked checks."""
import hashlib
from pathlib import Path
from . import archive
from .windows import VaultError, VaultGuard, guarded_reader, safe_path, output_identity, mount_device
from .registry import path_key


KEY_ACTIONS = ('add-device', 'remove-device', 'set-recovery', 'remove-recovery')


def keyring_restore(manager, args):
    from .storage import parse_header
    root = safe_path(args['root'], must_exist=True)
    if safe_path(root / '.yka-key').exists():
        raise VaultError('This vault already contains a Keyring. Restore is only available when it is missing; the existing Keyring will not be overwritten.')
    with guarded_reader(safe_path(args['backup'], must_exist=True)) as stream:
        raw = stream.read(archive.MAX_METADATA + 1)
    body = parse_header(raw)
    config = next((root / n for n in ('.config.pb', '.securefs.json') if (root / n).is_file()), None)
    if config is None: raise VaultError('SecureFS configuration missing.')
    with guarded_reader(config) as stream: configuration = stream.read(archive.MAX_METADATA + 1)
    if len(configuration) > archive.MAX_METADATA: raise VaultError('Configuration exceeds size limit.')
    if hashlib.sha256(configuration).hexdigest() != body['config_sha256']:
        raise VaultError('The SecureFS configuration does not match this vault key file. Restore an intact backup.')
    expected = manager._expected(root)
    if expected and (body['uuid'], body['signing_public']) != (expected['expected_uuid'], expected['expected_public']):
        raise VaultError('The current folder does not match its saved vault identity.')
    return raw, config.name, configuration


def key_change(args, body):
    action = args['action']
    if action == 'add-device' and body['key_count'] >= 32:
        raise VaultError('This vault already has the maximum number of authorized keys.')
    if action == 'set-recovery' and 'new_passphrase' in args and len(args['new_passphrase'] or '') < 8:
        raise VaultError('Password must contain at least 8 characters.')
    if action == 'remove-recovery':
        if not body['recovery']: raise VaultError('This vault does not have a password to remove.')
        if not body['key_count']: raise VaultError('Cannot remove the last unlock method.')
        if args.get('passphrase'): raise VaultError('Authenticate with a surviving YubiKey.')
    if action == 'remove-device':
        if not body['key_count']: raise VaultError('Device is not authorized.')
        if body['key_count'] == 1 and not body['recovery']: raise VaultError('Cannot remove the last unlock method.')
        target = (args.get('remove_serial'), args.get('remove_slot'))
        if target == (args.get('serial'), args.get('slot')) and all(target):
            raise VaultError('Authenticate with a surviving unlock method.')
        if body.get('metadata_available') and not any((d['serial'], d['slot']) == target for d in body['devices']):
            raise VaultError('Device is not authorized.')


def public_vault(manager, root, expected=None):
    body = manager._body(root)
    with guarded_reader(root / '.config.pb') as source:
        configuration = source.read(archive.MAX_METADATA + 1)
    if len(configuration) > archive.MAX_METADATA: raise VaultError('Configuration exceeds size limit.')
    digest = hashlib.sha256(configuration).hexdigest()
    if digest != body['config_sha256']:
        raise VaultError('The SecureFS configuration does not match this vault key file. Restore an intact backup.')
    expected = expected or manager._expected(root)
    if expected and (body['uuid'], body['signing_public']) != (
        expected.get('uuid', expected.get('expected_uuid')), expected.get('signing_public', expected.get('expected_public'))):
        raise VaultError('The current folder does not match its saved vault identity.')
    if body.get('metadata_available'): manager.registry.check_generation(body, root)
    return body


def new_folder(manager, value):
    root = safe_path(value)
    if root.exists(): raise VaultError('Vault folder already exists. Choose a new folder.')
    if not root.parent.is_dir(): raise VaultError('The destination parent folder does not exist.')
    if manager.registry.by_path(root): raise VaultError('This folder is reserved by a saved vault. Locate or remove that record first.')
    if (manager.registry.origin(root) or {}).get('pending'):
        raise VaultError('The destination has an unfinished import.')
    from .move import within
    for record in manager.registry.records():
        if within(root, Path(record['path'])):
            raise VaultError('Choose a destination outside other encrypted vault folders.')
        point = (record.get('last_mount') or {}).get('mount_point')
        if point and within(root, Path(point + '\\' if len(point) == 2 else point)):
            raise VaultError('Choose a destination outside mounted vaults.')
    return root


def export_target(root, value):
    replacement = value.get('replace_existing') if isinstance(value, dict) else None
    output = safe_path(value['path'] if isinstance(value, dict) else value)
    from .move import within
    if within(output, root): raise VaultError('Save the archive outside this vault.')
    if output.exists() and replacement is None: raise VaultError('Output already exists. Choose a new file.')
    if replacement is not None and output_identity(output) != replacement:
        raise VaultError('The destination file changed. Save again to confirm its replacement.')
    if not output.parent.is_dir(): raise VaultError('Output parent folder does not exist.')


def run(manager, args):
    from .native import NATIVE, BACKEND
    if not NATIVE.is_file() or not BACKEND.is_file(): raise VaultError('Components missing. Run scripts/build.ps1.')
    action = args['operation']
    if action == 'create':
        new_folder(manager, args['root'])
        if args.get('mode', 'lite') not in ('lite', 'full'): raise VaultError('Select Lite or Full.')
        return {}
    if action == 'import':
        target = new_folder(manager, args['destination'])
        with guarded_reader(safe_path(args['archive'], must_exist=True)) as source:
            _, body = archive.public_precheck(source, destination=target, cancel=manager.cancel.is_set)
        return {k: body[k] for k in ('key_tags', 'recovery')}
    if action == 'restore-keyring':
        root = safe_path(args['root'], must_exist=True)
        with VaultGuard(root):
            manager._idle(root, cleanup=False)
            keyring_restore(manager, args)
        return {}
    allowed = ('mount', 'export', 'test-unlock', 'relocate', 'move-vault', 'delete-vault', *KEY_ACTIONS)
    if action not in allowed: raise VaultError('Unsupported precheck operation.')
    record = manager.registry.get(args['record_id']) if args.get('record_id') else None
    root = safe_path(args['new_path'] if action == 'relocate' else (record['path'] if record else args['root']), must_exist=True)
    with manager.session_mutex:
        owned = manager.sessions.get(path_key(root))
        if owned and action == 'test-unlock' and (owned[1].process.poll() is not None or not owned[0].same_root()
            or mount_device(owned[2]) != getattr(owned[1], 'mount_device', None)):
            raise VaultError('The mount owner could not be verified. Unmount this vault before testing a key.')
        lease = owned[0].borrow() if owned and action == 'test-unlock' else None
    with lease or VaultGuard(root) as guard:
        if owned and action != 'test-unlock': raise VaultError('Unmount this vault before continuing.')
        if not owned and action != 'delete-vault': manager._idle(root, cleanup=False)
        body = public_vault(manager, root, record)
        if action not in ('relocate', 'delete-vault'):
            manager._check_provenance(root, args, body)
        if action in KEY_ACTIONS: key_change(dict(args, action=action), body)
        if action == 'mount':
            from .mount_settings import validate_settings, available_point
            config = validate_settings(args.get('mount_settings') or (record or {}).get('mount_settings') or
                dict(mount_point=args.get('mount_point', ''), volume_label=args.get('volume_label', '')))
            point = available_point(config['mount_point'], root)
            guard.reserve(manager.registry.locks, 'identity:' + body['uuid'])
            guard.reserve(manager.registry.locks, 'mount:' + path_key(point))
            for other in manager.registry.records():
                if other['uuid'] == body['uuid'] and other.get('last_mount'):
                    raise VaultError('Another copy of this vault has a recorded mount. Confirm unmount before continuing.')
        if action == 'relocate':
            if path_key(record['path']) in manager.sessions or record.get('last_mount'):
                raise VaultError('Unmount before locating this vault.')
            if (manager.registry.origin(record['path']) or {}).get('pending'):
                raise VaultError('Re-import the original archive before relocating a pending vault.')
            other = manager.registry.by_path(root)
            if other and other['id'] != record['id']: raise VaultError('This folder is already registered.')
        if action == 'move-vault':
            from .move import check_destination
            check_destination(manager, args)
            guard.reserve(manager.registry.locks, 'identity:' + body['uuid'])
            guard.reserve(manager.registry.locks, 'move:' + path_key(args['destination']))
        if action == 'delete-vault':
            from .deletion import precheck
            precheck(manager, args)
            guard.reserve(manager.registry.locks, 'identity:' + body['uuid'])
        if action == 'export' and args.get('output'): export_target(root, args['output'])
    result = {k: body[k] for k in ('key_tags', 'recovery')}
    if action == 'add-device':
        result['exclude_devices'] = [{k: d[k] for k in ('serial', 'slot')} for d in body['devices']]
    return result
