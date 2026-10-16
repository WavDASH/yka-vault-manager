"""Local records, identity pins and import provenance. Never stores credentials."""
import copy
import json
import os
from pathlib import Path
import time
import uuid
import win32api
from .windows import VaultError, VaultGuard, safe_path, private_directory, guarded_reader


def path_key(path):
    path = str(path)
    if len(path) == 2 and path[1] == ':': return path.lower() + '\\'
    path = os.path.abspath(path)
    try: path = win32api.GetLongPathName(path)
    except Exception: pass
    return os.path.normcase(path)


class Registry:
    def __init__(self, directory=None):
        self.directory = safe_path(directory or os.environ.get('YKA_STATE_DIR') or
            Path(os.environ['LOCALAPPDATA']) / 'YKA Vault Manager')
        self.directory.parent.mkdir(parents=True, exist_ok=True)
        if not self.directory.exists():
            try: private_directory(self.directory)
            except FileExistsError: pass
        self.locks = self.directory / 'leases'; self.locks.mkdir(exist_ok=True)
        safe_path(self.locks, must_exist=True)
        self.file = self.directory / 'registry.json'
        self.previous = self.directory / 'registry.previous.json'

    def _write(self, target, encoded):
        safe_path(target)
        staging = self.directory / ('.registry-' + uuid.uuid4().hex + '.partial')
        try:
            with staging.open('xb') as out:
                out.write(encoded); out.flush(); os.fsync(out.fileno())
            os.replace(staging, target)
        finally:
            staging.unlink(missing_ok=True)

    def transaction(self, operation, *, forget_previous=False):
        deadline = time.monotonic() + 5
        while True:
            try: guard = VaultGuard(self.directory); break
            except VaultError:
                if time.monotonic() > deadline: raise
                time.sleep(.05)
        with guard:
            data = {'schema': 1, 'records': [], 'origins': {}}
            raw = None
            if self.file.exists():
                with guarded_reader(self.file) as source:
                    raw = source.read(8 * 1024 * 1024 + 1)
                if len(raw) > 8 * 1024 * 1024: raise VaultError('Registry exceeds size limit.')
                try:
                    from .archive import unique_json
                    data = unique_json(raw)
                    if not isinstance(data, dict) or data.get('schema') != 1: raise ValueError()
                    if not isinstance(data.get('records'), list) or not isinstance(data.get('origins'), dict): raise ValueError()
                    if any(not isinstance(r, dict) or not all(k in r for k in ('id','path','uuid','signing_public')) for r in data['records']): raise ValueError()
                except (ValueError, TypeError, VaultError):
                    raise VaultError('The saved vault list is damaged or unsupported. It was not changed. Keep registry.json and registry.previous.json for recovery; do not delete pending import records.') from None
            result, changed = operation(data)
            if changed:
                encoded = json.dumps(data, ensure_ascii=False, indent=2).encode()
                if len(encoded) > 8 * 1024 * 1024: raise VaultError('Registry exceeds size limit. Existing records were kept.')
                # Recovery copy only, never auto-load stale identity/provenance pins.
                if raw is not None: self._write(self.previous, encoded if forget_previous else raw)
                self._write(self.file, encoded)
            return copy.deepcopy(result)

    def records(self): return self.transaction(lambda d: (d['records'], False))

    def save_size(self, record_id, value):
        from .vault_size import binding, cache
        def change(data):
            record = next((r for r in data['records'] if r['id'] == record_id), None)
            if record is None or not cache(dict(record, size_cache=value)) or value['binding'] != binding(record):
                return {'saved': False}, False
            if record.get('move_transaction') or record.get('restore_transaction') or record.get('delete_transaction'): return {'saved': False}, False
            previous = cache(record)
            if previous and previous['binding'] == value['binding'] and previous['measured_at'] > value['measured_at']:
                return {'saved': False}, False
            record['size_cache'] = {key:value[key] for key in ('binding','bytes','measured_at')}
            return {'saved': True}, True
        return self.transaction(change)

    def invalidate_sizes(self, record_ids=None):
        def change(data):
            changed = False
            for record in data['records']:
                if record_ids is None or record['id'] in record_ids:
                    record['size_revision'] = record.get('size_revision', 0) + 1; changed = True
            return None, changed
        return self.transaction(change)

    def get(self, record_id):
        for record in self.records():
            if record['id'] == record_id: return record
        raise VaultError('Vault record no longer exists. Refresh the list.')

    def by_path(self, root):
        return next((v for v in self.records() if path_key(v['path']) == path_key(root)), None)

    def origin(self, root):
        return self.transaction(lambda d: (d['origins'].get(path_key(root)), False))

    @staticmethod
    def _generation(data, identity, root=None, *, allow_older_import=False):
        value = identity.get('generation')
        highest = max((v.get('generation') or 0 for v in [*data['origins'].values(), *data.get('identity_history', [])]
            if (v.get('uuid'), v.get('signing_public')) == (identity['uuid'], identity['signing_public'])), default=0)
        if value is not None:
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise VaultError('Invalid vault authorization version.')
            origin = data['origins'].get(path_key(root), {}) if root is not None else {}
            # Explicit archive recovery approves one authenticated container at
            # one registered location, not arbitrary older states of this UUID.
            approved = (identity.get('keyring_sha256') and
                origin.get('approved_import_keyring') == identity['keyring_sha256'] and
                (origin.get('uuid'), origin.get('signing_public')) == (identity['uuid'], identity['signing_public']))
            if value < highest and not (allow_older_import or approved):
                raise VaultError('This folder has older unlock settings. To recover an older backup, use Import .yka and confirm its saved unlock methods, or use Restore Backup.')
        # Keep the high-water mark even for an approved historical snapshot.
        return max(highest, value or 0)

    def check_generation(self, identity, root=None):
        return self.transaction(lambda data: (self._generation(data, identity, root), False))

    def remember(self, root, identity, *, name=None, pending=False, proof_digest=None, authenticated=False, allow_older_import=False, replace_origin=None, auto_unmount=None):
        def change(data):
            from .move import within
            if any(v.get('delete_transaction') and (within(Path(root), Path(v['path'])) or within(Path(v['path']), Path(root))) for v in data['records']):
                raise VaultError('Finish deleting this vault before using its location.')
            previous = data['origins'].get(path_key(root), {})
            if replace_origin is not None:
                if previous != replace_origin or previous.get('pending') or pending or not authenticated:
                    raise VaultError('The saved folder identity changed. Review the folder again before adding it.')
                if any(path_key(v['path']) == path_key(root) for v in data['records']):
                    raise VaultError('This location is still listed. Remove its old list entry before adding a different vault.')
                if any(v.get('pending') and v.get('uuid') == identity['uuid'] for v in data['origins'].values()):
                    raise VaultError('This identity has a pending import. Restore from the original .yka archive.')
                # Retain the old identity's authorization floor without reserving its old path.
                history = data.setdefault('identity_history', [])
                old = {k: previous[k] for k in ('uuid', 'signing_public')}
                old['generation'] = previous.get('generation') or 0
                known = next((v for v in history if (v['uuid'], v['signing_public']) == (old['uuid'], old['signing_public'])), None)
                if known: known['generation'] = max(known['generation'], old['generation'])
                else: history.append(old)
            if allow_older_import and (not authenticated or not identity.get('keyring_sha256')):
                raise VaultError('Backup authentication is required before accepting its unlock methods.')
            generation = self._generation(data, identity, root, allow_older_import=allow_older_import)
            record = next((v for v in data['records'] if path_key(v['path']) == path_key(root)), None)
            if record:
                if (record['uuid'], record['signing_public']) != (identity['uuid'], identity['signing_public']):
                    raise VaultError('Vault identity changed. Registration stopped.')
            else:
                record = {'id': str(uuid.uuid4()), 'path': str(root), 'name': name or Path(root).name,
                    'uuid': identity['uuid'], 'signing_public': identity['signing_public'],
                    'mode': identity['mode'], 'mount_point': '', 'devices': {}, 'trusted': not pending or authenticated, 'auto_unmount': False}
                data['records'].append(record)
            if auto_unmount is not None:
                if type(auto_unmount) is not bool: raise VaultError('Invalid automatic unmount setting.')
                record['auto_unmount'] = auto_unmount
            if not pending or authenticated: record['trusted'] = True
            if name: record['name'] = name
            if replace_origin is not None: previous = {}
            data['origins'][path_key(root)] = dict(previous, uuid=identity['uuid'],
                signing_public=identity['signing_public'], generation=generation, pending=pending,
                proof_digest=proof_digest if pending else None)
            if allow_older_import:
                data['origins'][path_key(root)]['approved_import_keyring'] = identity['keyring_sha256']
            elif previous.get('approved_import_keyring') != identity.get('keyring_sha256'):
                data['origins'][path_key(root)].pop('approved_import_keyring', None)
            return record, True
        return self.transaction(change)

    def restore_journal(self, record_id, transaction):
        def change(data):
            record = next(v for v in data['records'] if v['id'] == record_id)
            if transaction is None: record.pop('restore_transaction', None)
            else:
                if record.get('restore_transaction'): raise VaultError('An interrupted restore needs recovery first.')
                record['restore_transaction'] = transaction
            return record, True
        return self.transaction(change)

    def restore_record(self, record_id, original_path, destination, verified):
        def change(data):
            record = next(v for v in data['records'] if v['id'] == record_id)
            if path_key(record['path']) != path_key(original_path) or (record['uuid'], record['signing_public']) != (verified['uuid'], verified['signing_public']):
                raise VaultError('The saved vault changed during restore. Its current folder was kept.')
            generation = self._generation(data, verified)
            record['path'] = str(destination); record['trusted'] = True
            record.pop('size_cache', None); record['size_revision'] = record.get('size_revision', 0) + 1
            record.pop('restore_previous_path', None)
            if record.get('restore_transaction'): record['restore_transaction']['committed'] = True
            record.pop('last_mount', None)
            data['origins'][path_key(destination)] = dict(uuid=verified['uuid'], signing_public=verified['signing_public'], generation=generation, pending=False, proof_digest=None)
            return record, True
        return self.transaction(change)

    def update(self, record_id, fields):
        if set(fields) - {'name', 'mount_point', 'mount_settings', 'devices', 'path', 'last_mount', 'auto_unmount'}: raise VaultError('Invalid preference.')
        if 'auto_unmount' in fields and type(fields['auto_unmount']) is not bool: raise VaultError('Invalid automatic unmount setting.')
        if 'mount_settings' in fields:
            from .mount_settings import validate_settings
            fields = dict(fields, mount_settings=validate_settings(fields['mount_settings']))
        def change(data):
            record = next(v for v in data['records'] if v['id'] == record_id)
            if record.get('move_transaction'): raise VaultError('Finish the interrupted move before changing this vault.')
            if record.get('delete_transaction'): raise VaultError('Finish deleting this vault before changing its record.')
            if 'path' in fields:
                record.pop('size_cache', None); record['size_revision'] = record.get('size_revision', 0) + 1
                if any(v['id'] != record_id and path_key(v['path']) == path_key(fields['path']) for v in data['records']):
                    raise VaultError('That folder is already registered.')
                origin = data['origins'].get(path_key(record['path']))
                if origin: data['origins'][path_key(fields['path'])] = copy.deepcopy(origin)
            record.update(fields); return record, True
        return self.transaction(change)

    def move_journal(self, record_id, transaction):
        def change(data):
            record = next(v for v in data['records'] if v['id'] == record_id)
            if transaction is None: record.pop('move_transaction', None)
            else:
                if record.get('restore_transaction'): raise VaultError('Finish the interrupted restore first.')
                record['move_transaction'] = copy.deepcopy(transaction)
            return record, True
        return self.transaction(change)

    def commit_move(self, record_id, transaction):
        def change(data):
            record = next(v for v in data['records'] if v['id'] == record_id)
            if record.get('move_transaction') != transaction or path_key(record['path']) != path_key(transaction['source']):
                raise VaultError('The saved vault changed during the move. The original files were kept.')
            destination = path_key(transaction['destination'])
            if any(v['id'] != record_id and path_key(v['path']) == destination for v in data['records']):
                raise VaultError('The destination is already registered.')
            previous = data['origins'].get(destination)
            if previous and previous.get('pending'): raise VaultError('The destination has an unfinished import.')
            if previous and (previous['uuid'], previous['signing_public']) != (record['uuid'], record['signing_public']):
                data.setdefault('identity_history', []).append({k: previous.get(k, 0) for k in ('uuid','signing_public','generation')})
            data['origins'][destination] = copy.deepcopy(data['origins'][path_key(record['path'])])
            record['path'] = transaction['destination']; record.pop('last_mount', None)
            record.pop('size_cache', None); record['size_revision'] = record.get('size_revision', 0) + 1
            record['move_transaction']['committed'] = True
            return record, True
        return self.transaction(change)

    def remove(self, record_id):
        def change(data):
            if any(v['id'] == record_id and v.get('delete_transaction') for v in data['records']):
                raise VaultError('Finish deleting this vault before removing its record.')
            if any(v['id'] == record_id and v.get('move_transaction') for v in data['records']):
                raise VaultError('Finish the interrupted move before removing this vault.')
            data['records'] = [v for v in data['records'] if v['id'] != record_id]
            # Keep provenance: removing a row cannot discard pending authentication.
            return {'removed': True, 'data_deleted': False}, True
        return self.transaction(change)

    def deletion_journal(self, expected, transaction):
        def change(data):
            from .move import within
            record = next(v for v in data['records'] if v['id'] == expected['id'])
            if any(record[k] != expected[k] for k in ('path','uuid','signing_public')):
                raise VaultError('The saved vault changed. Review its location before deleting it.')
            if record.get('last_mount') or record.get('move_transaction') or record.get('restore_transaction'):
                raise VaultError('Unmount this vault and finish any pending operations before deleting it.')
            if any(v['id'] != record['id'] and (within(Path(v['path']), Path(record['path'])) or within(Path(record['path']), Path(v['path']))) for v in data['records']):
                raise VaultError('Another saved vault uses this folder. Its files were not deleted.')
            record['delete_transaction'] = copy.deepcopy(transaction)
            record.pop('size_cache', None)
            return None, True
        self.transaction(change)

    def finish_deletion(self, expected, transaction):
        def change(data):
            record = next(v for v in data['records'] if v['id'] == expected['id'])
            if (any(record[k] != expected[k] for k in ('path','uuid','signing_public'))
                or record.get('delete_transaction') != transaction or transaction.get('phase') != 'finalizing'):
                raise VaultError('The saved deletion state changed. Refresh the list before retrying.')
            data['records'].remove(record)
            origin = data['origins'].get(path_key(record['path']))
            identity = (record['uuid'], record['signing_public'])
            if origin and (origin['uuid'], origin['signing_public']) == identity:
                data['origins'].pop(path_key(record['path']))
            # Preserve security floors and provenance belonging to other copies.
            if not any((v['uuid'],v['signing_public']) == identity for v in [*data['records'], *data['origins'].values()]):
                data['identity_history'] = [v for v in data.get('identity_history', []) if (v['uuid'],v['signing_public']) != identity]
            return None, True
        self.transaction(change, forget_previous=True)
