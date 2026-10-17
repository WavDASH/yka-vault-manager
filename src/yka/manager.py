import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import uuid
import hashlib
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
from . import archive, piv
from .native import BACKEND, NativeSession, native_call
from .windows import VaultError, VaultGuard, private_directory, safe_path, mount_state, mount_device, guarded_reader, pin_directory, pinned_parents
from .registry import Registry, path_key
from .windows import available_drives, output_identity, publish_output


class Manager:
    def __init__(self, progress=lambda _: None, destination=None, *, defer_restore_recovery=False):
        self.progress = progress
        self.destination = destination
        self.sessions = {}
        self.metadata_cache = {}
        self.cancel = threading.Event()
        self.security_pending = threading.Event()
        self.session_locked = False
        self.security_scope = None
        self.resume_requested = False
        self.security_mutex = threading.RLock()
        self.registry = Registry()
        self.session_mutex = threading.RLock()
        self.session_operations = {}
        from .tasks import Tasks
        self.jobs = Tasks(self.registry.directory)
        self.task_context = threading.local()
        from .restore import recover
        for record in self.registry.records():
            if record.get('move_transaction') and not record['move_transaction'].get('committed'):
                try:
                    from .move import recover as recover_move
                    recover_move(self.registry, record)
                except Exception: pass  # Keep both locations recorded for explicit recovery.
            if record.get('restore_transaction') and not defer_restore_recovery:
                try: recover(self.registry, record)
                except Exception: pass  # Keep the journal; status remains a warning.

    def _body(self, root):
        from .storage import read_header
        body = read_header(root)
        cached = self.metadata_cache.get(path_key(root), {})
        if cached.get('keyring_sha256') == body['keyring_sha256']:
            body.update(devices=cached.get('authorized_keys', []), generation=cached.get('generation'), metadata_available=True)
        else: body['metadata_available'] = False
        return body

    def _expected(self, root):
        record = self.registry.origin(root) or self.registry.by_path(root)
        return dict(expected_uuid=record['uuid'], expected_public=record['signing_public']) if record else {}

    def _verified(self, root, args, guard):
        from .precheck import public_vault
        body = public_vault(self, root)
        self._check_provenance(root, args, body)
        result = native_call(dict(action='verify', root=str(root), **self._auth(args), **self._expected(root)),
            guard=guard, pin=args.get('pin'), progress=self.progress, cancel=self.cancel.is_set)
        return self._check_verified(root, args, result)

    def _check_verified(self, root, args, result):
        self.registry.check_generation(result, root)
        self._check_provenance(root, args, result)
        return result

    def _check_provenance(self, root, args, result):
        origin = self.registry.origin(root)
        if origin is None and not (root / '.import-proof.json').exists():
            pending_copy = self.registry.transaction(lambda data: (any(
                v.get('pending') and v.get('uuid') == result['uuid'] for v in data['origins'].values()), False))
            if pending_copy: raise VaultError('This identity has a pending import. Restore from the original .yka archive.')
            if not args.get('trust_existing'):
                raise VaultError('Unregistered folder has no archive proof. Add Existing Vault and review its provenance first.')
        if origin and origin.get('pending'):
            proof = safe_path(root / '.import-proof.json', must_exist=True)
            with guarded_reader(proof) as source: raw = source.read(archive.MAX_METADATA + 1)
            if origin.get('proof_digest') != hashlib.sha256(raw).hexdigest():
                raise VaultError('Import proof changed. Re-import the original archive.')
        archive.verify_restored(root, result['signing_public'], cancel=self.cancel.is_set)
        return result

    def _accept(self, root, verification, name=None, *, replace_origin=None, auto_unmount=None):
        # Commit the external trust record first. If interrupted afterwards, the
        # remaining proof is still verified on the next operation; it is never lost.
        record = self.registry.remember(root, verification, name=name, replace_origin=replace_origin, authenticated=replace_origin is not None, auto_unmount=auto_unmount)
        self.metadata_cache[path_key(root)] = dict(verification)
        proof = root / '.import-proof.json'
        if proof.exists(): os.replace(proof, root / '.verified-import-proof.json')
        if (root / '.verified-import-proof.json').exists():
            # Registry is committed and the original archive proof has been
            # authenticated. Retire the manifest before its completion marker.
            try:
                from .move import deletable_reader, delete_handle
                from .storage import MAX_KEY, parse_header
                with guarded_reader(root / '.yka-key') as source:
                    header = parse_header(source.read(MAX_KEY + 1))
                    if any(header[key] != verification[key] for key in ('uuid', 'signing_public', 'keyring_sha256')):
                        raise VaultError('The verified keyring changed before cleanup.')
                    for name in ('.import-manifest.jsonl', '.verified-import-proof.json'):
                        path = root / name
                        if path.exists():
                            with deletable_reader(path) as (_, handle): delete_handle(handle)
            except (OSError, VaultError):
                self.progress('The vault was verified, but its temporary verification files could not be removed. They will be checked again next time.')
        return record

    def _auth(self, args, *, enroll=False):
        if args.get('serial') and args.get('slot'):
            return {'device': self._selected_device(args['serial'], args['slot'], enroll=enroll)}
        if args.get('passphrase'):
            return {'passphrase': args['passphrase']}
        raise VaultError('Select a YubiKey or enter a password.')

    def _idle(self, root, *, cleanup=True):
        for saved in self.registry.records():
            move = saved.get('move_transaction')
            if move and path_key(root) in (path_key(move['source']), path_key(move['destination'])):
                raise VaultError('Finish the interrupted move before using this vault.')
        local = self.registry.by_path(root)
        if local and local.get('delete_transaction'): raise VaultError('Finish deleting this vault before using it.')
        if local and local.get('restore_transaction'): raise VaultError('An interrupted restore needs recovery. Restart YKA before using this vault.')
        if local and local.get('last_mount'):
            if mount_state(BACKEND, local['last_mount']['mount_point']):
                raise VaultError('Recorded mount remains active or ownership is unknown.')
        state = safe_path(root / '.mount-state.json')
        if state.exists():
            with guarded_reader(state) as source: record = archive.unique_json(source.read(65536))
            if mount_state(BACKEND, record['mount_point']):
                raise VaultError('Vault is mounted. Unmount before export or Keyring changes.')
            if cleanup: state.unlink()

    def _write_state(self, root, state):
        target = safe_path(root / '.mount-state.json')
        partial = root / ('.mount-state-' + uuid.uuid4().hex + '.partial')
        from .residuals import temporary_output
        with temporary_output(partial) as output:
            output.write(archive.canonical(state)); output.flush(); os.fsync(output.fileno()); output.close()
            os.replace(partial, target)

    def _restore_mount_folder(self, root):
        record = self.registry.by_path(root) or {}
        saved = record.get('last_mount') or {}
        if saved.get('restore_mount_folder'):
            point = saved['mount_point']
            if mount_state(BACKEND, point): raise VaultError('Mount remains active. Its folder was not changed.')
            with pinned_parents(Path(point)):
                safe_path(point).mkdir(exist_ok=True)

    def _selected_device(self, serial, slot, *, enroll=False):
        from .readonly import call
        return call(dict(action='selected', serial=serial, slot=slot, enroll=enroll), cancel=self.cancel.is_set)

    def inspect(self, args):
        from .readonly import inspect
        return inspect(self.cancel.is_set)

    def create(self, args):
        if self.security_pending.is_set(): raise VaultError('Security event pending. Creation and mounting are blocked.')
        if type(args.get('auto_unmount', False)) is not bool: raise VaultError('Invalid automatic unmount setting.')
        if args.get('passphrase') and len(args['passphrase']) < 8:
            raise VaultError('Password must contain at least 8 characters.')
        from .precheck import new_folder
        root = new_folder(self, args['root'])
        if args.get('mode', 'lite') not in ('lite', 'full'): raise VaultError('Select Lite or Full.')
        auth = {}
        if args.get('serial') and args.get('slot'):
            auth['device'] = self._selected_device(args['serial'], args['slot'], enroll=True)
        if args.get('passphrase'): auth['passphrase'] = args['passphrase']
        if not auth: raise VaultError('Add a YubiKey or a password.')
        private_directory(root)
        created_identity = None
        try:
            with VaultGuard(root) as guard:
                created_identity = list(guard.root_identity)
                result = native_call(dict(action='create', root=str(root), mode=args.get('mode', 'lite'), **auth),
                    guard=guard, pin=args.get('pin'), progress=self.progress, cancel=self.cancel.is_set)
                # Recovery verification is an actual decrypt + config/identity check, not a flag selected in UI.
                if auth.get('passphrase'):
                    self.progress('The vault files are ready. Testing password access…')
                    verified = native_call(dict(action='verify', root=str(root), passphrase=auth['passphrase']), guard=guard,
                        progress=self.progress, cancel=self.cancel.is_set)
                if auth.get('device'):
                    self.progress('The vault files are ready. Testing YubiKey unlock access; follow the next PIN or touch prompt.')
                    verified = native_call(dict(action='verify', root=str(root), device=auth['device']), guard=guard,
                        pin=args.get('pin'), progress=self.progress, cancel=self.cancel.is_set)
        except BaseException:
            if created_identity is not None:
                try:
                    from .residuals import discard_empty_vault
                    discard_empty_vault(root, created_identity)
                except (OSError, VaultError): pass
            raise
        record = self._accept(root, verified, name=args.get('name'), auto_unmount=args.get('auto_unmount', False))
        return dict(result, path=str(root), record=record, experimental=True)

    @contextmanager
    def _session_operation(self, root):
        """Serialize one vault's lifecycle without holding up unrelated mounts."""
        key = path_key(root)
        with self.session_mutex:
            entry = self.session_operations.setdefault(key, [threading.RLock(), 0])
            entry[1] += 1
        try:
            with entry[0]: yield
        finally:
            with self.session_mutex:
                entry[1] -= 1
                if not entry[1]: del self.session_operations[key]

    def mount(self, args):
        with self._session_operation(args['root']): return self._mount(args)

    def _mount(self, args):
        if self.security_pending.is_set(): raise VaultError('Security event pending. Mounting is blocked.')
        root = safe_path(args['root'], must_exist=True)
        root = Path(path_key(root))
        from .mount_settings import validate_settings, available_point
        saved = self.registry.by_path(root) or {}
        settings = validate_settings(args.get('mount_settings') or saved.get('mount_settings') or
            dict(mount_point=args.get('mount_point', ''), volume_label=args.get('volume_label', '')))
        point = available_point(args.get('mount_point') or settings['mount_point'], root, self.registry)
        settings['mount_point'] = point
        guard = VaultGuard(root)
        session = None
        mount_launched = False
        try:
            self._idle(root)
            if len(point) != 2:
                # Keep the selected location's parent chain stable while WinFsp
                # replaces an empty directory with its mount junction.
                guard.pins.extend(pin_directory(parent) for parent in reversed(Path(point).parents))
            from .precheck import public_vault
            identity = public_vault(self, root)
            self._check_provenance(root, args, identity)
            for saved in self.registry.records():
                if saved['uuid'] == identity['uuid'] and saved.get('last_mount'):
                    if mount_state(BACKEND, saved['last_mount']['mount_point']):
                        raise VaultError('Another copy of this vault identity may still be mounted.')
            try:
                guard.reserve(self.registry.locks, 'identity:' + identity['uuid'])
                guard.reserve(self.registry.locks, 'mount:' + path_key(point))
            except Exception: raise VaultError('Vault identity or mount point is already in use.') from None
            session = NativeSession(dict(action='mount', prepare=True, root=str(root), mount_point=point, volume_label=settings['volume_label'],
                **self._auth(args), **self._expected(root)), guard, args.get('pin'), self.progress)
            verification = session.receive(cancel=self.cancel.is_set)
            if verification.get('event') != 'verified': raise VaultError('Vault authentication was not confirmed.')
            self._check_verified(root, args, verification)
            for saved in self.registry.records():
                if saved['uuid'] == verification['uuid'] and saved.get('last_mount'):
                    if mount_state(BACKEND, saved['last_mount']['mount_point']):
                        raise VaultError('Another copy of this vault identity may still be mounted.')
            if self.security_pending.is_set(): raise VaultError('Security event received. Mount cancelled.')
            available_point(point, root, self.registry)
            instance = uuid.uuid4().hex
            state = dict(mount_point=point, state='starting', instance=instance, uuid=verification['uuid'], signing_public=verification['signing_public'],
                supervisor_pid=session.process.pid, supervisor_started=session.started_at,
                restore_mount_folder=len(point) != 2 and Path(point).is_dir())
            safe_path(root / '.mount-state.json')
            self._write_state(root, state)
            record = self.registry.by_path(root) or self.registry.remember(root, verification)
            self.registry.update(record['id'], {'last_mount': state})
            self.progress('Authentication succeeded. Mounting the vault with SecureFS…')
            if self.security_pending.is_set() or self.cancel.is_set(): raise VaultError('Mount cancelled.')
            if state['restore_mount_folder']:
                from .mount_settings import prepare_empty_folder
                available_point(point, root)
                prepare_empty_folder(point)
            session.release_mount_job()
            mount_launched = True
            session.send({'action': 'continue'})
            result = session.receive(timeout=75, cancel=lambda: self.security_pending.is_set() or self.cancel.is_set(),
                timeout_message='The mount did not become ready in time. Check its status before trying again.')
            if result['event'] != 'mounted': raise VaultError('Mount was not confirmed.')
            session.mount_device = result['mount_device']
            state.update(state='mounted', supervisor_pid=session.process.pid, mount_device=session.mount_device)
            self._write_state(root, state)
            self.registry.update(record['id'], {'last_mount': state})
            # A failed backend mount must leave the import proof pending for retry.
            # Persist trust before retiring the proof; its manifest stays available.
            record = self._accept(root, verification)
            self.registry.update(record['id'], {'mount_point': point, 'mount_settings': settings, 'name': args.get('name') or record['name']})
            with self.session_mutex: self.sessions[str(root)] = (guard, session, point)
            if self.security_pending.is_set():
                self.unmount({'root': str(root)})
                raise VaultError('Security event received. Mount closed.')
            from .keyring_cleanup import cleanup
            pending = cleanup(root, verification, guard)
            return dict(result, mount_point=point, path=str(root), keyring_cleanup_pending=pending)
        except BaseException:
            if session:
                try: self.progress('Stopping the mount attempt and checking for remaining mounts…')
                except Exception: pass  # Losing the UI pipe must never skip cleanup.
                session.close()
                if not mount_launched:
                    session.close_job()
                    if session.process.poll() is None: session.process.terminate()
                confirmed = False
                try:
                    session.process.wait(timeout=15)
                    confirmed = not mount_state(BACKEND, point)
                except Exception: pass
                if confirmed:
                    session.reap_output()
                    # Keep a recoverable lease until both cleanup writes finish.
                    # A disk/registry error must not leave an unreachable guard.
                    with self.session_mutex: self.sessions[str(root)] = (guard, session, point)
                    self._restore_mount_folder(root)
                    (root / '.mount-state.json').unlink(missing_ok=True)
                    saved = self.registry.by_path(root)
                    if saved: self.registry.update(saved['id'], {'last_mount': None})
                    with self.session_mutex: self.sessions.pop(str(root), None)
                    guard.close()
                else:
                    with self.session_mutex: self.sessions[str(root)] = (guard, session, point)
            else: guard.close()
            raise

    def unmount(self, args):
        with self._session_operation(args['root']): return self._unmount(args)

    def recover_unmount(self, args):
        """Explicit recovery only with a pinned identity and exact NT device match."""
        import psutil
        if args.get('confirm') not in ('unmount-known-orphan', 'unmount-selected-location'): raise VaultError('Confirm mount recovery first.')
        root = safe_path(args['root'], must_exist=True); key = path_key(root)
        record = self.registry.by_path(root)
        if not record or not record.get('trusted'): raise VaultError('The vault has no trusted local identity. Inspect the mount manually.')
        body = self._body(root)
        if (body['uuid'], body['signing_public']) != (record['uuid'], record['signing_public']): raise VaultError('Vault identity changed. Recovery stopped.')
        with self._session_operation(root):
            with self.session_mutex: local = self.sessions.get(key)
            saved = record.get('last_mount')
            if not saved: return self._unmount(args)
            point = saved['mount_point']
            if not mount_state(BACKEND, point): return self._unmount(args)
            if local and local[1].process.poll() is None and not local[1].process.stdin.closed:
                return self._unmount(args)
            supervisor = None
            if psutil.pid_exists(saved.get('supervisor_pid', 0)):
                from .native import NATIVE
                try:
                    candidate = psutil.Process(saved['supervisor_pid'])
                    if (candidate.create_time() == saved.get('supervisor_started')
                        and path_key(candidate.exe()) == path_key(NATIVE)):
                        supervisor = candidate
                    else: raise VaultError('YKA could not confirm which vault owns this mount. No changes were made.')
                except psutil.NoSuchProcess: pass
            def unmount_location():
                if mount_state(BACKEND, point):
                    expected = saved.get('mount_device')
                    if not expected:
                        if args.get('confirm') != 'unmount-selected-location' or not args.get('expected_mount_device'):
                            raise VaultError('This mount has no saved device identity. Refresh, then use Recover Mount to review and confirm the exact location.')
                        expected = args['expected_mount_device']
                    if mount_device(point) != expected: raise VaultError('Mount point ownership changed. The other filesystem was not unmounted.')
                    result = subprocess.run([str(BACKEND), 'unmount', point], stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
                    if result.returncode != 0 or mount_state(BACKEND, point): raise VaultError("Recovery unmount was not confirmed. Close open files and retry.")
            if supervisor is not None:
                # A disconnected supervisor retains its lease until its child exits.
                # The explicit recovery request can stop only the saved NT device.
                # Pin the vault identity while doing so; acquire its lease only after exit.
                if not saved.get('mount_device') and not (args.get('confirm') == 'unmount-selected-location' and args.get('expected_mount_device')):
                    raise VaultError('YKA could not confirm which vault owns this mount. No changes were made.')
                with pinned_parents(root), guarded_reader(root / '.yka-key'):
                    current = self._body(root)
                    if (current['uuid'], current['signing_public']) != (record['uuid'], record['signing_public']):
                        raise VaultError('The vault identity does not match.')
                    unmount_location()
                    try: supervisor.wait(timeout=15)
                    except psutil.TimeoutExpired:
                        raise VaultError('The vault is unmounted, but its previous session still needs cleanup.') from None
            lease = nullcontext(local[0]) if local else None
            if lease is None:
                try: lease = VaultGuard(root)
                except VaultError:
                    # An older detached SecureFS child can retain an inherited
                    # lock after its supervisor dies. Only the explicit location
                    # confirmation can close it without acquiring that lock.
                    # No vault/registry writes are allowed until it is released.
                    if args.get('confirm') != 'unmount-selected-location' or not args.get('expected_mount_device'):
                        raise
                    if mount_device(point) != args['expected_mount_device']:
                        raise VaultError('Mount point ownership changed. The other filesystem was not unmounted.')
                    unmount_location()
                    lease = VaultGuard(root)
            with lease:
                current = self._body(root)
                if (current['uuid'], current['signing_public']) != (record['uuid'], record['signing_public']):
                    raise VaultError('Vault identity changed. Recovery stopped.')
                unmount_location()
                self._restore_mount_folder(root)
                safe_path(root / '.mount-state.json').unlink(missing_ok=True)
                self.registry.update(record['id'], {'last_mount': None})
                if local:
                    local[1].close(); local[1].reap_output()
                    with self.session_mutex:
                        local[0].close(); del self.sessions[key]
                return dict(path=str(root), state='confirmed-unmounted', mounted=False)

    def _unmount(self, args):
        key = path_key(args['root'])
        root = Path(key)
        with self.session_mutex: owned = self.sessions.get(key)
        if owned is None:
            root = safe_path(root, must_exist=True)
            with VaultGuard(root):
                self._idle(root)
                self._restore_mount_folder(root)
                saved = self.registry.by_path(root)
                if saved: self.registry.update(saved['id'], {'last_mount': None})
            with self.session_mutex: remaining = len(self.sessions)
            return {'path': key, 'mounted': False, 'remaining_managed': remaining, 'state': 'confirmed-unmounted'}
        guard, session, point = owned
        live = mount_state(BACKEND, point)
        if not live or session.process.stdin.closed:
            session.close()
            try: session.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                raise VaultError('SecureFS is still stopping. Close programs using the mounted folder, then select Recover Mount again. Files may remain accessible.') from None
            live = mount_state(BACKEND, point)
        if live and getattr(session, 'mount_device', None) != mount_device(point):
            raise VaultError('Mount point ownership changed. Automatic unmount stopped.')
        if session.process.poll() is not None:
            if mount_state(BACKEND, point):
                raise VaultError('Supervisor lost. Mount ownership unknown; use SecureFS to inspect and unmount.')
            self._restore_mount_folder(root)
            if guard.same_root(): safe_path(root / '.mount-state.json').unlink(missing_ok=True)
            saved = self.registry.by_path(root)
            if saved: self.registry.update(saved['id'], {'last_mount': None})
            session.reap_output()
            with self.session_mutex:
                guard.close(); del self.sessions[key]
            return {'path': key, 'mounted': False, 'state': 'confirmed-unmounted'}
        try:
            session.send({'action': 'unmount'})
            result = session.receive(timeout=35)
        except (OSError, VaultError):
            session.close()
            try: session.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                raise VaultError('The mount supervisor is still stopping. Close files using the mount, then select Recover Mount. Unmount has not been confirmed.') from None
            if mount_state(BACKEND, point):
                raise VaultError('The mount supervisor disconnected and files may still be accessible. Select Recover Mount to check and unmount the remaining filesystem.') from None
            result = {'event': 'unmounted'}
        if result.get('event') != 'unmounted' or mount_state(BACKEND, point):
            raise VaultError('Unmount failed. Plaintext may still be accessible.')
        session.close()
        try: session.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            raise VaultError('The filesystem is unmounted, but its supervisor is still stopping. Select Clean Up after it finishes.') from None
        self._restore_mount_folder(root)
        if guard.same_root(): safe_path(root / '.mount-state.json').unlink(missing_ok=True)
        saved = self.registry.by_path(root)
        if saved: self.registry.update(saved['id'], {'last_mount': None})
        session.reap_output()
        with self.session_mutex:
            guard.close(); del self.sessions[key]; remaining = len(self.sessions)
        return {'path': key, 'mounted': False, 'remaining_managed': remaining, 'state': 'confirmed-unmounted'}

    def status(self, args):
        statuses = []
        observations = {}
        def probe(point):
            key = path_key(point)
            if key not in observations:
                try: observations[key] = mount_state(BACKEND, point)
                except Exception as error: observations[key] = error
            result = observations[key]
            if isinstance(result, Exception): raise result
            return result
        with self.session_mutex: sessions = list(self.sessions.items())
        for root, (_, session, point) in sessions:
            try: live = probe(point)
            except Exception: live = None
            if session.process.poll() is not None and live:
                state = 'mounted-supervisor-lost'
            else: state = 'unknown' if live is None else 'mounted' if live else 'mount-stopping' if session.process.poll() is None else 'unmounted-awaiting-cleanup'
            if live:
                try:
                    if getattr(session, 'mount_device', None) != mount_device(point): state = 'unknown-mount-owner'
                except Exception: state = 'unknown-mount-owner'
            statuses.append({'path': root, 'mount_point': point, 'mounted': live, 'state': state})
        return {'volumes': statuses, 'records': self.list_vaults({}, statuses, probe=probe)['records'], 'experimental': True,
                'security_pending': self.security_pending.is_set()}

    @contextmanager
    def _prepared(self, request, args, guard):
        from .precheck import public_vault
        body = public_vault(self, Path(request['root']))
        self._check_provenance(Path(request['root']), args, body)
        session = NativeSession(dict(request, prepare=True), guard, args.get('pin'), self.progress)
        try:
            verified = session.receive(cancel=self.cancel.is_set)
            if verified.get('event') != 'verified': raise VaultError('Vault authentication was not confirmed.')
            self._check_verified(Path(request['root']), args, verified)
            yield session, verified
        finally:
            session.finish_crypto()

    def export(self, args):
        root = safe_path(args['root'], must_exist=True)
        if path_key(root) in self.sessions: raise VaultError('Please unmount this vault before exporting it.')
        self.progress('Checking the vault before export…')
        with VaultGuard(root) as guard, guarded_reader(root / '.yka-key'):
            self._idle(root)
            output = args.get('output')
            if not output and self.destination: output = self.destination()
            if not output: raise VaultError('Export was cancelled. No archive was created.')
            from .precheck import export_target
            export_target(root, output)
            replace_existing = None
            if isinstance(output, dict):
                replace_existing = output.get('replace_existing'); output = output['path']
            self.note_output(output)
            from .exporting import ExportProgress, measure_export
            report = ExportProgress(self.progress)
            plan = measure_export(root, safe_path(output), self.cancel.is_set, report)
            request = dict(action='sign', root=str(root), **self._auth(args), **self._expected(root))
            with self._prepared(request, args, guard) as (session, verified):
                self._accept(root, verified)
                archive.check_cancel(self.cancel.is_set)
                def sign(digest):
                    session.send({'action': 'continue', 'message': base64.b64encode(digest).decode()})
                    return session.receive(cancel=self.cancel.is_set)
                from .export_cleanup import remember, retain
                def own_temporary(partial, target, stream, scratch):
                    remember(self, guard, verified, partial, target, stream, scratch)
                with pinned_parents(Path(output)):
                    return archive.export_archive(root, output, sign,
                        progress=self.progress, cancel=self.cancel.is_set, replace_existing=replace_existing,
                        on_temporary=own_temporary, on_retain=lambda: retain(self), plan=plan, report=report)

    def import_(self, args):
        from .exporting import ExportProgress
        report = ExportProgress(self.progress, restoring=True)
        from .precheck import new_folder
        new_folder(self, args['destination'])
        verified_info = {}
        def verify(metadata):
            result = native_call(dict(action='archive-verify', **metadata, **self._auth(args)),
                pin=args.get('pin'), progress=self.progress, cancel=self.cancel.is_set)
            if args.get('accept_backup_authorization') is not True: self.registry.check_generation(result)
            verified_info.update(result); return result
        def before_publish(stage, destination, proof):
            body = verified_info
            self.registry.remember(destination, body, name=args.get('name'), pending=True,
                proof_digest=hashlib.sha256(archive.canonical(proof)).hexdigest(), authenticated=True,
                allow_older_import=args.get('accept_backup_authorization') is True)
        result = archive.import_archive(args['archive'], args['destination'], verify,
            authenticated=True, authenticate_first=True, cancel=self.cancel.is_set, progress=self.progress, before_publish=before_publish, on_residual=self.note_residual, report=report)
        with VaultGuard(Path(result['path'])):
            result['record'] = self._accept(Path(result['path']), verified_info, name=args.get('name'))
        report.report('Restore complete', force=True, complete=True)
        return result

    def check_restore_backup(self, args):
        record = self.registry.get(args['record_id'])
        if not record.get('trusted'): raise VaultError('Authenticate this vault before restoring a backup.')
        root = safe_path(record['path'], must_exist=True)
        with VaultGuard(root) as guard:
            self._idle(root, cleanup=False)
            current = self._body(root)
            if (current['uuid'], current['signing_public']) != (record['uuid'], record['signing_public']):
                raise VaultError('The current folder does not match its saved vault identity.')
            guard.reserve(self.registry.locks, 'identity:' + record['uuid'])
            with guarded_reader(safe_path(args['archive'], must_exist=True)) as stream:
                _, body = archive.public_precheck(stream, destination=root, expected=record, cancel=self.cancel.is_set)
                archive.check_cancel(self.cancel.is_set)
        return {k: body[k] for k in ('key_tags', 'recovery')}

    def restore_backup(self, args):
        from .exporting import ExportProgress
        report = ExportProgress(self.progress, restoring=True)
        if args.get('confirmed') is not True: raise VaultError('Confirm Restore Backup before continuing.')
        record = self.registry.get(args['record_id'])
        if not record.get('trusted'): raise VaultError('Authenticate this vault before restoring a backup.')
        root = safe_path(record['path'], must_exist=True)
        destination = root.with_name(root.name + '-restored-' + uuid.uuid4().hex[:12])
        session = None; verified = {}
        with VaultGuard(root) as guard, pinned_parents(destination):
            self._idle(root)
            current = self._body(root)
            if (current['uuid'], current['signing_public']) != (record['uuid'], record['signing_public']):
                raise VaultError('The current folder does not match its saved vault identity.')
            guard.reserve(self.registry.locks, 'identity:' + record['uuid'])
            floor = self.registry.transaction(lambda data: (self.registry._generation(data, dict(record, generation=None)), False))
            def authenticate(metadata):
                nonlocal session
                # Repeat on the handle held through extraction: a GUI precheck
                # cannot authorize a file later replaced at the selected path.
                archive.check_restore_identity(metadata, record)
                session = NativeSession(dict(action='archive-restore', **metadata,
                    restore_generation=floor, expected_uuid=record['uuid'], expected_public=record['signing_public'], **self._auth(args)),
                    None, args.get('pin'), self.progress)
                result = session.receive(cancel=self.cancel.is_set)
                if result.get('event') != 'verified': raise VaultError('Backup authentication was not confirmed.')
                verified.update(result); return result
            def prepare_commit(stage, target, proof):
                # Import has authenticated the original signed manifest before this
                # explicit restore creates a fresh signed authorization revision.
                with VaultGuard(stage):
                    archive.check_cancel(self.cancel.is_set)
                    session.send({'action':'continue', 'root':str(stage)})
                    result = session.receive(cancel=self.cancel.is_set)
                    if result.get('event') != 'result': raise VaultError('Restore authorization was not committed.')
                    session.close()
                    if session.process.wait(timeout=15) != 0: raise VaultError('Restore authorization did not finish successfully.')
                    session.close_job()
                    verified.clear(); verified.update(result)
                    os.replace(stage / '.import-proof.json', stage / '.verified-import-proof.json')
            incoming_identity = None
            def own_stage(stage, target, stage_id, scratch):
                from .restore_cleanup import remember
                remember(self, record, guard, stage, target, stage_id, scratch)
            try:
                archive.import_archive(args['archive'], destination, authenticate, authenticated=True,
                    cancel=self.cancel.is_set, progress=self.progress, before_publish=prepare_commit, on_residual=self.note_residual, authenticate_first=True, report=report, on_stage=own_stage)
                with VaultGuard(destination) as incoming:
                    incoming_identity = list(incoming.root_identity)
                    archive.check_cancel(self.cancel.is_set)
                    self._idle(root)
                    if not guard.same_root(): raise VaultError('The current vault folder changed during restore.')
                    from .storage import read_header
                    if read_header(destination)['keyring_sha256'] != verified['keyring_sha256']:
                        raise VaultError('The restored authorization file changed before commit.')
                    from .restore import commit
                    restored = commit(self.registry, record, guard, incoming, verified)
                    self.metadata_cache[path_key(root)] = dict(verified)
                # Cleanup runs after the old and new directory pins are released.
                outcome = dict(record=restored, path=str(root), generation=verified['generation'])
            except BaseException:
                # After a confirmed rollback, discard the exact incoming copy
                # before forgetting its journal. Otherwise preserve recovery.
                tx = self.registry.get(record['id']).get('restore_transaction')
                rolled_back = bool(tx and not tx.get('committed') and guard.root == root
                    and list(guard.root_identity) == tx['old_id'] and guard.same_root()
                    and str(destination) == tx['staged'] and not Path(tx['old']).exists())
                if incoming_identity is not None and (not tx or rolled_back):
                    try:
                        from .residuals import discard_tree
                        discard_tree(destination, incoming_identity)
                        if rolled_back: self.registry.restore_journal(record['id'], None)
                    except (OSError, VaultError):
                        self.progress('The restore stopped. Its temporary folder could not be removed: ' + str(destination))
                raise
            finally:
                if session:
                    session.finish_crypto()

        from .restore import cleanup
        try:
            cleanup(self.registry, restored)
            outcome['record'] = self.registry.get(record['id'])
        except Exception:
            outcome['cleanup_pending'] = True
        report.report('Restore complete', force=True, complete=True)
        return outcome

    def restore_keyring(self, args):
        root = safe_path(args['root'], must_exist=True)
        with VaultGuard(root) as guard:
            self._idle(root)
            from .precheck import keyring_restore
            raw, config_name, configuration = keyring_restore(self, args)
            target = safe_path(root / '.yka-key')
            with tempfile.TemporaryDirectory(prefix='yka-keyring-') as scratch:
                probe = Path(scratch)
                (probe / config_name).write_bytes(configuration)
                (probe / '.yka-key').write_bytes(raw)
                result = native_call(dict(action='verify', root=str(probe), **self._auth(args), **self._expected(root)),
                    pin=args.get('pin'), progress=self.progress, cancel=self.cancel.is_set)
            self.registry.check_generation(result, root)
            target.parent.mkdir(exist_ok=True)
            guard.pins.append(pin_directory(target.parent))
            partial = target.with_name('.yka-key-' + uuid.uuid4().hex + '.partial')
            from .residuals import temporary_output
            with temporary_output(partial) as output:
                output.write(raw); output.flush(); os.fsync(output.fileno()); output.close()
                os.rename(partial, target)
        return dict(result, restored=True, path=str(root))

    def list_vaults(self, args, statuses=None, *, probe=None):
        probe = probe or (lambda point: mount_state(BACKEND, point))
        runtime = {path_key(v['path']): v for v in (statuses or [])}
        records = self.registry.records()
        for record in records:
            if record.get('delete_transaction'):
                record['state'] = 'Deletion incomplete'
                record['authorized_keys'] = []; record['unlock_methods'] = 'Unavailable'
                try:
                    body = self._body(Path(record['path']))
                    if (body['uuid'], body['signing_public']) == (record['uuid'], record['signing_public']):
                        record.update(recovery=body['recovery'], key_tags=body['key_tags'])
                except Exception: pass
                continue
            if record.get('move_transaction'):
                record['state'] = 'Move cleanup pending' if record['move_transaction'].get('committed') else 'Move interrupted'
                continue
            if record.get('restore_transaction'):
                record['state'] = 'Restore cleanup pending' if record['restore_transaction'].get('committed') else 'Restore interrupted'
                continue
            root = Path(record['path']); record['state'] = 'Unknown'; record['authorized_keys'] = []
            record['unlock_methods'] = 'Unavailable'
            if not root.exists():
                current = runtime.get(path_key(root))
                local = record.get('last_mount')
                live = None
                if local:
                    try: live = probe(local['mount_point'])
                    except Exception: live = True
                record['state'] = 'Unknown / source offline' if current or live else 'Offline'
                if current: record['mount_point'] = current['mount_point']
                elif live: record['mount_point'] = local['mount_point']
                continue
            identity_checked = False
            try:
                safe_path(root, must_exist=True)
                body = self._body(root)
                if (body['uuid'], body['signing_public']) != (record['uuid'], record['signing_public']):
                    record['state'] = 'Identity changed'; continue
                identity_checked = True
                record['authorized_keys'] = [{k: d[k] for k in ('serial', 'slot', 'public_key')} for d in body['devices']]
                record['recovery'] = bool(body['recovery'])
                record['generation'] = body['generation']
                record['key_tags'] = body['key_tags']
                record['metadata_available'] = body['metadata_available']
                record['unlock_methods'] = ' · '.join(filter(None, [f"{body['key_count']} YubiKey" if body['key_count'] else '',
                    'Password' if body['recovery'] else '']))
                state = runtime.get(path_key(root))
                if state:
                    record.update(state=state['state'], mount_point=state['mount_point'])
                else:
                    with VaultGuard(root):
                        statefile = safe_path(root / '.mount-state.json')
                        if statefile.exists():
                            with guarded_reader(statefile) as source: saved = archive.unique_json(source.read(65536))
                            record['mount_point'] = saved['mount_point']
                            record['state'] = 'Unknown / orphan mount' if probe(saved['mount_point']) else 'unmounted-awaiting-cleanup'
                        elif record.get('last_mount'):
                            local = record['last_mount']; record['mount_point'] = local['mount_point']
                            record['state'] = 'Unknown / orphan mount' if probe(local['mount_point']) else 'unmounted-awaiting-cleanup'
                        else: record['state'] = 'Unmounted'
                if record['state'] in ('Unknown / orphan mount', 'unknown-mount-owner'):
                    try: record['observed_mount_device'] = mount_device(record['mount_point'])
                    except Exception: pass
                if not record['trusted'] and record['state'] == 'Unmounted': record['state'] = 'Verification pending'
            except Exception:
                record['state'] = 'Unknown / busy'
                # Observing a location does not claim ownership. Explicit recovery
                # still checks the supervisor, device and trusted folder identity.
                saved = record.get('last_mount')
                if identity_checked and saved and record.get('trusted'):
                    try:
                        if mount_state(BACKEND, saved['mount_point']):
                            record.update(state='Unknown / orphan mount', mount_point=saved['mount_point'], lease_unavailable=True,
                                observed_mount_device=mount_device(saved['mount_point']))
                    except Exception: pass
        return {'records': records}

    def registration_info(self, args):
        """Read-only UI preflight; registration still authenticates and rechecks everything."""
        from .storage import selected_root
        root = selected_root(args['key_file']) if args.get('key_file') else safe_path(args['root'], must_exist=True)
        with VaultGuard(root):
            self._idle(root, cleanup=False)
            with guarded_reader(root / '.config.pb'): pass
            body = self._body(root)
            from .precheck import public_vault
            public_vault(self, root, body)
            origin = self.registry.origin(root)
            changed = bool(origin and (origin['uuid'], origin['signing_public']) != (body['uuid'], body['signing_public']))
            if changed and origin.get('pending'):
                raise VaultError('This location has an unfinished import. Re-import the original .yka archive.')
            if changed and self.registry.by_path(root):
                raise VaultError('This location is still listed as another vault. Remove its old list entry before adding this vault.')
            proof = safe_path(root / '.import-proof.json')
            if origin and origin.get('pending'):
                if not proof.exists(): raise VaultError('The import proof is missing. Re-import the original .yka archive.')
                with guarded_reader(proof) as source: raw = source.read(archive.MAX_METADATA + 1)
                if origin.get('proof_digest') != hashlib.sha256(raw).hexdigest():
                    raise VaultError('Import proof changed. Re-import the original archive.')
            requires_trust = changed or (origin is None and not proof.exists())
            if requires_trust and self.registry.transaction(lambda data: (any(
                    v.get('pending') and v.get('uuid') == body['uuid'] for v in data['origins'].values()), False)):
                raise VaultError('This identity has a pending import. Restore from the original .yka archive.')
            archive.verify_restored(root, body['signing_public'], cancel=self.cancel.is_set)
            return {'requires_trust': requires_trust, 'root': str(root),
                'key_tags': body['key_tags'], 'recovery': body['recovery'],
                'identity_change': {'previous_origin': origin, 'keyring_sha256': body['keyring_sha256']} if changed else None}

    def register(self, args):
        root = safe_path(args['root'], must_exist=True)
        with VaultGuard(root) as guard, guarded_reader(root / '.yka-key'):
            self._idle(root)
            body = self._body(root); origin = self.registry.origin(root)
            changed = bool(origin and (origin['uuid'], origin['signing_public']) != (body['uuid'], body['signing_public']))
            if changed:
                if origin.get('pending'):
                    raise VaultError('This location has an unfinished import. Re-import the original .yka archive.')
                if self.registry.by_path(root):
                    raise VaultError('This location is still listed. Remove its old list entry before adding a different vault.')
                expected = {'previous_origin': origin, 'keyring_sha256': body['keyring_sha256']}
                if not args.get('trust_existing') or args.get('identity_change') != expected:
                    raise VaultError('The folder identity changed. Review and confirm adding it as a different vault.')
                if self.registry.transaction(lambda data: (any(v.get('pending') and v.get('uuid') == body['uuid'] for v in data['origins'].values()), False)):
                    raise VaultError('This identity has a pending import. Restore from the original .yka archive.')
                archive.verify_restored(root, body['signing_public'], cancel=self.cancel.is_set)
                verified = native_call(dict(action='verify', root=str(root), **self._auth(args),
                    expected_uuid=body['uuid'], expected_public=body['signing_public']), guard=guard,
                    pin=args.get('pin'), progress=self.progress, cancel=self.cancel.is_set)
                self.registry.check_generation(verified, root)
                archive.verify_restored(root, verified['signing_public'], cancel=self.cancel.is_set)
                if verified['keyring_sha256'] != body['keyring_sha256'] or self._body(root)['keyring_sha256'] != body['keyring_sha256']:
                    raise VaultError('The vault key file changed. Review the folder again before adding it.')
                record = self._accept(root, verified, args.get('name'), replace_origin=origin)
            else:
                if args.get('identity_change'):
                    raise VaultError('The folder identity changed again. Review the folder before adding it.')
                verified = self._verified(root, args, guard)
                record = self._accept(root, verified, args.get('name'))
            from .keyring_cleanup import cleanup
            pending = cleanup(root, verified, guard)
        return {'record': record, 'keyring_cleanup_pending': pending}

    def preferences(self, args):
        record = self.registry.get(args['record_id'])
        fields = {k: args[k] for k in ('name', 'mount_point', 'mount_settings', 'auto_unmount') if k in args}
        return {'record': self.registry.update(record['id'], fields)}

    def device_label(self, args):
        record = self.registry.get(args['record_id'])
        body = self._body(Path(record['path']))
        if not any(d['public_key'] == args['public_key'] for d in body['devices']): raise VaultError('Device is not authorized.')
        labels = record.get('devices', {}); label = labels.get(args['public_key'], {})
        label['name'] = args['name'].strip() or 'YubiKey'; labels[args['public_key']] = label
        return {'record': self.registry.update(record['id'], {'devices': labels})}

    def relocate(self, args):
        record = self.registry.get(args['record_id'])
        if path_key(record['path']) in self.sessions: raise VaultError('Unmount before locating this vault.')
        root = safe_path(args['new_path'], must_exist=True)
        with VaultGuard(root) as guard:
            self._idle(root)
            origin = self.registry.origin(record['path'])
            if origin and origin.get('pending'): raise VaultError('Re-import the original archive before relocating a pending vault.')
            verified = native_call(dict(action='verify', root=str(root), **self._auth(args),
                expected_uuid=record['uuid'], expected_public=record['signing_public']), guard=guard,
                pin=args.get('pin'), progress=self.progress, cancel=self.cancel.is_set)
            self.registry.check_generation(verified, record['path'])
            archive.verify_restored(root, verified['signing_public'], cancel=self.cancel.is_set)
            self.metadata_cache[path_key(root)] = dict(verified)
        return {'record': self.registry.update(record['id'], {'path': str(root)})}

    def remove_record(self, args):
        record = self.registry.get(args['record_id'])
        if record.get('last_mount') and mount_state(BACKEND, record['last_mount']['mount_point']):
            raise VaultError('A recorded mount remains. Confirm unmount before removing the record.')
        with self.session_mutex: owned = self.sessions.get(path_key(record['path']))
        if owned:
            _, session, point = owned
            if session.process.poll() is None or mount_state(BACKEND, point):
                raise VaultError('The mount is still active or stopping. Use Recover Mount before removing this vault from the list.')
            self.unmount({'root': record['path']})
        if Path(record['path']).exists():
            with VaultGuard(record['path']): self._idle(Path(record['path']))
        return self.registry.remove(record['id'])

    def manage_keyring(self, args):
        root = safe_path(args['root'], must_exist=True)
        with VaultGuard(root) as guard:
            self._idle(root)
            body = self._body(root)
            self._key_change_precheck(args, body)
            if args['action'] == 'set-recovery' and body['recovery']:
                if not args.get('passphrase'): raise VaultError('Enter your current password to change it.')
                authorization = {'passphrase': args['passphrase']}
            else:
                authorization = self._auth(args)
            request = dict(action=args['action'], root=str(root), **authorization, **self._expected(root))
            request['restore_generation'] = self.registry.check_generation(dict(body, generation=None))
            if args['action'] == 'add-device':
                request['new_device'] = self._selected_device(args['new_serial'], args['new_slot'], enroll=True)
                tag = hashlib.sha256(base64.b64decode(request['new_device']['public_key'])).hexdigest()
                if tag in body['key_tags'] or any((d['serial'], d['slot']) == (request['new_device']['serial'], request['new_device']['slot']) for d in body['devices']):
                    raise VaultError('This key is already authorized.')
                request['new_pin'] = args.get('new_pin')
            if args['action'] == 'set-recovery': request['new_passphrase'] = args.get('new_passphrase')
            if args['action'] == 'remove-device':
                request.update(remove_serial=int(args['remove_serial']), remove_slot=int(args['remove_slot']))
            with self._prepared(request, args, guard) as (session, verified):
                self._accept(root, verified)
                session.send({'action': 'continue'})
                result = session.receive(cancel=self.cancel.is_set)
            self._accept(root, result)
            if args['action'] == 'add-device':
                record = self.registry.by_path(root); devices = record.get('devices', {})
                public = request['new_device']['public_key']
                devices[public] = {'name': args.get('device_name') or 'YubiKey', 'tested_generation': result['generation'], 'tested_at': datetime.now(timezone.utc).isoformat()}
                self.registry.update(record['id'], {'devices': devices})
            from .keyring_cleanup import cleanup
            result['keyring_cleanup_pending'] = cleanup(root, result, guard)
            return result

    def test_unlock(self, args):
        root = safe_path(args['root'], must_exist=True)
        # Only borrow our own live lease. A separate instance still needs the exclusive lock.
        # Keep an extra directory pin throughout the read-only test; safety unmount stays independent.
        with self.session_mutex:
            owned = self.sessions.get(path_key(root))
            if owned and (owned[1].process.poll() is not None or not owned[0].same_root()
                or mount_device(owned[2]) != getattr(owned[1], 'mount_device', None)):
                raise VaultError('The mount owner could not be verified. Unmount this vault before testing a key.')
            lease = owned[0].borrow() if owned else VaultGuard(root)
        with lease as guard, guarded_reader(root / '.yka-key'):
            if not owned: self._idle(root, cleanup=False)
            result = self._verified(root, args, guard)
            # Read-only testing never retires an import proof or changes vault files.
            record = self.registry.remember(root, result) if not (self.registry.origin(root) or {}).get('pending') else self.registry.by_path(root)
            self.metadata_cache[path_key(root)] = dict(result)
            if args.get('serial'):
                body = self._body(root)
                device = next(d for d in body['devices'] if d['serial'] == int(args['serial']) and d['slot'] == int(args['slot']))
                labels = record.get('devices', {}); label = labels.get(device['public_key'], {})
                label['tested_generation'] = body['generation']; label['tested_at'] = datetime.now(timezone.utc).isoformat(); labels[device['public_key']] = label
                self.registry.update(record['id'], {'devices': labels})
        return dict(result, independent_unlock_tested=True)

    @staticmethod
    def _key_change_precheck(args, body):
        from .precheck import key_change
        key_change(args, body)

    def check_operation(self, args):
        from .precheck import run
        return run(self, args)

    def security(self, args):
        with self.security_mutex:
            return self._security(args)

    def _security(self, args):
        self.security_pending.set(); self.cancel.set()
        event = args.get('event', 'lock')
        if event in ('session-lock', 'suspend-or-hibernate'):
            if self.security_scope != 'all': self.security_scope = 'automatic'
            self.resume_requested = False
        elif event not in ('session-unlock', 'resume', 'mount-recovered', 'task-finished'):
            self.security_scope = 'all'; self.resume_requested = False
        elif self.security_scope is None: self.security_scope = 'automatic'
        if args.get('event') in ('session-lock', 'session-disconnect'):
            self.session_locked = True
        failures = []; unmounted = []; kept = []
        try: records = self.registry.records()
        except Exception: records = []; failures.append('Saved mount records could not be checked.')
        policies = {path_key(r['path']): r.get('auto_unmount', True) for r in records}
        def keep(root): return self.security_scope == 'automatic' and policies.get(path_key(root), True) is False
        with self.session_mutex: roots = list(self.sessions)
        owned_paths = {path_key(root) for root in roots}
        def stop_one(root):
            if keep(root):
                try:
                    with self.session_mutex: current = self.sessions.get(root)
                    if current and mount_state(BACKEND, current[2]):
                        return 'kept', root
                except Exception:
                    return 'failed', root
            try: self.unmount({'root': root}); return 'unmounted', root
            except Exception: return 'failed', root
        # Independent supervisors can stop together. Each unmount retains its
        # vault's lifecycle lock, so pipe readers and cleanup never overlap.
        if roots:
            with ThreadPoolExecutor(max_workers=min(8, len(roots)), thread_name_prefix='YKA unmount') as pool:
                for outcome, root in pool.map(stop_one, roots):
                    {'kept': kept, 'failed': failures, 'unmounted': unmounted}[outcome].append(root)
        # A restarted worker does not own surviving mounts. Detect their records
        # without attempting to unmount a volume whose ownership is unconfirmed.
        try:
            for record in records:
                root = record['path']
                if path_key(root) in owned_paths: continue
                try:
                    saved = record.get('last_mount')
                    points = {saved['mount_point']} if saved else set()
                    marker = safe_path(Path(root) / '.mount-state.json')
                    if marker.exists():
                        with guarded_reader(marker) as source: raw = source.read(65537)
                        if len(raw) > 65536: raise VaultError('Mount record exceeds size limit.')
                        points.add(archive.unique_json(raw)['mount_point'])
                    if any(mount_state(BACKEND, point) for point in points):
                        (kept if keep(root) else failures).append(root)
                    elif points:
                        # Stale records must not block Exit after a restart. The
                        # directory lease also proves no old supervisor owns it.
                        self.unmount({'root': root})
                        unmounted.append(root)
                except Exception: failures.append(root)
        except Exception:
            failures.append('Saved mount records could not be checked.')
        return {'event': args.get('event', 'lock'), 'unmount_failed': failures, 'unmounted': unmounted, 'kept_mounted': kept,
                'state': 'plaintext-may-remain' if failures else 'mounted-by-preference' if kept else 'all-managed-mounts-confirmed-unmounted'}

    def resume(self, args):
        # No automatic remount or reuse of cached credentials after unlock/resume.
        with self.security_mutex:
            if args.get('event') == 'session-unlock': self.session_locked = False
            result = self._security(args)
            self.resume_requested = True
            if not result['unmount_failed'] and not self.session_locked and not args.get('defer_resume'):
                self.security_pending.clear(); self.cancel.clear(); self.security_scope = None; self.resume_requested = False
            return result

    def dispatch(self, request):
        action = request.get('action')
        methods = {'create': self.create, 'mount': self.mount, 'unmount': self.unmount,
            'delete-vault': self.delete_vault,
            'size-cache': lambda a: self.registry.save_size(a['record_id'], a['size']),
            'status': self.status, 'export': self.export, 'import': self.import_,
            'restore-keyring': self.restore_keyring, 'restore-backup': self.restore_backup,
            'check-restore-backup': self.check_restore_backup,
            'check-operation': self.check_operation,
            'inspect': self.inspect, 'security': self.security, 'resume': self.resume,
              'tasks': lambda a: {'tasks': [t for t in self.jobs.records() if t.get('action') != 'transfer']}, 'transfer': self.transfer, 'recover-unmount': self.recover_unmount,
              'list': lambda a: self.status(a), 'register': self.register, 'registration-info': self.registration_info, 'preferences': self.preferences,
            'relocate': self.relocate, 'move-vault': self.move_vault, 'recover-move': self.recover_move,
            'remove-record': self.remove_record, 'test-unlock': self.test_unlock, 'device-label': self.device_label,
            **{a: self.manage_keyring for a in ('add-device', 'remove-device', 'set-recovery', 'remove-recovery')}}
        if action not in methods: raise VaultError('Unsupported operation.')
        if request.get('record_id'):
            record = self.registry.get(request['record_id'])
            deleting = action == 'delete-vault' or (action == 'check-operation' and request.get('operation') == 'delete-vault')
            if record.get('delete_transaction') and action not in ('list', 'status', 'size-cache') and not deleting:
                raise VaultError('Finish deleting this vault before using it.')
            if action != 'relocate': request = dict(request, root=record['path'])
        if request.get('root') and action not in ('delete-vault', 'list', 'status', 'size-cache'):
            local = self.registry.by_path(request['root'])
            if local and local.get('delete_transaction') and not (action == 'check-operation' and request.get('operation') == 'delete-vault'):
                raise VaultError('Finish deleting this vault before using it.')
        if self.security_pending.is_set() and action not in ('security', 'resume', 'status', 'list', 'unmount', 'inspect', 'tasks', 'recover-unmount', 'remove-record', 'size-cache'):
            raise VaultError('Security event pending. Retry unmount before continuing.')
        from .tasks import TRACKED
        task = None
        if action in TRACKED:
            fields = {k: request[k] for k in ('root', 'record_id', 'destination', 'archive', 'backup') if k in request}
            output = request.get('output')
            if output: fields['output'] = output.get('path') if isinstance(output, dict) else output
            task = self.jobs.start(action, **fields)
        self.task_context.task = task
        result = None
        try:
            result = methods[action](request)
            if task:
                task['result'] = {k: result[k] for k in ('uuid', 'generation', 'path', 'state') if k in result}
                self.jobs.finish(task, 'Completed', 'The operation reported completion. Recheck mount status before accessing data.')
            return result
        except Exception as error:
            cancelled = self.cancel.is_set() or (isinstance(error, VaultError) and 'cancelled' in str(error).lower())
            from .errors import error_info
            detail, diagnostic = error_info(error)
            if task: self.jobs.finish(task, 'Cancelled' if cancelled else 'Failed', detail)
            if isinstance(error, VaultError): raise
            public = VaultError(detail); public.diagnostic = diagnostic
            raise public from None
        finally:
            self.task_context.task = None
            if task and (task.get('restore_stage') or task.get('export_stage')):
                # The operation's guards have closed. Attempt bounded cleanup
                # now; the next startup makes one final attempt and forgets it.
                import time
                if task.get('export_stage'): from .export_cleanup import cleanup_task
                else: from .restore_cleanup import cleanup_task
                deadline = time.monotonic() + 1
                try: cleanup_task(self, task['id'], cancel=lambda: time.monotonic() >= deadline or self.security_pending.is_set())
                except Exception: pass
            if action in ('create','register','import','mount','unmount','recover-unmount','restore-backup','restore-keyring',
                'relocate','move-vault','recover-move','transfer','add-device','remove-device','set-recovery','remove-recovery','security','resume'):
                try:
                    ids = None
                    if request.get('record_id'): ids = {request['record_id']}
                    elif isinstance(result, dict) and result.get('record'): ids = {result['record']['id']}
                    elif action == 'transfer' and request.get('selections'):
                        target = request['selections'][-1].get('record_id'); ids = {target} if target else set()
                    elif request.get('root'):
                        record = self.registry.by_path(request['root']); ids = {record['id']} if record else set()
                    self.registry.invalidate_sizes(ids)
                except Exception: pass  # Advisory cache must never change an operation's outcome.

    def transfer(self, args):
        from .transfer import Transfer
        return Transfer(self).run(args)

    def move_vault(self, args):
        from .move import run
        return run(self, args)

    def delete_vault(self, args):
        from .deletion import run
        return run(self, args)

    def recover_move(self, args):
        from .move import recover
        record = self.registry.get(args['record_id'])
        if record.get('move_transaction'):
            recover(self.registry, record, cancel=self.cancel.is_set, progress=self.progress)
        return {'message': 'Move recovery finished. The saved location is ready to use.'}

    def note_output(self, path):
        task = getattr(self.task_context, 'task', None)
        if task:
            task['output'] = str(path); self.jobs.save(task)

    def note_residual(self, path):
        task = getattr(self.task_context, 'task', None)
        if task:
            task.setdefault('residuals', []).append(str(path)); self.jobs.save(task)
