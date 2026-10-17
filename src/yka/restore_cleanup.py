"""Best-effort cleanup of owned restore artifacts, never a filename sweep."""
from pathlib import Path
import re
import tempfile
import time
import threading
from .tasks import owner_finished
from .windows import VaultError, VaultGuard, safe_path
from .registry import path_key
from .storage import read_header
from .archive import check_cancel
from .residuals import discard_tree


def remember(manager, record, original, stage, destination, stage_id, scratch):
    task = getattr(manager.task_context, 'task', None)
    if task is None: return  # Direct callers retain existing synchronous cleanup.
    with VaultGuard(scratch) as temporary:
        task['restore_stage'] = dict(root=str(original.root), root_id=list(original.root_identity),
            uuid=record['uuid'], signing_public=record['signing_public'], stage=str(stage),
            destination=str(destination), stage_id=stage_id,
            scratch=str(scratch), scratch_id=list(temporary.root_identity))
        manager.jobs.save(task)


def eligible(task):
    if task.get('action') != 'restore-backup' or not task.get('restore_stage'): return False
    return owner_finished(task)


def _overlap(a, b):
    a, b = path_key(a).rstrip('\\/'), path_key(b).rstrip('\\/')
    return a == b or a.startswith(b + '\\') or b.startswith(a + '\\')


def cleanup_task(manager, ident, *, cancel=lambda: False, task=None):
    check_cancel(cancel)
    task = task or manager.jobs.load(ident)
    if not eligible(task): return
    saved = task['restore_stage']
    record = manager.registry.get(task['record_id'])
    if record.get('restore_transaction') or record.get('move_transaction') or record.get('delete_transaction'): return
    root = safe_path(saved['root'])
    stage = safe_path(saved['stage']); destination = safe_path(saved['destination'])
    scratch = safe_path(saved['scratch'])
    # Do not infer ownership from a recognizable filename. Names, parents,
    # Registry binding AND the original Windows directory IDs must all agree.
    if (path_key(root) != path_key(record['path']) or
        (saved['uuid'], saved['signing_public']) != (record['uuid'], record['signing_public']) or
        stage.parent != root.parent or destination.parent != root.parent or
        not re.fullmatch(re.escape(root.name) + r'-restored-[0-9a-f]{12}', destination.name) or
        not re.fullmatch(re.escape('.' + destination.name) + r'\.[0-9a-f]{32}\.staging', stage.name) or
        path_key(scratch.parent) != path_key(tempfile.gettempdir()) or
        not re.fullmatch(r'yka-import-[a-z0-9_]{8}', scratch.name)):
        raise VaultError('Restore cleanup ownership could not be verified.')
    candidates = ((stage, saved['stage_id']), (destination, saved['stage_id']), (scratch, saved['scratch_id']))
    if any(_overlap(path, manager.registry.directory) for path, _ in candidates): return
    for other in manager.registry.records():
        protected = [other['path'], (other.get('last_mount') or {}).get('mount_point')]
        for path, _ in candidates:
            if any(_overlap(path, p) for p in protected if p): return
    if any(path.exists() for path, _ in candidates):
        with VaultGuard(root) as original:
            original.reserve(manager.registry.locks, 'identity:' + record['uuid'])
            manager._idle(root, cleanup=False)
            if list(original.root_identity) != saved['root_id']: return
            body = read_header(root)
            if (body['uuid'], body['signing_public']) != (saved['uuid'], saved['signing_public']): return
            for path, identity in candidates:
                check_cancel(cancel)
                discard_tree(path, identity, cancel=cancel)
    # Persist success last. A crash after deletion is harmless on the next pass.
    if any(path.exists() for path, _ in candidates): return
    manager.jobs.forget(task)


def sweep(manager, *, cancel=lambda: False):
    """One startup attempt. Forget attempted receipts even if files must remain.

    Registry transactions are separate recovery authority and must survive an
    incomplete rollback. They are not ordinary task history.
    """
    deadline = time.monotonic() + 1
    stop = lambda: cancel() or time.monotonic() >= deadline
    from .restore import recover
    for record in manager.registry.records():
        if stop(): return
        if not record.get('restore_transaction'): continue
        try:
            # Existing transaction recovery decides rollback versus committed
            # cleanup. Never discard either directory before this decision.
            tx = record['restore_transaction']
            if tx.get('committed'):
                body = read_header(Path(record['path']))
                if (body['uuid'], body['signing_public']) != (record['uuid'], record['signing_public']): continue
            recover(manager.registry, record, cancel=stop)
        except Exception: pass  # Leave durable recovery authority for a later retry.
    for path in manager.jobs.directory.glob('*.json'):
        if stop(): return
        try:
            task = manager.jobs.load(path.stem)
            if not owner_finished(task): continue
            # Consume the receipt before the final attempt. Even a process crash
            # during cleanup cannot turn this into an unlimited retry loop.
            if not manager.jobs.forget(task): continue
            if task.get('action') == 'export':
                from .export_cleanup import cleanup_task as cleanup_export
                cleanup_export(manager, path.stem, cancel=stop, task=task)
            else: cleanup_task(manager, path.stem, cancel=stop, task=task)
        except Exception: pass  # Busy, offline, or changed: never guess ownership.


class Maintenance:
    """One deferred startup pass; no timer or periodic filesystem scans."""
    def __init__(self, manager, executor, disconnected):
        self.manager = manager; self.executor = executor; self.disconnected = disconnected
        self.lock = threading.Lock(); self.stop = threading.Event()
        self.waiting = 0; self.scheduled = False; self.pending = True

    def enqueue(self):
        with self.lock:
            self.waiting += 1; self.stop.set()

    def finished(self):
        with self.lock: self.waiting -= 1
        self.schedule()

    def schedule(self):
        with self.lock:
            if (not self.pending or self.waiting or self.scheduled or self.disconnected.is_set() or
                self.manager.security_pending.is_set()): return
            self.scheduled = True
            self.executor.submit(self.run)

    def run(self):
        try:
            with self.lock:
                if self.waiting or self.disconnected.is_set() or self.manager.security_pending.is_set(): return
                self.stop.clear(); self.pending = False
            cancelled = lambda: self.stop.is_set() or self.disconnected.is_set() or self.manager.security_pending.is_set()
            from .mount_cleanup import reconcile
            reconcile(self.manager, cancel=cancelled)
            sweep(self.manager, cancel=cancelled)
        except Exception: pass
        finally:
            with self.lock:
                self.scheduled = False
