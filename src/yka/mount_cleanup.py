"""One startup pass for stopped sessions; never unmount or scan vault data."""
from pathlib import Path
import psutil
from . import archive
from .native import BACKEND
from .registry import path_key
from .windows import VaultGuard, guarded_reader, mount_state, safe_path


def reconcile(manager, *, cancel=lambda: False):
    for original in manager.registry.records():
        if cancel(): return
        try:
            root = safe_path(original['path'], must_exist=True)
            with manager._session_operation(root), VaultGuard(root) as guard:
                record = manager.registry.get(original['id'])
                if (not record.get('trusted') or path_key(record['path']) != path_key(root)
                    or any(record.get(k) for k in ('move_transaction', 'restore_transaction', 'delete_transaction'))):
                    continue
                with manager.session_mutex:
                    if path_key(root) in manager.sessions: continue
                marker = safe_path(root / '.mount-state.json')
                marker_raw = None
                states = [record['last_mount']] if record.get('last_mount') else []
                if marker.exists():
                    with guarded_reader(marker) as stream: marker_raw = stream.read(65537)
                    if len(marker_raw) > 65536: continue
                    states.append(archive.unique_json(marker_raw))
                if not states: continue
                body = manager._body(root)
                identity = (record['uuid'], record['signing_public'])
                if (body['uuid'], body['signing_public']) != identity: continue
                # Both independent receipts must agree with the trusted identity.
                # PID reuse is harmless only when process creation time differs.
                points = set()
                for state in states:
                    if (state['uuid'], state['signing_public']) != identity: break
                    pid, started = state['supervisor_pid'], state['supervisor_started']
                    if type(pid) is not int or pid <= 0 or type(started) not in (int, float) or started <= 0: break
                    try:
                        if psutil.Process(pid).create_time() == started: break
                    except psutil.NoSuchProcess: pass
                    point = state['mount_point']
                    if (not isinstance(point, str) or not point or not
                        (Path(point).is_absolute() or (len(point) == 2 and point[0].isascii() and point[0].isalpha() and point[1] == ':'))): break
                    points.add(point)
                else:
                    # Reserve every recorded mount point against other YKA instances.
                    guard.reserve(manager.registry.locks, 'identity:' + record['uuid'])
                    for point in sorted(points): guard.reserve(manager.registry.locks, 'mount:' + path_key(point))
                    if cancel() or any(mount_state(BACKEND, p) for p in points): continue
                    if not guard.same_root(): continue
                    current = manager.registry.get(record['id'])
                    if current != record: continue
                    if marker_raw is not None:
                        with guarded_reader(marker) as stream:
                            if stream.read(65537) != marker_raw: continue
                    elif marker.exists(): continue
                    # Reuse ordinary cleanup, including restoring a removed empty
                    # mount folder. It checks both receipts again before deleting.
                    manager._restore_mount_folder(root)
                    manager._idle(root)
                    manager.registry.update(record['id'], {'last_mount': None})
        except Exception:
            # Offline, busy, changed, malformed or unknown: retain explicit recovery.
            continue
