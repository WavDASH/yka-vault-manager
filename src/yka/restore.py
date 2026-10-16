"""Recoverable same-path publication. Never overwrite an unidentified directory."""
import shutil
from pathlib import Path
from .windows import VaultGuard, VaultError, safe_path, pinned_parents, mount_state
from .native import BACKEND


def identity(guard): return list(guard.root_identity)


def cleanup(registry, record):
    tx=record.get('restore_transaction')
    if not tx or not tx.get('committed'): return
    root=safe_path(tx['root']); old=safe_path(tx['old'])
    if old.parent != root.parent or not old.name.startswith('.yka-replaced-'):
        raise VaultError('Restore cleanup location is invalid.')
    with VaultGuard(root) as active, pinned_parents(old):
        if identity(active)!=tx['new_id']: raise VaultError('The restored folder changed. Old data was not deleted.')
        # Authenticated identity and committed restore are durable in Registry.
        # Manifest goes first so interrupted cleanup never leaves it without
        # the completed-verification marker.
        if (root / '.import-proof.json').exists():
            raise VaultError('Restore authentication is still pending. Recovery files were kept.')
        for name in ('.import-manifest.jsonl', '.verified-import-proof.json'):
            safe_path(root / name).unlink(missing_ok=True)
        import uuid
        for backup in root.glob('.yka-key-rollback-*'):
            try: uuid.UUID(backup.name.removeprefix('.yka-key-rollback-'))
            except ValueError: continue
            safe_path(backup, must_exist=True).unlink()
        if old.exists():
            # Pin the exact root throughout recursive deletion. Windows rmtree
            # unlinks junctions rather than traversing their targets.
            with VaultGuard(old) as guard:
                if identity(guard)!=tx['old_id']: raise VaultError('Restore cleanup folder identity changed.')
                resolved=old.resolve(strict=True)
                if resolved.parent != root.parent.resolve(strict=True) or not resolved.name.startswith('.yka-replaced-'):
                    raise VaultError('Restore cleanup path changed.')
                guard.handle.Close();guard.handle=None
                try: shutil.rmtree(old)
                except PermissionError:
                    # Only the pinned, now-empty root may fail its final removal.
                    if list(old.iterdir()): raise
            if old.exists(): old.rmdir()
        registry.restore_journal(record['id'],None)


def commit(registry, record, current, incoming, verified):
    root=current.root; staged=incoming.root
    old=root.with_name('.yka-replaced-'+__import__('uuid').uuid4().hex)
    current.prepare_rename();incoming.prepare_rename()
    tx=dict(root=str(root), staged=str(staged), old=str(old), old_id=identity(current), new_id=identity(incoming), committed=False)
    registry.restore_journal(record['id'],tx)
    moved=False;installed=False
    try:
        current.rename_to(old);moved=True
        incoming.rename_to(root);installed=True
        restored=registry.restore_record(record['id'],root,root,verified)
        return restored
    except BaseException:
        persisted = registry.get(record['id'])
        if (persisted.get('restore_transaction') or {}).get('committed'): return persisted
        # If rollback itself fails, keep the journal and both copies for restart.
        if installed: incoming.rename_to(staged)
        if moved: current.rename_to(root)
        registry.restore_journal(record['id'],None)
        raise


def recover(registry, record):
    tx=record.get('restore_transaction')
    if not tx:return
    root=safe_path(tx['root']);old=safe_path(tx['old']);staged=safe_path(tx['staged'])
    if root != Path(record['path']) or old.parent!=root.parent or staged.parent!=root.parent or not old.name.startswith('.yka-replaced-'):
        raise VaultError('Interrupted restore paths could not be verified.')
    point=(record.get('last_mount') or {}).get('mount_point')
    if point and mount_state(BACKEND,point): raise VaultError('Unmount before recovering an interrupted restore.')
    # Claim the same UUID lease as mounts and restores.
    with VaultGuard(registry.locks) as lease:
        lease.reserve(registry.locks,'identity:'+record['uuid'])
        if tx.get('committed'):
            cleanup(registry,record);return
        with pinned_parents(root):
            if old.exists():
                with VaultGuard(old) as original:
                    if identity(original)!=tx['old_id']:raise VaultError('Original restore folder identity changed.')
                    if root.exists():
                        with VaultGuard(root) as active:
                            if identity(active)!=tx['new_id']:raise VaultError('Restore target is occupied by another folder.')
                            active.prepare_rename();active.rename_to(staged)
                    original.prepare_rename();original.rename_to(root)
            else:
                with VaultGuard(root) as original:
                    if identity(original)!=tx['old_id']:raise VaultError('Original restore folder is missing.')
            registry.restore_journal(record['id'],None)
