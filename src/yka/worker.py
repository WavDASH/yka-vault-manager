"""One serial manager per UI; no sockets, no persistent secret files or ordinary logs."""
import concurrent.futures
import json
import sys
import threading
import queue
import time
from .manager import Manager
from .windows import VaultError


def main():
    from .instance import Instance
    worker_instance = Instance('Worker')
    if not worker_instance.primary:
        worker_instance.close()
        raise SystemExit('A YKA worker is already running for this user. No second manager was started.')
    import win32event
    running_mutex = win32event.CreateMutex(None, False, "Local\\YKA.VaultManager.Running")
    sys.stdin.reconfigure(encoding='utf-8'); sys.stdout.reconfigure(encoding='utf-8')
    output_lock = threading.Lock()
    output_lost = threading.Event()
    def emit(value):
        with output_lock:
            if output_lost.is_set(): return
            try:
                sys.stdout.write(json.dumps(value, ensure_ascii=False) + '\n'); sys.stdout.flush()
            except (OSError, ValueError):
                # Progress reporting must not interrupt cleanup or leave a task
                # waiting forever for a dialog whose parent has disconnected.
                output_lost.set(); manager.security_pending.set(); manager.cancel.set()
                safety.submit(manager.security, {'event': 'controller-disconnected'})
    context = threading.local(); cancelled = set(); active = set(); task_lock = threading.Lock()
    destinations = {}
    def destination():
        task_id = context.id
        answer = queue.Queue(maxsize=1)
        with task_lock: destinations[task_id] = answer
        emit({'event': 'destination', 'id': task_id, 'record_id': context.record_id})
        deadline = time.monotonic() + 120
        try:
            while time.monotonic() < deadline:
                if manager.cancel.is_set(): raise VaultError('The operation was cancelled before a destination was selected.')
                try: return answer.get(timeout=0.1)
                except queue.Empty: pass
            raise VaultError('The save dialog timed out. Start the operation again to authenticate.')
        finally:
            with task_lock: destinations.pop(task_id, None)
    def progress(value):
        payload = {'event': 'progress', 'id': getattr(context, 'id', None), 'record_id': getattr(context, 'record_id', None)}
        if isinstance(value, dict) and value.get('kind') == 'transfer':
            payload.update(message=value['current'], transfer=value)
        else: payload['message'] = value
        emit(payload)
    manager = Manager(progress, destination)
    def task(request):
        request_id = request.get('id')
        context.id = request_id; context.record_id = request.get('record_id')
        control = request.get('action') in ('security', 'resume', 'status', 'list', 'tasks', 'size-cache')
        try:
            with task_lock:
                if request.get('action') == 'resume': request['defer_resume'] = bool(active)
                if output_lost.is_set() or request_id in cancelled: raise VaultError('Task cancelled.')
                if not control:
                    if not manager.security_pending.is_set(): manager.cancel.clear()
                    active.add(request_id)
            if not control and request.get('action') not in ('inspect', 'registration-info'):
                emit({'event': 'progress', 'id': request_id, 'record_id': request.get('record_id'), 'message': 'Preparing the operation…'})
            result = manager.dispatch(request)
            if control:
                with task_lock: result['tasks_pending'] = bool(active)
            emit({'id': request_id, 'record_id': request.get('record_id'), 'result': result})
        except VaultError as error:
            from .native import diagnostic_fields
            emit({'id': request_id, 'error': str(error), **diagnostic_fields(getattr(error, 'diagnostic', {}))})
        except Exception as error:
            if request.get('action') == 'restore-backup':
                # Report diagnostic codes, never raw exception text or credentials.
                code = getattr(error, 'winerror', None) or getattr(error, 'errno', None)
                detail = type(error).__name__ + (f', system error {code}' if isinstance(code, int) else '')
                emit({'id': request_id, 'error': f'Restore did not complete ({detail}). Check the vault status before retrying. Close programs using the vault folder and check the drive connection.'})
            else: emit({'id': request_id, 'error': 'Operation failed. Check vault status and components.'})
        finally:
            for secret in ('pin', 'passphrase', 'new_pin', 'new_passphrase'): request.pop(secret, None)
            with task_lock: active.discard(request_id); cancelled.discard(request_id)
            if not control and manager.security_pending.is_set():
                (manager.resume if manager.resume_requested else manager.security)({'event': 'task-finished'})
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, concurrent.futures.ThreadPoolExecutor(max_workers=1) as safety, concurrent.futures.ThreadPoolExecutor(max_workers=1) as monitor:
        for raw in iter(lambda: sys.stdin.readline(4 * 1024 * 1024 + 1), ''):
            if len(raw) > 4 * 1024 * 1024: emit({'error': 'IPC size limit exceeded.'}); break
            try: request = json.loads(raw)
            except Exception: emit({'error': 'Invalid IPC message.'}); continue
            finally: raw = None  # Do not retain the last serialized PIN/password while idle.
            if not isinstance(request, dict): emit({'error': 'Invalid IPC message.'}); continue
            if request.get('action') == 'export-destination':
                with task_lock:
                    answer = destinations.get(request.get('task_id'))
                    if answer is not None and answer.empty(): answer.put_nowait(request.get('output'))
                continue
            if request.get('action') in ('security', 'resume'):
                manager.security_pending.set(); manager.cancel.set()
                safety.submit(task, request); continue
            elif request.get('action') == 'cancel':
                with task_lock:
                    target = request.get('task_id'); cancelled.add(target)
                    if target in active: manager.cancel.set()
                emit({'id': request.get('id'), 'result': {'cancel_requested': target}}); continue
            elif request.get('action') in ('status', 'list', 'tasks', 'size-cache'):
                monitor.submit(task, request); continue
            executor.submit(task, request)
        # Prevent queued tasks from clearing cancellation after parent EOF.
        output_lost.set(); manager.security_pending.set(); manager.cancel.set()
        safety.submit(manager.security, {'event': 'controller-disconnected'})
    manager.security({'event': 'worker-exit'})


if __name__ == '__main__': main()
