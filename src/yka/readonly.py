"""Bounded, disposable helpers. No provisioning or filesystem writes allowed."""
import base64
import json
import os
import queue
import subprocess
import sys
import threading
import time
import win32api
import win32con
import win32job
from .windows import VaultError

UNAVAILABLE = 'The YubiKey did not respond. Reconnect it and try again.'


def call(request, *, timeout=20, cancel=lambda: False, progress=lambda _: None):
    from .native import PROJECT
    command = [sys.executable, '--readonly'] if getattr(sys, 'frozen', False) else [sys.executable, '-m', 'yka.readonly']
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, cwd=PROJECT, creationflags=subprocess.CREATE_NO_WINDOW)
    job = None
    try:
        job = win32job.CreateJobObject(None, '')
        limits = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
        limits['BasicLimitInformation']['LimitFlags'] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, limits)
        handle = win32api.OpenProcess(win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE, False, process.pid)
        try: win32job.AssignProcessToJobObject(job, handle)
        finally: handle.Close()
    except BaseException:
        if job: job.Close()
        if process.poll() is None: process.terminate()
        process.wait(timeout=5); process.stdin.close(); process.stdout.close()
        raise
    lines = queue.Queue(maxsize=16); stopped = threading.Event()
    def read():
        try:
            while not stopped.is_set():
                raw = process.stdout.readline(1024 * 1024 + 1)
                while not stopped.is_set():
                    try: lines.put(raw, timeout=.1); break
                    except queue.Full: pass
                if not raw: break
        except (OSError, ValueError): pass
    thread = threading.Thread(target=read, daemon=True); thread.start()
    payload = bytearray()
    try:
        payload.extend(json.dumps(request).encode() + b'\n')
        process.stdin.write(payload); process.stdin.flush()
        payload[:] = b'\0' * len(payload)
        deadline = time.monotonic() + timeout
        while True:
            if cancel(): raise VaultError('Operation cancelled.')
            if time.monotonic() >= deadline: raise VaultError(UNAVAILABLE)
            try: raw = lines.get(timeout=.05)
            except queue.Empty:
                if process.poll() is not None and not thread.is_alive(): raise VaultError(UNAVAILABLE)
                continue
            if not raw or len(raw) > 1024 * 1024: raise VaultError(UNAVAILABLE)
            try: value = json.loads(raw)
            except (ValueError, UnicodeError): raise VaultError(UNAVAILABLE) from None
            if not isinstance(value, dict): raise VaultError(UNAVAILABLE)
            if 'progress' in value: progress(value['progress'])
            elif 'error' in value:
                error = VaultError(value['error']); error.diagnostic = value.get('diagnostic', {})
                raise error
            elif 'result' in value: return value['result']
            else: raise VaultError(UNAVAILABLE)
    finally:
        payload[:] = b'\0' * len(payload); stopped.set()
        # Only read-only helpers: terminate a stuck PC/SC call, never a key write or mount.
        job.Close()  # Also reaps any read-only SecureFS status probe on parent failure.
        process.wait(timeout=5)
        process.stdin.close(); thread.join(timeout=2)
        if not thread.is_alive(): process.stdout.close()


def inspect(cancel=lambda: False):
    names = call({'action': 'readers'}, timeout=10, cancel=cancel)
    devices, failed = [], False
    for name in names:
        if cancel(): raise VaultError('Operation cancelled.')
        try: devices.append(call({'action': 'inspect-reader', 'reader': name}, timeout=12, cancel=cancel))
        except VaultError:
            if cancel(): raise
            failed = True
    result = {'devices': devices, 'inspection_incomplete': failed}
    if failed: result['message'] = 'Some YubiKeys could not be checked. Reconnect them and refresh.'
    return result


def execute(request, progress):
    from . import piv
    action = request['action']
    if action == 'readers': return [r.name for r in piv._readers()]
    if action == 'inspect-reader':
        reader = next((r for r in piv._readers() if r.name == request['reader']), None)
        if reader is None: raise VaultError('The YubiKey was disconnected. Reconnect it and try again.')
        with piv._connect(reader) as connection:
            session = piv.PivSession(connection)
            return piv._report(session, session.get_serial())
    if action == 'selected': return piv.selected_device(request['serial'], request['slot'], enroll=request.get('enroll', False))
    if action == 'sign': return piv.sign(request['device'], base64.b64decode(request['message'], validate=True), request['pin'], progress)
    if action == 'exit-check':
        from .exit_check import check
        return check(request)
    raise VaultError('The operation failed. See Diagnostics for details.')


def main():
    def emit(value): print(json.dumps(value), flush=True)
    raw = sys.stdin.readline(1024 * 1024 + 1)
    if not raw or len(raw) > 1024 * 1024: return
    # Parent death closes stdin; no orphan smart-card call may retain a PIN.
    def eof():
        sys.stdin.read(); os._exit(0)
    threading.Thread(target=eof, daemon=True).start()
    request = None
    try:
        request = json.loads(raw); raw = None
        emit({'result': execute(request, lambda message: emit({'progress': message}))})
    except VaultError as error:
        emit({'error': str(error), 'diagnostic': getattr(error, 'diagnostic', {})})
    except Exception: emit({'error': UNAVAILABLE})
    finally:
        if isinstance(request, dict): request.clear()


if __name__ == '__main__': main()
