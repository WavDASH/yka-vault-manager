import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import queue
import threading
import time
import win32api
import win32con
import win32job
import psutil
from . import piv
from .windows import VaultError

PROJECT = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parents[2]))
BACKEND = PROJECT / 'vendor/securefs/securefs.exe'
NATIVE = PROJECT / 'native/target/release/yka-crypto.exe'
PLUGIN = PROJECT / 'vendor/age-plugin-yubikey-source/target/release/age-plugin-yubikey.exe'
ERROR_CODES = frozenset(('config_mismatch', 'identity_mismatch', 'device_unauthorized',
    'metadata_changed', 'backend_timeout', 'filesystem_failed', 'operation_failed'))
ERROR_STAGES = frozenset(('request', 'authentication', 'keyring_commit', 'securefs_create',
    'securefs_unmount', 'keyring_create', 'securefs_mount', 'keyring_update', 'archive_sign'))


def diagnostic_fields(value):
    # Only fixed identifiers may enter logs. Never forward arbitrary backend text.
    return {key: value[key] for key, allowed in (('code', ERROR_CODES), ('stage', ERROR_STAGES))
            if isinstance(value.get(key), str) and value[key] in allowed}


class NativeSession:
    def __init__(self, request, guard=None, pin=None, progress=lambda _: None):
        if not NATIVE.is_file() or not BACKEND.is_file():
            raise VaultError('Components missing. Run scripts/build.ps1.')
        self.pin, self.progress, self.device = pin, progress, request.get('device')
        self.new_device = request.get('new_device')
        self.new_pin = request.pop('new_pin', None)
        request = dict(request, securefs=str(BACKEND), guard_handles=[int(h) for h in guard.handles] if guard else [])
        env = dict(os.environ)
        # Never search user PATH for the age plugin. Stock upstream binary is not used.
        env['PATH'] = str(PLUGIN.parent) + os.pathsep + os.path.join(os.environ['SystemRoot'], 'System32')
        for key in ('RUST_LOG', 'RUST_BACKTRACE'): env.pop(key, None)
        startup = subprocess.STARTUPINFO()
        self.process = None; self.job = None; self.reader = None
        self.reader_stopping = threading.Event()
        self.lines = queue.Queue(maxsize=8)
        inherited = []
        try:
            try:
                if guard:
                    for handle in guard.handles:
                        win32api.SetHandleInformation(handle, win32con.HANDLE_FLAG_INHERIT, win32con.HANDLE_FLAG_INHERIT)
                        inherited.append(handle)
                    startup.lpAttributeList = {'handle_list': [int(h) for h in inherited]}
                self.process = subprocess.Popen([str(NATIVE)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, env=env, cwd=str(NATIVE.parent), startupinfo=startup, close_fds=True,
                    creationflags=subprocess.CREATE_NO_WINDOW)
            finally:
                for handle in inherited:
                    win32api.SetHandleInformation(handle, win32con.HANDLE_FLAG_INHERIT, 0)
            self.started_at = psutil.Process(self.process.pid).create_time()
            if request['action'] != 'mount' or request.get('prepare'):
                # Private crypto can be cancelled; live mounts release this policy.
                self.job = win32job.CreateJobObject(None, '')
                limits = win32job.QueryInformationJobObject(self.job, win32job.JobObjectExtendedLimitInformation)
                limits['BasicLimitInformation']['LimitFlags'] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                win32job.SetInformationJobObject(self.job, win32job.JobObjectExtendedLimitInformation, limits)
                process_handle = win32api.OpenProcess(win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE, False, self.process.pid)
                try: win32job.AssignProcessToJobObject(self.job, process_handle)
                finally: process_handle.Close()
            self.reader = threading.Thread(target=self._read, name='YKA native output', daemon=True)
            self.reader.start()
            if request.get('device'):
                self.progress(f"Connecting to YubiKey {request['device']['serial']}. Please wait for the PIN or touch verification prompt…")
            elif request.get('passphrase'): self.progress('Verifying your password. This may take a few seconds…')
            self.send(request)
        except BaseException:
            # No complete request has been dispatched. Never use this path for an established mount.
            self.reader_stopping.set()
            self.pin = None; self.new_pin = None
            if self.process is not None:
                self.close(); self.close_job()
                if self.process.poll() is None: self.process.terminate()
                self.process.wait(timeout=15)
                self.reap_output()
            else: self.close_job()
            raise

    def _read(self):
        def enqueue(raw):
            while not self.reader_stopping.is_set():
                try: self.lines.put(raw, timeout=.1); return
                except queue.Full: pass
        try:
            while True:
                raw = self.process.stdout.readline(4 * 1024 * 1024 + 1)
                enqueue(raw)
                if not raw or len(raw) > 4 * 1024 * 1024: break
        except (OSError, ValueError): pass
        finally: enqueue(b'')

    def reap_output(self):
        """Release pipes after exit; never terminate a mount to close them."""
        if self.process.poll() is None: return
        self.reader_stopping.set()
        if self.reader is not None: self.reader.join(timeout=2)
        if self.reader is None or not self.reader.is_alive(): self.process.stdout.close()
        while True:
            try: self.lines.get_nowait()
            except queue.Empty: break

    def send(self, message):
        payload = bytearray(json.dumps(message, ensure_ascii=False).encode('utf-8') + b'\n')
        try:
            self.process.stdin.write(payload)
            self.process.stdin.flush()
        finally:
            payload[:] = b'\x00' * len(payload)

    def receive(self, timeout=180, cancel=lambda: False, timeout_message=None):
        deadline = time.monotonic() + timeout
        while True:
            if cancel(): raise VaultError('The operation was cancelled. Check the vault status before trying again.')
            if time.monotonic() > deadline: raise VaultError(timeout_message or 'The operation timed out. Check your YubiKey connection and the vault status before trying again.')
            try: line = self.lines.get(timeout=0.1)
            except queue.Empty: continue
            if not line or len(line) > 4 * 1024 * 1024:
                raise VaultError('Backend connection lost. Mount status needs checking.')
            try: message = json.loads(line)
            except (ValueError, UnicodeError): raise VaultError('The encryption worker returned an invalid response. Check vault status before retrying.') from None
            if not isinstance(message, dict) or not isinstance(message.get('event'), str):
                raise VaultError('The encryption worker returned an invalid response. Check vault status before retrying.')
            event = message.get('event')
            if event == 'pin':
                if not self.pin: raise VaultError('Enter the PIV PIN.')
                self.progress('Verifying the PIN for the selected YubiKey…')
                self.send({'pin': self.pin})
                self.pin = None
            elif event == 'piv_sign':
                new = message.get('new_device', False)
                pin = self.new_pin if new else self.pin
                if not pin: raise VaultError('Enter the PIV PIN to authorize this vault.')
                signature = piv.sign(self.new_device if new else self.device, base64.b64decode(message['message']), pin, progress=self.progress)
                self.send({'signature': signature})
                # Signing and age creation do not reuse a cached PIN for future unlocks.
                if not new: self.pin = None
            elif event == 'new_device_test':
                self.progress('Testing the new YubiKey independently. A separate touch will confirm that it can unlock this vault.')
                self.pin = self.new_pin; self.new_pin = None
                self.send({'action': 'continue'})
            elif event in ('touch', 'progress'): self.progress(message.get('message', 'Processing the operation…'))
            elif event == 'error':
                error = VaultError(message['message'])
                error.diagnostic = diagnostic_fields(message)
                raise error
            else: return message

    def close(self):
        self.pin = None
        self.new_pin = None
        if self.process.stdin and not self.process.stdin.closed:
            try: self.process.stdin.close()
            except OSError: pass  # A broken pipe must not skip guard/process cleanup.

    def close_job(self):
        if self.job: self.job.Close(); self.job = None

    def finish_crypto(self):
        """Reap a short-lived operation and all private plugin children, never a mount."""
        self.reader_stopping.set()
        self.close()
        try:
            try: self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                if self.job is None: raise VaultError('The mount supervisor is still running. Check mount status before retrying.') from None
                self.close_job()
                if self.process.poll() is None: self.process.terminate()
                self.process.wait(timeout=15)
        finally: self.close_job()
        self.reap_output()

    def release_mount_job(self):
        # Authentication can be aborted with its private plugin. After continue,
        # only the mount supervisor may stop the filesystem safely.
        if self.job:
            limits = win32job.QueryInformationJobObject(self.job, win32job.JobObjectExtendedLimitInformation)
            limits['BasicLimitInformation']['LimitFlags'] &= ~win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            win32job.SetInformationJobObject(self.job, win32job.JobObjectExtendedLimitInformation, limits)
            self.close_job()


def native_call(request, *, guard=None, pin=None, progress=lambda _: None, cancel=lambda: False):
    if request['action'] == 'mount': raise VaultError('Mounting requires the managed mount supervisor.')
    session = NativeSession(request, guard, pin, progress)
    try:
        result = session.receive(cancel=cancel)
    finally:
        session.finish_crypto()
    if session.process.returncode != 0: raise VaultError('Backend operation failed.')
    return result
