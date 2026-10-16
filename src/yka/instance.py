"""Per-user kernel lifetime locks and activation events; no lock files or sockets."""
import hashlib
import os
import time
import win32api
import win32con
import win32event
import win32security
import pywintypes


def name(kind):
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try: sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
    finally: token.Close()
    # Only explicit isolated test environments use a separate namespace.
    state = os.environ.get('YKA_STATE_DIR')
    suffix = hashlib.sha256(os.path.normcase(os.path.abspath(state)).encode()).hexdigest() if state else 'production'
    return f'Global\\YKA.{sid}.{suffix}.{kind}'


def attributes():
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try: sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
    finally: token.Close()
    attr = pywintypes.SECURITY_ATTRIBUTES()
    attr.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f'D:P(A;;GA;;;SY)(A;;GA;;;{sid})', win32security.SDDL_REVISION_1)
    return attr


class Instance:
    def __init__(self, kind='GUI'):
        self.handle = win32event.CreateMutex(attributes(), False, name(kind))
        self.primary = win32api.GetLastError() != 183
        self.activate = win32event.CreateEvent(attributes(), False, False, name('activate'))
        self.ack = win32event.CreateEvent(attributes(), True, False, name('ack'))

    def request_activation(self, timeout=5):
        win32event.ResetEvent(self.ack)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            win32event.SetEvent(self.activate)
            if win32event.WaitForSingleObject(self.ack, 250) == 0: return True
        return False

    def poll(self, show):
        if win32event.WaitForSingleObject(self.activate, 0) == 0:
            show(); win32event.SetEvent(self.ack)

    def close(self):
        for attr in ('handle', 'activate', 'ack'):
            handle = getattr(self, attr, None)
            if handle: handle.Close(); setattr(self, attr, None)


def worker_available():
    probe = Instance('Worker')
    try: return probe.primary
    finally: probe.close()
