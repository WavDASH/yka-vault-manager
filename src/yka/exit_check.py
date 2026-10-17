"""One-shot mount safety probe after loss of the worker; never clears records."""
from contextlib import ExitStack
from pathlib import Path
import psutil
from .native import BACKEND
from .registry import path_key
import os
import json
import win32file
import win32con
from .windows import guarded_reader, mount_state, safe_path, pin_directory


def check(request):
    try:
        pid = request.get('worker_pid', 0)
        if pid and psutil.pid_exists(pid): return {'safe': False, 'mounted': False}
        directory = safe_path(os.environ.get('YKA_STATE_DIR') or Path(os.environ['LOCALAPPDATA']) / 'YKA Vault Manager')
        with ExitStack() as stack:
            from .instance import Instance
            worker = Instance('Worker'); stack.callback(worker.close)
            if not worker.primary: return {'safe': False, 'mounted': False}
            def pin(root):
                for folder in reversed([root, *root.parents]):
                    handle = pin_directory(folder); stack.callback(handle.Close)
                lock = safe_path(root / '.manager.lock')
                if lock.exists():
                    handle = win32file.CreateFile(str(lock), win32con.GENERIC_READ, 0, None,
                        win32con.OPEN_EXISTING, 0x00200000, None)
                    stack.callback(handle.Close)
                    info = win32file.GetFileInformationByHandle(handle)
                    if info[0] & 0x400 or info[7] != 1: raise ValueError()
            records = []
            if directory.exists():
                pin(directory)
                registry = directory / 'registry.json'
                if registry.exists():
                    from .archive import unique_json
                    with guarded_reader(registry) as stream: raw = stream.read(8 * 1024 * 1024 + 1)
                    if len(raw) > 8 * 1024 * 1024: raise ValueError()
                    data = unique_json(raw)
                    if data.get('schema') != 1 or not isinstance(data.get('records'), list): raise ValueError()
                    records = data['records']
            # Include the GUI snapshot so missing state cannot erase known mounts.
            records += request.get('records', [])
            pinned, points = set(), set()
            for record in records:
                saved = record.get('last_mount') or {}
                if saved.get('mount_point'): points.add(saved['mount_point'])
                if record.get('mount_point'): points.add(record['mount_point'])
                root = safe_path(record['path'])
                if path_key(root) in pinned: continue
                pinned.add(path_key(root))
                if root.exists():
                    pin(root)
                    state = root / '.mount-state.json'
                    if state.exists():
                        with guarded_reader(state) as stream: value = json.loads(stream.read(65537))
                        points.add(value['mount_point'])
                elif saved: return {'safe': False, 'mounted': False}
            for point in points:
                if mount_state(BACKEND, point): return {'safe': False, 'mounted': True}
            return {'safe': True, 'mounted': False}
    except Exception:
        return {'safe': False, 'mounted': False}


def start(window):
    from PySide6.QtCore import QThread, QProcess
    from .readonly import call
    from .ui_common import show_error
    class Probe(QThread):
        def run(self):
            try: self.result = call(self.request, timeout=40)
            except Exception: self.result = {'safe': False, 'mounted': False}
    if window.controller.process.state() != QProcess.NotRunning:
        show_error(window, 'unmount', 'YKA could not confirm that all vaults are unmounted. Files may still be accessible.')
        return
    window.exiting = True
    window.state.setText('Checking mount status…')
    task = Probe(window)
    task.request = {'action': 'exit-check', 'records': window.model.records}
    window.exit_probe = task
    def finished():
        window.exiting = False
        if task.result.get('safe'):
            window.security_unconfirmed = False
            window.model.replace([dict(r, state='Unmounted') for r in window.model.records])
            window.allow_close = True
            window.close()
        else:
            show_error(window, 'unmount', 'Some vaults are still mounted. Unmount them before exiting.' if task.result.get('mounted') else
                'YKA could not confirm that all vaults are unmounted. Files may still be accessible.')
        window.exit_probe = None; task.deleteLater()
    task.finished.connect(finished)
    task.start()
