"""GUI-thread IPC controller. Requests retain their record identity, never selection."""
import json
import sys
from PySide6.QtCore import QObject, QProcess, Signal
from .native import PROJECT, diagnostic_fields

BACKGROUND_ACTIONS = frozenset(('list', 'status', 'inspect', 'registration-info', 'tasks', 'size-cache'))
CONTROL_ACTIONS = BACKGROUND_ACTIONS | {'security', 'resume', 'cancel'}


class Controller(QObject):
    result = Signal(str, object, object)
    error = Signal(str, str, object)
    progress = Signal(str, object)
    changed = Signal()
    stopped = Signal()
    destination = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.pending = {}; self.counter = 0; self.buffer = bytearray(); self.disconnected = False; self.shutting_down = False
        self.process = QProcess(self)
        self.process.setProgram(sys.executable)
        self.process.setArguments(['--worker'] if getattr(sys, 'frozen', False) else ['-m', 'yka.worker'])
        self.process.setWorkingDirectory(str(PROJECT))
        self.process.readyReadStandardOutput.connect(self.read)
        self.process.readyReadStandardError.connect(self.process.readAllStandardError)
        self.process.finished.connect(self.connection_lost)
        self.process.errorOccurred.connect(self.connection_lost)
        self.process.start()

    def connection_lost(self, *_):
        if self.disconnected: return
        self.disconnected = True
        # EOF requests graceful task cancellation and mount cleanup. Never kill
        # the worker to recover a protocol error while mounts may still be live.
        self.process.closeWriteChannel()
        self.pending.clear(); self.buffer.clear()
        self.stopped.emit(); self.changed.emit()

    def protocol_failed(self):
        self.connection_lost()
        self.error.emit('protocol', 'Communication with the background worker failed. Mount status is unknown. Check the mounted locations before restarting YKA.', {})

    @property
    def busy(self):
        return any(v['action'] not in CONTROL_ACTIONS for v in self.pending.values())

    def send(self, request, *, before_send=None):
        if self.shutting_down: return
        self.counter += 1; request = dict(request, id=self.counter)
        context = {k: request[k] for k in ('id', 'action', 'record_id') if k in request}
        task_id = request['id']
        self.pending[task_id] = context
        if before_send is not None: before_send(context)
        if self.disconnected or self.process.state() != QProcess.Running:
            self.pending.pop(task_id, None)
            self.error.emit(request['action'], 'The background worker is unavailable. Restart YKA before trying again.', context); return
        payload = bytearray(json.dumps(request, ensure_ascii=False).encode() + b'\n')
        try: written = self.process.write(bytes(payload))
        finally: payload[:] = b'\0' * len(payload)
        if written < 0:
            self.protocol_failed(); return
        self.changed.emit()
        return task_id

    def shutdown(self):
        self.shutting_down = True
        self.process.closeWriteChannel()

    def end_system_session(self):
        # Windows confirmed session end. EOF activates worker cancellation and
        # unmount independently of the GUI event loop. Never force-kill it.
        # Keep this shorter than Windows' usual hung-application timeout.
        from PySide6.QtCore import QSignalBlocker
        with QSignalBlocker(self.process):
            self.shutdown()
            if self.process.state() != QProcess.NotRunning:
                self.process.waitForFinished(2500)

    def cancel(self):
        for task_id, item in list(self.pending.items()):
            if item['action'] not in CONTROL_ACTIONS:
                self.send({'action': 'cancel', 'task_id': task_id})

    def export_destination(self, task_id, output):
        if self.disconnected: return
        if self.process.write((json.dumps({'action': 'export-destination', 'task_id': task_id, 'output': output}) + '\n').encode()) < 0:
            self.protocol_failed()

    def read(self):
        if self.disconnected:
            self.process.readAllStandardOutput(); return
        self.buffer.extend(bytes(self.process.readAllStandardOutput()))
        if len(self.buffer) > 8 * 1024 * 1024:
            self.protocol_failed(); return
        while b'\n' in self.buffer:
            raw, _, rest = self.buffer.partition(b'\n'); self.buffer = bytearray(rest)
            try: reply = json.loads(raw)
            except (ValueError, UnicodeError):
                self.protocol_failed(); return
            if not isinstance(reply, dict) or type(reply.get('id')) is not int:
                self.protocol_failed(); return
            if reply.get('event') == 'progress':
                context = self.pending.get(reply.get('id'))
                if context and context['action'] not in CONTROL_ACTIONS:
                    if not isinstance(reply.get('message'), str): self.protocol_failed(); return
                    if 'transfer' in reply:
                        value = reply['transfer']
                        if (context['action'] not in ('transfer', 'export', 'restore-backup', 'import') or not isinstance(value, dict)
                            or not isinstance(value.get('current'), str) or not isinstance(value.get('summary'), str)
                            or ('cancellable' in value and (type(value['cancellable']) is not bool or context['action'] not in ('restore-backup', 'import')))
                            or (value.get('percent') is not None and (type(value['percent']) is not int or not 0 <= value['percent'] <= 100))):
                            self.protocol_failed(); return
                        context = dict(context, transfer_progress=value)
                    self.progress.emit(reply['message'], context)
                continue
            if reply.get('event') == 'destination':
                context = self.pending.get(reply.get('id'))
                if context and context['action'] == 'export': self.destination.emit(context)
                continue
            if ('error' in reply) == ('result' in reply) or ('error' in reply and not isinstance(reply['error'], str)) or ('result' in reply and not isinstance(reply['result'], dict)):
                self.protocol_failed(); return
            context = self.pending.pop(reply.get('id'), None)
            if not context: continue
            if 'error' in reply: self.error.emit(context['action'], reply['error'], dict(context, **diagnostic_fields(reply)))
            else: self.result.emit(context['action'], reply['result'], context)
            self.changed.emit()
