"""One disposable read-only size helper; foreground work always takes priority."""
import json
import sys
import time
from PySide6.QtCore import QObject, QProcess, QTimer, Signal
from .native import PROJECT
from .vault_size import binding, cache


class SizeController(QObject):
    changed = Signal()

    def __init__(self, window):
        super().__init__(window); self.window = window
        self.records = {}; self.attempted = {}; self.states = {}; self.active = None; self.forced = set()
        self.stopped = False; self.aborted = False; self.output = bytearray()
        self.process = QProcess(self)
        self.process.setProgram(sys.executable)
        self.process.setArguments(['--measure-size'] if getattr(sys, 'frozen', False) else ['-m', 'yka.vault_size'])
        self.process.setWorkingDirectory(str(PROJECT))
        self.process.started.connect(self.started)
        self.process.readyReadStandardOutput.connect(self.read)
        self.process.readyReadStandardError.connect(self.process.readAllStandardError)
        self.process.finished.connect(self.finished)
        self.process.errorOccurred.connect(self.error)
        self.timer = QTimer(self); self.timer.setSingleShot(True); self.timer.timeout.connect(self.pump)
        self.deadline = QTimer(self); self.deadline.setSingleShot(True); self.deadline.timeout.connect(self.timeout)
        window.controller.changed.connect(self.activity_changed)

    def blocked(self):
        w = self.window
        return self.stopped or w.controller.busy or getattr(w.controller, 'shutting_down', False) or any(
            getattr(w, name, False) for name in ('worker_dead', 'security_unconfirmed', 'exiting', 'shutdown_started')) or any(
            v['action'] in ('security', 'resume') for v in w.controller.pending.values())

    def update(self, records):
        for record in records:
            previous = self.records.get(record['id'], {})
            if ((previous.get('state') == 'Offline' and record.get('state') in ('Unmounted', 'mounted'))
                or (previous.get('state') == 'mounted' and record.get('state') == 'Unmounted')):
                self.attempted.pop(record['id'], None); self.forced.add(record['id'])
        self.records = {r['id']: dict(r) for r in records}
        self.attempted = {k:v for k,v in self.attempted.items() if k in self.records}
        self.forced.intersection_update(self.records)
        self.states = {k:v for k,v in self.states.items() if k in self.records and v[0] == binding(self.records[k])}
        if self.active and (self.active['id'] not in self.records or binding(self.records[self.active['id']]) != binding(self.active)):
            self.abort()
        for record in records: self.decorate(record)
        self.timer.start(800)

    def decorate(self, record):
        record.pop('size_status', None); record.pop('size_error', None)
        state = self.states.get(record['id'])
        if state and state[0] == binding(record):
            record['size_status'] = state[1]
            if len(state) > 2: record['size_error'] = state[2]

    def refresh(self, record_id):
        if self.active and self.active['id'] == record_id: return
        self.attempted.pop(record_id, None)
        self.forced.add(record_id)
        if record_id in self.records:
            self.records[record_id].pop('size_cache', None)
            # Refresh takes precedence over other not-yet-measured records.
            self.records = {record_id:self.records[record_id], **self.records}
        self.states.pop(record_id, None); self.timer.start(0)

    def activity_changed(self):
        if self.blocked(): self.abort()
        elif self.process.state() == QProcess.NotRunning: self.timer.start(800)

    def abort(self):
        if not self.active: return
        self.aborted = True
        ident = self.active['id']; self.attempted.pop(ident, None); self.states.pop(ident, None)
        self.forced.add(ident)
        self.process.kill(); self.changed.emit()

    def stop(self):
        self.stopped = True; self.timer.stop(); self.deadline.stop(); self.abort()

    def pump(self):
        if self.blocked() or self.active or self.process.state() != QProcess.NotRunning: return
        for record in self.records.values():
            if record.get('state') not in ('Unmounted', 'mounted') or not record.get('trusted'): continue
            token = binding(record)
            if self.attempted.get(record['id']) == token: continue
            value = cache(record)
            if record['id'] not in self.forced and value and value['binding'] == token and 0 <= time.time()-value['measured_at'] < 86400: continue
            self.forced.discard(record['id'])
            self.active = {key:record[key] for key in ('id','path','uuid','signing_public')}
            self.active['size_revision'] = record.get('size_revision', 0)
            self.attempted[record['id']] = token; self.states[record['id']] = (token, 'calculating')
            self.output.clear(); self.aborted = False
            self.process.start(); self.deadline.start(600000); self.changed.emit(); return

    def started(self):
        if self.aborted or self.blocked(): self.abort(); return
        self.process.write((json.dumps(self.active) + '\n').encode())

    def read(self):
        self.output.extend(bytes(self.process.readAllStandardOutput()))
        if len(self.output) > 65536: self.timeout()

    def timeout(self):
        if self.active:
            self.states[self.active['id']] = (binding(self.active), 'unavailable', 'Size calculation did not finish. Use Refresh Size to try again.')
        self.process.kill()

    def error(self, error):
        if error == QProcess.FailedToStart: self.finished(-1, QProcess.CrashExit)

    def finished(self, code, status):
        self.deadline.stop(); record = self.active
        if record is None: return
        self.read(); self.active = None
        if not self.aborted:
            try:
                value = json.loads(self.output)
                if code != 0 or status != QProcess.NormalExit or not isinstance(value, dict): raise ValueError()
                if 'error' in value:
                    if not isinstance(value['error'], str): raise ValueError()
                    self.states[record['id']] = (binding(record), 'unavailable', value['error'])
                else:
                    size = value['size']
                    if not cache(dict(record,size_cache=size)) or size['binding'] != binding(record): raise ValueError()
                    self.states.pop(record['id'], None)
                    self.window.controller.send(dict(action='size-cache', record_id=record['id'], size=size))
            except (ValueError, KeyError, TypeError):
                if self.states.get(record['id'], (None, None))[1] != 'unavailable':
                    self.states[record['id']] = (binding(record), 'unavailable', 'The size could not be measured. Use Refresh Size to try again.')
        self.output.clear(); self.changed.emit()
        if not self.stopped: self.timer.start(800)
