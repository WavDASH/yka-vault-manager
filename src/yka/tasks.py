"""Private recovery journal. Never stores credentials or file contents."""
import json
import os
from pathlib import Path
import time
import uuid
from contextlib import contextmanager
import psutil
from .archive import unique_json
from .windows import VaultError, VaultGuard, safe_path, guarded_reader, private_directory

TRACKED = {'restore-backup', 'create', 'mount', 'unmount', 'export', 'import', 'restore-keyring',
           'add-device', 'remove-device', 'set-recovery', 'remove-recovery', 'move-vault', 'recover-move'}


class Tasks:
    def __init__(self, state):
        self.directory = safe_path(Path(state) / 'tasks')
        if not self.directory.exists():
            try: private_directory(self.directory)
            except FileExistsError: pass

    def path(self, ident):
        if str(uuid.UUID(ident)) != ident: raise VaultError('Invalid task identifier.')
        return safe_path(self.directory / (ident + '.json'))

    @contextmanager
    def guard(self):
        deadline = time.monotonic() + 5
        while True:
            try: lock = VaultGuard(self.directory); break
            except VaultError:
                if time.monotonic() >= deadline: raise
                time.sleep(.02)
        with lock: yield

    def save(self, task):
        encoded = json.dumps({k:v for k,v in task.items() if k not in ('files','directories') and not k.startswith('_')}, ensure_ascii=False).encode('utf-8')
        if len(encoded) > 32 * 1024 * 1024: raise VaultError('Task journal is too large.')
        with self.guard():
            target = self.path(task['id'])
            temporary = self.directory / (uuid.uuid4().hex + '.partial')
            with temporary.open('xb') as out:
                out.write(encoded); out.flush(); os.fsync(out.fileno())
            os.replace(temporary, target)

    def load(self, ident):
        with self.guard(): return self._load(ident)

    def _load(self, ident):
        with guarded_reader(self.path(ident)) as stream: raw = stream.read(32 * 1024 * 1024 + 1)
        if len(raw) > 32 * 1024 * 1024: raise VaultError('Task journal is too large.')
        task = unique_json(raw)
        if task.get('id') != ident or task.get('schema') != 1: raise VaultError('Invalid task journal. Keep it for inspection.')
        return task

    def start(self, action, **fields):
        task = dict(schema=1, id=str(uuid.uuid4()), action=action, state='Running',
                    pid=os.getpid(), process_started=psutil.Process().create_time(), created=time.time(), **fields)
        task['started'] = task['created']
        self.save(task)
        return task

    def finish(self, task, state, detail=''):
        now = time.time()
        task.update(state=state, detail=detail, updated=now, ended=now); self.save(task)

    def records(self):
        result = []
        for file in self.directory.glob('*.json'):
            try:
                task = self.load(file.stem)
                if task['state'] == 'Running':
                    try: alive = psutil.Process(task['pid']).create_time() == task['process_started']
                    except psutil.Error: alive = False
                    if not alive: task['state'] = 'Interrupted'
                # Ignore retired transfer records; only other operations use this journal.
                if task.get('action') == 'transfer': continue
                result.append({k: v for k, v in task.items() if k not in ('files', 'directories') and not k.startswith('_')})
            except Exception:
                result.append(dict(id=file.stem, action='Unreadable journal', state='Needs attention', detail=str(file)))
        return sorted(result, key=lambda t: t.get('created', 0), reverse=True)
