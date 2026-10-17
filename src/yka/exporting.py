"""Ephemeral export traversal and progress; no credentials or persisted transfer state."""
from contextlib import ExitStack
from dataclasses import dataclass
import os
from pathlib import Path
import time
from .storage import internal_file
from .transfer import Paths
from .windows import VaultError, safe_path


def export_header():
    return {'type': 'YKA', 'schema': '2', 'compression': 'store',
            'source_consistency': 'unconfirmed', 'source_detection': 'locked-per-file-stat', 'experimental': True}


@dataclass(frozen=True)
class ExportPlan:
    root: Path
    output: Path
    total: int
    files: int
    folders: int
    archive_bytes: int
    temporary_bytes: int

    def check_space(self):
        from .capacity import check_space
        check_space(self.output.parent, self.archive_bytes, self.temporary_bytes)


def measure_export(root, output, cancel, report):
    """The existing size walk also accounts for ZIP and workspace overhead."""
    from .archive import canonical, MAX_CENTRAL, MAX_MANIFEST, check_cancel
    from .capacity import index_space
    from contextlib import closing
    from zipfile import ZIP64_LIMIT
    total = files = folders = position = central = 0
    manifest = len(canonical({'header': export_header()}) + b'\n')
    def entry(name, size, force_zip64=False):
        nonlocal position, central
        length = len(name.encode('utf-8'))
        if length > 65535: raise VaultError('A file path is too long for a .yka backup.')
        extra = (16 if size > ZIP64_LIMIT else 0) + (8 if position > ZIP64_LIMIT else 0)
        central += 46 + length + (4 + extra if extra else 0)
        position += 30 + length + (20 if force_zip64 or size * 1.05 > ZIP64_LIMIT else 0) + size
        if central > MAX_CENTRAL: raise VaultError('This backup has too many or too-long file paths for the .yka format.')
    report.report('Calculating total size', force=True)
    with closing(ExportSource(root, cancel).walk()) as walker:
        for _, name, kind, info in walker:
            size = info.st_size if kind == 'file' else 0
            record = dict(path=name, kind=kind, size=size)
            if kind == 'file':
                files += 1; total += size; record['sha256'] = '0' * 64
            else: folders += 1
            manifest += len(canonical(record)) + 1
            if manifest > MAX_MANIFEST: raise VaultError('The backup file list exceeds the .yka format limit.')
            entry(name + ('/' if kind == 'directory' else ''), size, kind == 'file')
            report.report('Calculating total size', found=total, files=files)
    entry('manifest.jsonl', manifest); entry('manifest.sig', 512)
    plan = ExportPlan(root, output, total, files, folders, position + central + 98,
                      manifest + index_space(manifest, files + folders))
    report.report('Calculating total size', found=total, files=files, force=True)
    check_cancel(cancel); plan.check_space()
    return plan


class ExportSource:
    def __init__(self, root, cancel):
        self.root = root; self.cancel = cancel; self.paths = Paths()

    def check(self):
        if self.cancel(): raise VaultError('Cancelled. No result committed.')

    def walk(self):
        """Reuse directory-enumeration metadata; keep only one handle per depth."""
        from .archive import MAX_ENTRIES, entry_path
        for required in ('.yka-key', '.config.pb'):
            if not safe_path(self.root / required, must_exist=True).is_file():
                raise VaultError('Vault files are missing.')
        frames = []; count = 0
        def descend(path):
            scope = ExitStack()
            try:
                scope.enter_context(self.paths.directory(path, enumeration=True))
                entries = scope.enter_context(os.scandir(path))
                frames.append((path, entries, scope))
            except BaseException:
                scope.close(); raise
        try:
            descend(self.root)
            while frames:
                self.check()
                directory, entries, scope = frames[-1]
                entry = next(entries, None)
                if entry is None:
                    frames.pop(); scope.close(); continue
                if directory == self.root and internal_file(entry.name): continue
                info = entry.stat(follow_symlinks=False)
                if info.st_file_attributes & 0x400:
                    raise VaultError('Source contains links or reparse points.')
                path = Path(entry.path); name = path.relative_to(self.root).as_posix()
                # Entry syntax is checked once per traversal, not by opening each
                # file. Content handles still enforce link and sharing rules.
                entry_path(name)
                count += 1
                if count > MAX_ENTRIES: raise VaultError(f'A .yka backup supports up to {MAX_ENTRIES:,} files and folders.')
                kind = 'directory' if info.st_file_attributes & 0x10 else 'file'
                yield path, name, kind, info
                if kind == 'directory': descend(path)
        finally:
            for _, _, scope in reversed(frames): scope.close()


class ExportProgress:
    def __init__(self, callback, *, restoring=False):
        self.callback = callback; self.phase = ''; self.last = 0
        self.restoring = restoring
        self.started = time.monotonic(); self.total = self.total_files = 0
        self.copied = self.verified = self.completed = 0

    def start(self, total, files):
        self.total = total; self.total_files = files; self.started = time.monotonic()
        self.report('Restoring backup' if self.restoring else 'Exporting backup', force=True)

    def report(self, phase, *, found=0, files=0, force=False, complete=False):
        now = time.monotonic()
        if not force and now - self.last < .2: return
        finishing = phase == 'Finishing restore'
        if phase != self.phase and not complete and not finishing: self.started = now
        self.last = now; self.phase = phase
        counting = phase == 'Calculating total size'
        percent = None if counting else (100 if complete else min(99, (self.copied + self.verified) * 100 // max(2 * self.total, 1)))
        done = self.verified if phase in ('Verifying backup', 'Verifying restored files') else self.copied
        speed = done / max(now - self.started, .001) / (1024 * 1024)
        summary = (f'{files:,} files · {found / (1024 ** 3):,.2f} GiB found' if counting else
                   f'{self.completed:,} / {self.total_files:,} files · {done / (1024 ** 3):,.2f} / {self.total / (1024 ** 3):,.2f} GiB · {speed:,.1f} MiB/s')
        value = dict(kind='transfer', current=phase + '…', summary=summary, percent=percent)
        if finishing or (complete and self.restoring): value['cancellable'] = False
        self.callback(value)
