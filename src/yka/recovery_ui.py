"""Small transfer and recovery windows; no file work on the GUI thread."""
import os
from pathlib import Path
from PySide6.QtCore import Qt, QEvent
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QListWidget, QPushButton,
    QFileDialog, QLineEdit, QComboBox, QCheckBox, QDialogButtonBox,
    QAbstractItemView, QMenu, QListWidgetItem)
from .dialogs import Form
from .ui_common import show_error, clear_on_blank
from .transfer import within
from .file_picker import choose_items


class TransferDialog(Form):
    def __init__(self, window):
        super().__init__('Safe Transfer', window); self.resize(720, 500); self.setMinimumWidth(640)
        self.owner = window; self.records = list(getattr(window.model, 'records', []))
        self.source = QComboBox(); self.target = QComboBox()
        self.form.addRow('Source', self.source); self.form.addRow('Destination', self.target)
        self.destination = QLineEdit(); self.destination.setReadOnly(True)
        row = QHBoxLayout(); row.addWidget(self.destination)
        self.browse = QPushButton('Choose Folder…'); self.browse.clicked.connect(self.choose_destination); row.addWidget(self.browse)
        self.form.addRow('Copy to', row)
        self.sources = QListWidget(); self.sources.setSelectionMode(QAbstractItemView.ExtendedSelection)
        clear_on_blank(self.sources)
        self.sources.setContextMenuPolicy(Qt.CustomContextMenu); self.sources.customContextMenuRequested.connect(self.context_menu)
        self.form.addRow('Selected items', self.sources)
        row = QHBoxLayout(); self.edit_buttons = []
        for title, handler in [('Add Files…', self.add_files), ('Remove Selected', self.remove_selected), ('Clear', self.sources.clear)]:
            button = QPushButton(title); button.clicked.connect(handler); row.addWidget(button); self.edit_buttons.append(button)
        self.form.addRow(row)
        self.sources.installEventFilter(self)
        self.conflict = QComboBox()
        self.conflict.addItem('Skip existing files', 'skip')
        self.conflict.addItem('Overwrite existing files', 'overwrite')
        self.form.addRow('If files already exist', self.conflict)
        self.verify = QCheckBox('Verify copied files'); self.verify.setChecked(True); self.form.addRow(self.verify)
        self.notice = QLabel(); self.notice.setWordWrap(True); self.notice.setTextFormat(Qt.PlainText); self.form.addRow(self.notice)
        self.buttons.button(QDialogButtonBox.Ok).setText('Start Copy')
        self.submit_handler = self.start; self.destination_binding = None
        self.refresh_choices()
        self.source.currentIndexChanged.connect(self.source_changed)
        self.target.currentIndexChanged.connect(self.destination_changed)
        self.sources.itemSelectionChanged.connect(self.selection_changed)
        window.controller.result.connect(self.updated); self.finished.connect(self.detach)
        self.selection_changed(); self.destination_changed()

    def detach(self, *_): self.owner.controller.result.disconnect(self.updated)
    def operation_succeeded(self, action, result):
        # Called only for this dialog's submitted request, after the worker has
        # completed every copy and any requested content verification.
        if action == 'transfer': self.sources.clear()
    def updated(self, action, result, context):
        if action in ('list', 'status'):
            self.records = result.get('records', []); self.refresh_choices()
    def refresh_choices(self):
        selected = self.source.currentData(); self.source.blockSignals(True); self.source.clear()
        self.source.addItem('Windows folder', None)
        for record in self.records:
            if record.get('state') == 'mounted': self.source.addItem(f"{record['name']} — {record['mount_point']}", record['id'])
        index = self.source.findData(selected)
        if selected and index < 0:
            self.source.addItem('Vault unavailable — mount it again', selected); index = self.source.count()-1
        self.source.setCurrentIndex(max(index, 0)); self.source.blockSignals(False)
        self.refresh_targets()

    def refresh_targets(self):
        selected = self.target.currentData(); self.target.blockSignals(True); self.target.clear()
        source = next((r for r in self.records if r['id'] == self.source.currentData()), None)
        if self.source.currentData(): self.target.addItem('Windows folder', None)
        for record in self.records:
            if record.get('state') != 'mounted': continue
            if source and (record['id'] == source['id'] or (record['uuid'], record.get('signing_public')) == (source['uuid'], source.get('signing_public'))): continue
            self.target.addItem(f"{record['name']} — {record['mount_point']}", record['id'])
        index = self.target.findData(selected); self.target.setCurrentIndex(max(index, 0)); self.target.blockSignals(False)
        if self.target.currentData() != selected: self.destination_changed()
        self.selection_changed()

    def binding(self, combo):
        ident = combo.currentData()
        if not ident: return dict(record_id=None)
        record = next((r for r in self.records if r['id'] == ident and r.get('state') == 'mounted'), None)
        if not record: raise ValueError('The selected vault is not mounted. Mount it and choose it again.')
        return dict(record_id=ident, uuid=record['uuid'], mount_point=record['mount_point'])
    def validate_path(self, path, binding):
        if binding['record_id']:
            if not within(path, binding['mount_point']): raise ValueError('Choose a location inside the selected vault.')
            current = next((r for r in self.records if r['id'] == binding['record_id'] and r.get('state') == 'mounted'), None)
            if not current or current['mount_point'] != binding['mount_point'] or current['uuid'] != binding['uuid']:
                raise ValueError('The vault mount changed. Choose it again.')
        else:
            if any(r.get('state') == 'mounted' and within(path, r['mount_point']) for r in self.records):
                raise ValueError('Choose this vault from the list before selecting its files.')
        if any(within(path, r['path']) for r in self.records): raise ValueError('Choose a mounted vault, not its encrypted folder.')
    def source_changed(self):
        if not self.busy:
            self.sources.clear(); self.notice.clear(); self.refresh_targets()
    def destination_changed(self):
        # A background status refresh can change the combo during a transfer.
        # Submitted requests own their values; clear only the next operation's UI.
        self.destination.clear(); self.destination_binding = None
    def selection_error(self, message):
        self.notice.setText(message)
        show_error(self, 'transfer', message)
    def add(self, paths, binding=None):
        if self.busy: return
        try:
            binding = binding or self.binding(self.source)
            for raw in paths:
                path = os.path.abspath(raw); self.validate_path(path, binding)
                existing = [(self.sources.item(i), self.sources.item(i).data(Qt.UserRole)['path']) for i in range(self.sources.count())]
                if any(within(path, p) for _,p in existing): continue
                for item, p in existing:
                    if within(p, path): self.sources.takeItem(self.sources.row(item))
                label = os.path.relpath(path, binding['mount_point']) if binding['record_id'] else path
                item = QListWidgetItem(label); item.setToolTip(path); item.setData(Qt.UserRole, dict(path=path, binding=binding))
                self.sources.addItem(item)
            self.notice.clear()
        except ValueError as error: self.selection_error(str(error))
    def add_files(self):
        if self.busy: return
        try:
            binding = self.binding(self.source)
            paths = choose_items(self, binding.get('mount_point', ''))
            if paths: self.add(paths, binding)
        except ValueError as error: self.selection_error(str(error))
        except OSError: self.selection_error('The Windows file picker could not be opened. Try again.')
    def choose_destination(self):
        if self.busy: return
        try:
            binding = self.binding(self.target)
            path = QFileDialog.getExistingDirectory(self, 'Choose the destination folder', binding.get('mount_point', ''))
            if path:
                self.validate_path(path, binding); self.destination.setText(path); self.destination_binding = binding; self.notice.clear()
        except ValueError as error: self.selection_error(str(error))
    def remove_selected(self):
        if not self.busy:
            for item in self.sources.selectedItems(): self.sources.takeItem(self.sources.row(item))
    def eventFilter(self, watched, event):
        if watched is self.sources and event.type() == QEvent.KeyPress and event.key() == Qt.Key_Delete and event.modifiers() == Qt.NoModifier:
            self.remove_selected(); return True
        return super().eventFilter(watched, event)
    def context_menu(self, point):
        if self.busy or not self.sources.selectedItems(): return
        menu = QMenu(self); menu.addAction('Remove', self.remove_selected)
        try: menu.exec(self.sources.mapToGlobal(point))
        finally: menu.deleteLater()
    def selection_changed(self):
        available = any(r.get('state') == 'mounted' for r in self.records)
        source_available = not self.source.currentData() or any(r['id'] == self.source.currentData() and r.get('state') == 'mounted' for r in self.records)
        ready = not self.busy and not getattr(self.owner, 'worker_dead', False) and available and source_available
        self.edit_buttons[0].setEnabled(ready)
        self.edit_buttons[1].setEnabled(not self.busy and bool(self.sources.selectedItems()))
        self.browse.setEnabled(ready and self.target.count() > 0)
        self.buttons.button(QDialogButtonBox.Ok).setEnabled(ready and self.target.count() > 0)
        if not available: self.notice.setText('Mount a vault to use Safe Transfer.')
        elif self.notice.text() == 'Mount a vault to use Safe Transfer.': self.notice.clear()
    def set_busy(self, busy):
        super().set_busy(busy)
        for button in [*self.edit_buttons, self.browse]: button.setEnabled(not busy)
        self.selection_changed()
    def start(self):
        if self.busy: return
        if not self.sources.count() or not self.destination_binding:
            self.selection_error('Choose files to copy and a destination folder.'); return
        try:
            items = [self.sources.item(i).data(Qt.UserRole) for i in range(self.sources.count())]
            for item in items: self.validate_path(item['path'], item['binding'])
            self.validate_path(self.destination.text(), self.destination_binding)
            if self.destination_binding != self.binding(self.target) or any(i['binding'] != self.binding(self.source) for i in items):
                raise ValueError('The vault mount changed. Choose it again.')
            if not any(i['binding']['record_id'] for i in items) and not self.destination_binding['record_id']:
                raise ValueError('Choose a mounted vault as the source or destination.')
            if self.destination_binding['record_id'] and any(i['binding']['record_id'] == self.destination_binding['record_id'] for i in items):
                raise ValueError('Choose a different vault or a Windows folder.')
            self.owner.submit(dict(action='transfer', sources=[i['path'] for i in items], destination=self.destination.text(),
                verify=self.verify.isChecked(), conflict=self.conflict.currentData(),
                selections=[i['binding'] for i in items]+[self.destination_binding]), origin=self)
        except ValueError as error: self.selection_error(str(error))

