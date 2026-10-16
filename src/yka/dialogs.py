"""Short, explicit dialogs. Secrets exist only until a request is submitted."""
import base64
import copy
import hashlib
import json
import re
from pathlib import Path
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from .ui_common import ModalDialog
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QFormLayout, QDialogButtonBox,
    QLineEdit, QComboBox, QLabel, QPushButton, QFileDialog, QMessageBox, QTabWidget,
    QWidget, QHBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView, QApplication, QTextEdit, QProgressBar, QCheckBox)
from .ui_common import MountPicker, style_table, available_drives, style_form, TaskDialog, show_error, show_result, AdjacentHeader
from .mount_recovery import RECOVERY_STATES, recovery_hint


class Form(ModalDialog):
    def __init__(self, title, parent=None):
        super().__init__(parent); self.setWindowTitle(title); self.resize(480, 180); self.setMinimumWidth(480)
        self.submit_handler = None; self.busy = False
        self.layout = QVBoxLayout(self); self.form = QFormLayout(); style_form(self.form); self.layout.addLayout(self.form)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept); self.buttons.rejected.connect(self.reject)
        self.layout.addWidget(self.buttons)

    def accept(self):
        if self.busy: return
        if self.submit_handler is not None: self.submit_handler(); return
        super().accept()

    def set_busy(self, busy):
        self.busy = busy; self.buttons.setEnabled(not busy)
        if busy:
            self._enabled_before_task = [(self.form.itemAt(i).widget(), self.form.itemAt(i).widget().isEnabled()) for i in range(self.form.count()) if self.form.itemAt(i).widget()]
            for widget, _ in self._enabled_before_task: widget.setEnabled(False)
        else:
            for widget, enabled in getattr(self, '_enabled_before_task', []): widget.setEnabled(enabled)

    def reject(self):
        if self.busy: return
        for field in self.findChildren(QLineEdit):
            if field.echoMode() == QLineEdit.Password: field.clear()
        super().reject()

    def closeEvent(self, event):
        if self.busy: event.ignore()
        else: super().closeEvent(event)

    def text(self, label, value='', secret=False):
        widget = QLineEdit(value)
        if secret: widget.setEchoMode(QLineEdit.Password)
        self.form.addRow(label, widget); return widget

    def note(self, text):
        label = QLabel(text); label.setTextFormat(Qt.PlainText); label.setWordWrap(True); self.form.addRow(label)

    def folder(self, label, value='', new=False, name=None, leaf='New Vault'):
        field = QLineEdit(value); row = QHBoxLayout(); row.addWidget(field)
        button = QPushButton('Browse…'); row.addWidget(button)
        def browse():
            path = QFileDialog.getExistingDirectory(self, 'Choose parent folder' if new else 'Choose vault folder')
            if path: field.setText(str(Path(path) / ((name.text().strip() or leaf) if name is not None else leaf)) if new else path)
        if name is not None:
            def rename_folder():
                if field.text().strip(): field.setText(str(Path(field.text()).parent / (name.text().strip() or 'New Vault')))
            name.textChanged.connect(rename_folder)
        button.clicked.connect(browse); self.form.addRow(label, row); return field


class AddExistingDialog(Form):
    def __init__(self, window, key_file=''):
        super().__init__('Add Existing Vault', window)
        self.owner = window; self.request_id = None; self.checked_path = None; self.requires_trust = True
        self.root = QLineEdit(key_file); row = QHBoxLayout(); row.addWidget(self.root)
        browse = QPushButton('Browse…'); row.addWidget(browse); self.form.addRow('Vault key file (.yka-key)', row)
        def choose():
            selected, _ = QFileDialog.getOpenFileName(self, 'Select Vault Key File', '', 'Vault key (.yka-key);;All files (*)')
            if selected:
                previous_name = Path(self.root.text()).parent.name if self.root.text() else ''
                if self.name.text().strip() in ('', previous_name): self.name.setText(Path(selected).parent.name)
                self.root.setText(selected)
        browse.clicked.connect(choose); self.name = self.text('Name', Path(key_file).parent.name if key_file else '')
        self.vault_root = None; self.identity_change = None
        self.explanation = QLabel(); self.explanation.setWordWrap(True); self.explanation.setTextFormat(Qt.PlainText); self.form.addRow(self.explanation)
        self.trust = QCheckBox('I recognize and trust this vault folder.'); self.form.addRow(self.trust)
        self.timer = QTimer(self); self.timer.setSingleShot(True); self.timer.setInterval(300)
        self.timer.timeout.connect(self.check_folder)
        self.root.textChanged.connect(self.path_changed); self.trust.toggled.connect(self.update_continue)
        window.controller.result.connect(self.checked); window.controller.error.connect(self.check_failed)
        self.finished.connect(self.detach)
        self.submit_handler = self.submit_folder; self.path_changed()

    def detach(self, *_):
        self.timer.stop(); self.request_id = None
        self.owner.controller.result.disconnect(self.checked); self.owner.controller.error.disconnect(self.check_failed)

    def path_changed(self, *_):
        self.identity_change = None
        self.request_id = None; self.checked_path = None; self.trust.setChecked(False)
        self.show_notice('Checking the folder…' if self.root.text().strip() else '')
        self.update_continue(); self.timer.start()

    def show_notice(self, text, *, confirmation=False):
        self.explanation.setText(text)
        self.form.setRowVisible(self.explanation, bool(text))
        self.form.setRowVisible(self.trust, confirmation)
        QTimer.singleShot(0, self.fit_content)

    def fit_content(self):
        # Recalculate wrapped text after Qt has applied row visibility and width.
        self.layout.invalidate(); self.layout.activate()
        height = max(self.layout.minimumSize().height(), self.layout.totalHeightForWidth(self.width()))
        self.setMinimumHeight(height)
        self.resize(self.width(), height)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if event.size().width() != event.oldSize().width() and hasattr(self, 'explanation'):
            QTimer.singleShot(0, self.fit_content)

    def update_continue(self, *_):
        ready = self.checked_path == self.root.text().strip() and bool(self.checked_path)
        self.buttons.button(QDialogButtonBox.Ok).setEnabled(not self.busy and ready and (not self.requires_trust or self.trust.isChecked()))

    def check_folder(self):
        if not self.root.text().strip() or self.busy: return
        self.request_id = self.owner.controller.counter + 1
        self.request_path = self.root.text().strip()
        self.owner.controller.send({'action': 'registration-info', 'key_file': self.request_path})

    def checked(self, action, result, context):
        if action != 'registration-info' or context.get('id') != self.request_id or self.request_path != self.root.text().strip(): return
        self.checked_path = self.request_path; self.vault_root = result['root']; self.requires_trust = result['requires_trust']
        self.identity_change = result.get('identity_change')
        self.unlock_info = {k: result[k] for k in ('key_tags', 'recovery') if k in result}
        self.trust.setText('I recognize this as a different vault.' if self.identity_change else 'I recognize and trust this vault folder.')
        self.show_notice('This location previously contained a different vault. Its identity will be verified before the saved record is updated.' if self.identity_change else 'This folder has no saved trust record or archive proof. Confirm that you trust its source before continuing.' if self.requires_trust else
            '', confirmation=self.requires_trust)
        self.update_continue()

    def check_failed(self, action, message, context):
        if action != 'registration-info' or context.get('id') != self.request_id: return
        self.checked_path = None; self.show_notice(message); self.update_continue()

    def submit_folder(self):
        self.update_continue()
        if not self.buttons.button(QDialogButtonBox.Ok).isEnabled(): return
        credentials = auth(self, 'Verify Existing Vault', record=dict(name=self.name.text().strip(), path=self.vault_root, **self.unlock_info))
        if credentials is not None:
            self.owner.submit(dict(action='register', root=self.vault_root, name=self.name.text().strip(),
                trust_existing=self.requires_trust and self.trust.isChecked(), identity_change=self.identity_change, **credentials), origin=self, close_on_success=True)

    def set_busy(self, busy):
        super().set_busy(busy); self.update_continue()


class MountSettingsDialog(Form):
    def __init__(self, record, parent=None, *, require_available=False):
        super().__init__('Mount Settings', parent); self.record = record; self.require_available = require_available
        saved = record.get('mount_settings', {})
        self.name = self.text('YKA display name', record['name'])
        self.point = MountPicker(saved.get('mount_point', record.get('mount_point', '')))
        self.form.addRow('Mount point', self.point)
        self.label = self.text('Windows volume label', saved.get('volume_label', record['name']))
        self.label.setMaxLength(32)
        self.note("The volume label appears in Windows Explorer after the next mount.")
        self.buttons.button(QDialogButtonBox.Ok).setText('Continue' if require_available else 'Save')
    def values(self):
        from .mount_settings import validate_settings
        return validate_settings(dict(mount_point=self.point.text().strip(), volume_label=self.label.text().strip()))
    def accept(self):
        from .mount_settings import available_point
        from .windows import VaultError
        try:
            value = self.values()
            if self.require_available: available_point(value['mount_point'], self.record['path'])
        except (VaultError, ValueError) as error:
            QMessageBox.warning(self, 'Check Mount Settings', str(error)); return
        super().accept()


def next_passkey_name(record):
    numbers = [0]
    for label in record.get('devices', {}).values():
        match = re.fullmatch(r'Passkey\s+([0-9]+)', label.get('name', '').strip(), re.IGNORECASE)
        if match:
            numbers.append(int(match[1]))
    return f'Passkey {max(numbers) + 1}'


class AuthDialog(Form):
    def __init__(self, title, devices, parent=None, *, record=None, create=False, only_device=None,
                 recovery=True, new_key=False, mount=False, exclude_device=None, exclude_tags=(), exclude_devices=(), password_only=False):
        super().__init__(title, parent)
        if record: self.note('Vault: ' + record['name'] + '\n' + record['path'])
        self.selector = QComboBox(); self.form.addRow('Unlock with', self.selector)
        authorized = record.get('authorized_keys', []) if record else None
        for device in (() if password_only else devices):
            for slot in device.get('slots', []):
                candidate = dict(serial=device['serial'], slot=slot['slot'], public_key=slot.get('public_key'))
                if not slot.get('age_compatible_candidate'): continue
                if exclude_tags and hashlib.sha256(base64.b64decode(candidate['public_key'])).hexdigest() in exclude_tags: continue
                if exclude_device and all(exclude_device.get(k) == candidate[k] for k in ('serial', 'slot')): continue
                if any(all(d.get(k) == candidate[k] for k in ('serial', 'slot')) for d in exclude_devices): continue
                if authorized is not None:
                    known = any(all(d.get(k) == candidate[k] for k in ('serial','slot','public_key')) for d in authorized)
                    tag = hashlib.sha256(base64.b64decode(candidate['public_key'])).hexdigest()
                    # A fresh signed header takes precedence over previously
                    # displayed device details after authorization changes.
                    authorized_now = tag in record['key_tags'] if 'key_tags' in record else known
                    if not authorized_now: continue
                if only_device and any(only_device.get(k) != candidate[k] for k in ('serial', 'slot', 'public_key')): continue
                self.selector.addItem(f"YubiKey {device['serial']} · PIV {slot['slot']:02X}", candidate)
        if recovery and not new_key and (record is None or record.get('recovery', True)):
            self.selector.addItem('Password', None)
        self.pin = self.text('PIV PIN', secret=True)
        self.pin.setToolTip("Your PIV PIN authorizes use of the private key stored on your YubiKey.")
        self.password = self.text('Password', secret=True)
        self.create = create; self.new_key = new_key
        if create:
            self.confirm = self.text('Confirm password', secret=True)
            self.note("A password is optional with a YubiKey and can also unlock the vault on its own.")
        if new_key: self.note("This uses a key already stored on your YubiKey. Signing and independent unlock testing require separate touches.")
        self.point = MountPicker(record.get('mount_point', '') if record else '') if mount else None
        if self.point:
            self.form.addRow('Mount location', self.point)
            self.note('Choose an available drive letter or an empty folder outside the encrypted vault.')
        if not self.selector.count():
            self.note('This vault does not have a password.' if password_only else 'No compatible authorized key is connected. Connect the correct YubiKey, or open Tools → Manage PIV Keys to check its configuration.')
        self.selector.currentIndexChanged.connect(self.update_fields); self.update_fields()

    def update_fields(self):
        hardware = self.selector.currentData() is not None
        password = self.selector.count() > 0 and not self.new_key and (self.create or not hardware)
        self.pin.setEnabled(hardware)
        self.form.setRowVisible(self.pin, hardware)
        self.password.setEnabled(password)
        self.form.setRowVisible(self.password, password)
        if self.create: self.form.setRowVisible(self.confirm, password)
        self.form.labelForField(self.password).setText('Password')
        self.buttons.button(QDialogButtonBox.Ok).setEnabled(self.selector.count() > 0)
        self.layout.activate(); self.resize(self.width(), self.sizeHint().height())

    def accept(self):
        if self.selector.currentData() is not None and not self.pin.text():
            QMessageBox.information(self, 'Your YubiKey PIN is required', 'Please enter your PIV PIN to continue.'); return
        if self.password.isEnabled() and (not self.selector.currentData() or self.password.text()):
            if not self.password.text(): return
            if self.create and (len(self.password.text()) < 8 or self.password.text() != self.confirm.text()):
                QMessageBox.warning(self, 'Password', 'Enter at least 8 characters and make sure both passwords match.'); return
        if self.point is not None and not self.point.text().strip(): return
        if self.point and self.point.kind.currentIndex() == 0 and self.point.text() not in available_drives():
            QMessageBox.warning(self, 'Drive letter unavailable', 'This drive letter is now in use. Choose another available letter.'); return
        super().accept()

    def values(self):
        result = {}; device = self.selector.currentData()
        if device: result.update(serial=device['serial'], slot=device['slot'], pin=self.pin.text())
        if self.password.isEnabled() and self.password.text(): result['passphrase'] = self.password.text()
        if self.point is not None: result['mount_point'] = self.point.text().strip()
        self.pin.clear(); self.password.clear()
        if self.create: self.confirm.clear()
        return result


def auth(parent, title, **kwargs):
    owner = parent
    while not hasattr(owner, 'devices') or not isinstance(owner.devices, list): owner = owner.parentWidget()
    dialog = AuthDialog(title, owner.devices, parent, **kwargs)
    return dialog.values() if dialog.exec() == QDialog.Accepted else None


class ManageDialog(ModalDialog):
    def __init__(self, window, record):
        super().__init__(window); self.window = window; self.record_id = record['id']; self.record = record
        self.busy = False; self.saving_preferences = False; self.preference_fence = -1
        self.saved_preferences = self.preferences_from(record)
        self.draft_mount_settings = copy.deepcopy(self.saved_preferences['mount_settings'])
        self.setWindowTitle(record['name'] + ' — Manage'); self.resize(760, 480); self.setMinimumWidth(680)
        layout = QVBoxLayout(self); self.tabs = QTabWidget(); layout.addWidget(self.tabs)
        general = QWidget(); general_layout = QVBoxLayout(general)
        form = QFormLayout(); style_form(form); general_layout.addLayout(form)
        self.name = QLineEdit(record['name']); form.addRow('YKA display name', self.name)
        mount_settings = QPushButton('Mount Settings…'); mount_settings.clicked.connect(self.mount_settings); form.addRow('Mount preferences', mount_settings)
        self.readonly_fields = {}
        for title, key in [('UUID', 'uuid'), ('Format', 'mode'), ('Encrypted folder', 'path'), ('State', 'state')]:
            value = str(record.get(key, '')); value = value.capitalize() if key in ('mode', 'state') else value
            label = QLineEdit(value); label.setReadOnly(True); label.setFrame(False); label.setCursorPosition(0); label.setToolTip(value); form.addRow(title, label); self.readonly_fields[key] = label
        size_row = QHBoxLayout()
        self.size_value = QLineEdit(); self.size_value.setReadOnly(True); self.size_value.setFrame(False)
        self.size_refresh = QPushButton('Refresh Size')
        self.size_refresh.setMinimumWidth(self.size_refresh.sizeHint().width() * 2)
        self.size_refresh.clicked.connect(lambda: self.window.refresh_size(self.record_id))
        size_row.addWidget(self.size_value, 1); size_row.addWidget(self.size_refresh)
        form.addRow('Encrypted size', size_row)
        locate = self.locate_button = QPushButton('Locate Moved Vault…'); locate.clicked.connect(self.locate)
        move = self.move_button = QPushButton('Move Vault…'); move.clicked.connect(self.move_vault)
        locate.setEnabled(record.get('state') in ('Unmounted', 'Offline'))
        locations = QHBoxLayout(); locations.addWidget(move, 1); locations.addWidget(locate, 1)
        form.addRow('Location', locations)
        self.finish_move_button = QPushButton('Finish Move')
        self.finish_move_button.clicked.connect(lambda: self.submit('recover-move'))
        form.addRow(self.finish_move_button)
        self.move_hint = QLabel(); self.move_hint.setWordWrap(True); form.addRow(self.move_hint)
        self.recover_button = QPushButton('Recover Mount…')
        self.recover_button.setToolTip('Unmount this vault after its mount supervisor stops unexpectedly.')
        self.recover_button.clicked.connect(lambda: self.window.recover_mount(self.record, origin=self))
        form.addRow('Mount recovery', self.recover_button)
        self.recover_hint = QLabel(); self.recover_hint.setWordWrap(True); self.recover_hint.setTextFormat(Qt.PlainText); form.addRow(self.recover_hint)
        self.delete_button = QPushButton('Delete Vault…')
        self.delete_button.clicked.connect(self.delete_vault)
        form.addRow('Vault deletion', self.delete_button)
        general_layout.addStretch()
        self.tabs.addTab(general, 'General')
        security = QWidget(); sl = QVBoxLayout(security)
        self.keys = QTableWidget(0, 5); self.keys.setHorizontalHeaderLabels(['Name', 'Device / Slot', 'Key ID', 'Connected', 'Unlock Test'])
        self.keys.setHorizontalHeader(AdjacentHeader(self.keys))
        style_table(self.keys)
        self.keys.setSelectionBehavior(QAbstractItemView.SelectRows); self.keys.setSelectionMode(QAbstractItemView.SingleSelection)
        self.keys.setEditTriggers(QAbstractItemView.NoEditTriggers); self.keys.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        for column, width in enumerate((130, 180, 180, 100, 100)): self.keys.setColumnWidth(column, width)
        self.keys.horizontalHeader().setStretchLastSection(True)
        sl.addWidget(self.keys)
        self.test_unlock_button = QPushButton('Unlock…')
        self.test_unlock_button.clicked.connect(self.unlock_or_test_key); sl.addWidget(self.test_unlock_button)
        row = QHBoxLayout(); sl.addLayout(row)
        self.key_buttons = {}
        for label, handler in [('Add Key…', self.add_key), ('Rename…', self.rename_key), ('Remove Authorization…', self.revoke), ('Key Details…', self.key_details)]:
            button = QPushButton(label); button.clicked.connect(handler); row.addWidget(button); self.key_buttons[label] = button
        self.keys.itemSelectionChanged.connect(self.key_selection_changed)
        self.tabs.addTab(security, 'Authorized Keys')
        recovery = QWidget(); rl = QVBoxLayout(recovery)
        self.recovery_status = QLabel('Password: ' + ('Enabled' if record.get('recovery') else 'Disabled')); rl.addWidget(self.recovery_status)
        self.password_buttons = []
        for label, handler in [('Set / change password…', self.set_recovery), ('Remove password…', self.remove_recovery)]:
            b = QPushButton(label); b.clicked.connect(handler); rl.addWidget(b); self.password_buttons.append(b)
        self.password_test_button = QPushButton('Unlock Test…')
        self.password_test_button.clicked.connect(self.test_password); rl.addWidget(self.password_test_button)
        rl.addStretch(); self.tabs.addTab(recovery, 'Password')
        backup = QWidget(); bl = QVBoxLayout(backup)
        self.export_button = QPushButton('Export Backup…'); self.export_button.clicked.connect(lambda: self.window.vault_operation('export', self.record, origin=self)); bl.addWidget(self.export_button)
        self.restore_button = QPushButton('Restore Backup…'); self.restore_button.clicked.connect(lambda: self.window.vault_operation('restore-backup', self.record, origin=self)); bl.addWidget(self.restore_button)
        bl.addStretch(); self.tabs.addTab(backup, 'Backup')
        safety = QWidget(); safety_layout = QVBoxLayout(safety)
        self.auto_unmount = QCheckBox('Unmount when Windows locks or sleeps')
        self.auto_unmount.setChecked(record.get('auto_unmount', True)); safety_layout.addWidget(self.auto_unmount)
        safety_layout.addStretch(); self.tabs.addTab(safety, 'Security')
        self.notice = QLabel(); self.notice.setWordWrap(True); self.notice.setTextFormat(Qt.PlainText); layout.addWidget(self.notice)
        footer = QHBoxLayout(); layout.addLayout(footer)
        self.save_button = QPushButton('Save'); self.save_button.clicked.connect(self.save_preferences)
        self.close_button = QPushButton('Close'); self.close_button.clicked.connect(self.reject)
        footer.addStretch(); footer.addWidget(self.save_button); footer.addWidget(self.close_button)
        # Management actions are explicit choices, not a dialog-wide Enter action.
        for button in self.findChildren(QPushButton):
            button.setAutoDefault(False); button.setDefault(False)
        self.name.textChanged.connect(lambda: self.preferences_edited(clear_notice=True))
        self.auto_unmount.toggled.connect(lambda: self.preferences_edited(clear_notice=True))
        self.populate()
        self.window.controller.result.connect(self.updated)
        if hasattr(self.window.controller, 'changed'): self.window.controller.changed.connect(self.key_selection_changed)
        if hasattr(self.window, 'sizes'): self.window.sizes.changed.connect(self.refresh_size_view)
        self.refresh_size_view()

    def refresh_size_view(self):
        from .vault_size import display
        records = getattr(getattr(self.window, 'model', None), 'records', [])
        record = next((r for r in records if r['id'] == self.record_id), self.record)
        text, detail = display(record)
        self.size_value.setText(text); self.size_value.setToolTip(detail)
        self.size_refresh.setEnabled(not self.busy and not self.window.controller.busy and not getattr(self.window, 'worker_dead', False)
            and record.get('state') in ('mounted', 'Unmounted') and record.get('size_status') != 'calculating')

    @staticmethod
    def preferences_from(record):
        settings = copy.deepcopy(record.get('mount_settings'))
        if settings is not None: settings.setdefault('unlock', {'method': 'automatic'})
        return dict(name=record['name'], auto_unmount=record.get('auto_unmount', True),
                    mount_settings=settings)

    def preference_values(self):
        return dict(name=self.name.text().strip(), auto_unmount=self.auto_unmount.isChecked(),
                    mount_settings=copy.deepcopy(self.draft_mount_settings))

    def dirty_preferences(self):
        return {key: value for key, value in self.preference_values().items() if value != self.saved_preferences[key]}

    def preferences_edited(self, *, clear_notice=False):
        if clear_notice: self.notice.clear()
        self.save_button.setEnabled(bool(self.dirty_preferences()) and not self.busy
            and not self.window.controller.busy and not getattr(self.window, 'worker_dead', False)
            and not self.record.get('delete_transaction'))

    def sync_preferences(self, record, *, saved=False):
        dirty = self.dirty_preferences(); values = self.preferences_from(record)
        self.saved_preferences = values
        if saved or 'name' not in dirty: self.name.setText(values['name'])
        if saved or 'auto_unmount' not in dirty: self.auto_unmount.setChecked(values['auto_unmount'])
        if saved or 'mount_settings' not in dirty: self.draft_mount_settings = copy.deepcopy(values['mount_settings'])
        self.preferences_edited()

    def save_preferences(self):
        if not self.save_button.isEnabled(): return
        self.saving_preferences = True; self.notice.setText('Saving changes…')
        accepted = self.window.submit(dict(action='preferences', record_id=self.record_id, **self.dirty_preferences()), origin=self)
        if accepted is False:
            self.saving_preferences = False; self.notice.setText('Changes could not be saved.')

    def set_busy(self, busy):
        self.busy = busy; self.tabs.setEnabled(not busy); self.close_button.setEnabled(not busy)
        self.key_selection_changed()

    def operation_feedback(self, action, message, *, failed, result=None, context=None):
        if action != 'preferences' or not self.saving_preferences: return False
        self.saving_preferences = False
        if failed:
            self.notice.setText('Changes could not be saved.')
            show_error(self, action, self.notice.text())
        else:
            # A status request sent during Save can finish after its result.
            # Only subsequent polls may replace the acknowledged preferences.
            self.preference_fence = max(self.preference_fence, (context or {}).get('id', -1),
                getattr(self.window.controller, 'counter', -1))
            record = result['record']; self.record = dict(self.record, **record)
            self.sync_preferences(record, saved=True)
            self.setWindowTitle(record['name'] + ' — Manage')
            self.notice.setText('Changes saved.')
        return True

    def updated(self, action, result, context):
        if not self.isVisible(): return
        if action == 'preferences' and context.get('record_id') == self.record_id:
            self.preference_fence = max(self.preference_fence, context.get('id', -1))
        if action in ('list', 'status'):
            record = next((r for r in result.get('records', []) if r['id'] == self.record_id), None)
            if not record: self.close(); return
            if record != self.record:
                size_fields = {'size_cache', 'size_revision', 'size_status', 'size_error'}
                details_changed = ({k:v for k,v in record.items() if k not in size_fields} !=
                    {k:v for k,v in self.record.items() if k not in size_fields})
                if not self.saving_preferences and context.get('id', 0) > self.preference_fence:
                    self.sync_preferences(record)
                self.record = record
                if details_changed: self.populate()
                for key, field in self.readonly_fields.items():
                    value = str(record.get(key, '')); field.setText(value); field.setToolTip(value); field.setCursorPosition(0)
                self.recovery_status.setText('Password: ' + ('Enabled' if record.get('recovery') else 'Disabled'))
            self.refresh_size_view()
        elif action == 'inspect': self.populate()

    def populate(self):
        self.keys.clearSelection(); self.keys.setSortingEnabled(False)
        entries = self.record.get('authorized_keys', []); self.keys.setRowCount(len(entries))
        for row, key in enumerate(entries):
            label = self.record.get('devices', {}).get(key['public_key'], {})
            connected = next((s for d in self.window.devices if d['serial'] == key['serial'] for s in d['slots'] if s['slot'] == key['slot'] and s.get('public_key') == key['public_key']), None)
            fingerprint = hashlib.sha256(base64.b64decode(key['public_key'])).hexdigest().upper()
            values = [label.get('name', 'YubiKey'), f"{key['serial']} / {key['slot']:02X}", fingerprint[:8] + '…' + fingerprint[-4:],
                'Yes' if connected else 'No',
                'Yes' if label.get('tested_generation') == self.record.get('generation') and label.get('tested_generation') is not None else 'No']
            for column, value in enumerate(values):
                item = QTableWidgetItem(value); item.setToolTip(fingerprint if column == 2 else value); item.setData(Qt.UserRole, dict(key))
                if column >= 3: item.setTextAlignment(Qt.AlignCenter)
                self.keys.setItem(row, column, item)
        self.keys.setSortingEnabled(True); self.key_selection_changed()

    def key_details(self):
        key = self.selected_key()
        if key: KeyDetails(key, self).exec()

    def selected_key(self):
        selected = self.keys.selectionModel().selectedRows()
        if not selected: return None
        key = self.keys.item(selected[0].row(), 0).data(Qt.UserRole)
        return key if key in self.record.get('authorized_keys', []) else None

    def key_selection_changed(self):
        self.refresh_size_view()
        key = self.selected_key()
        available = not (self.busy or self.window.controller.busy or getattr(self.window, 'worker_dead', False)
            or getattr(self.window, 'hardware_busy', False))
        ready = available and not getattr(self.window, 'security_unconfirmed', False)
        self.preferences_edited()
        self.recover_button.setEnabled(available and self.record.get('trusted', False) and self.record.get('state') in RECOVERY_STATES)
        self.recover_button.setText('Clean Up' if self.record.get('state') == 'unmounted-awaiting-cleanup' else 'Recover Mount…')
        self.recover_hint.setText(recovery_hint(self.record))
        self.recover_hint.setVisible(bool(self.recover_hint.text()))
        moving = bool(self.record.get('move_transaction'))
        state = self.record.get('state')
        idle = state in ('Unmounted', 'Verification pending')
        test_ready = ready and not moving and (idle or state == 'mounted')
        self.password_test_button.setEnabled(test_ready and self.record.get('recovery', False))
        self.export_button.setEnabled(ready and idle and not moving)
        self.restore_button.setEnabled(ready and state == 'Unmounted' and self.record.get('trusted', False) and not moving)
        self.delete_button.setEnabled(ready and state in ('Unmounted', 'Deletion incomplete')
            and self.record.get('trusted', False) and not moving and not self.record.get('restore_transaction'))
        self.delete_button.setText('Retry Deletion' if self.record.get('delete_transaction') else 'Delete Vault…')
        self.delete_button.setToolTip('' if self.delete_button.isEnabled() else
            'Unmount this vault and finish any pending operations before deleting it.')
        self.move_button.setEnabled(ready and self.record.get('state') == 'Unmounted' and self.record.get('trusted', False) and not moving)
        self.locate_button.setEnabled(ready and self.record.get('state') in ('Unmounted', 'Offline', 'Identity changed') and not moving)
        self.finish_move_button.setVisible(moving); self.finish_move_button.setEnabled(ready)
        self.finish_move_button.setText('Finish Move' if (self.record.get('move_transaction') or {}).get('committed') else 'Recover Move')
        self.move_hint.setText('The new copy is verified. Finish checking and removing the remaining original copies before using this vault.'
            if (self.record.get('move_transaction') or {}).get('committed') else 'The original vault was kept. Recover Move removes the incomplete copy so you can retry.')
        self.move_hint.setVisible(moving)
        connected = bool(key and any(d['serial'] == key['serial'] and any(s['slot'] == key['slot'] and s.get('public_key') == key['public_key'] for s in d['slots']) for d in self.window.devices))
        metadata_available = self.record.get('metadata_available', bool(self.record.get('authorized_keys')))
        self.test_unlock_button.setText('Unlock Test…' if metadata_available else 'Unlock…')
        self.test_unlock_button.setEnabled(test_ready and (not metadata_available or connected))
        password_ready = ready and idle and not moving and self.record.get('trusted', False)
        self.password_buttons[0].setEnabled(password_ready)
        self.password_buttons[1].setEnabled(password_ready and self.record.get('recovery', False) and bool(self.record.get('authorized_keys')))
        for button in self.password_buttons:
            button.setToolTip('' if idle else 'Unmount this vault to change password settings.')
        for label, button in self.key_buttons.items():
            enabled = ready and (label == 'Add Key…' or bool(key))
            if label in ('Add Key…', 'Remove Authorization…'): enabled = enabled and password_ready
            if label == 'Remove Authorization…': enabled = enabled and (len(self.record.get('authorized_keys', [])) > 1 or self.record.get('recovery', False))
            button.setEnabled(enabled)

    def mount_settings(self):
        record = dict(self.record, name=self.name.text().strip())
        if self.draft_mount_settings is not None: record['mount_settings'] = self.draft_mount_settings
        dialog = MountSettingsDialog(record, self)
        dialog.buttons.button(QDialogButtonBox.Ok).setText('OK')
        if dialog.exec() == QDialog.Accepted:
            self.name.setText(dialog.name.text().strip()); self.draft_mount_settings = dialog.values()
            self.preferences_edited(clear_notice=True)

    def submit(self, action, **values):
        self.window.submit(dict(action=action, record_id=self.record_id, **values), origin=self)

    def permission(self, title, **kwargs): return auth(self, title, record=self.record, **kwargs)

    def authorize(self, request, title, *, origin=None, close_on_success=False, notify_success=True, **options):
        origin = origin or self
        request = dict(record_id=self.record_id, **request)
        record = copy.deepcopy(self.record)
        def checked(info):
            credentials = auth(origin, title, record=dict(record, **info), **options)
            if credentials is not None:
                self.window.submit(dict(request, **credentials), origin=origin, close_on_success=close_on_success, notify_success=notify_success)
        return self.window.before_auth(request, origin, checked)

    def delete_vault(self):
        if not self.delete_button.isEnabled(): return
        record = copy.deepcopy(self.record)
        dialog = Form('Delete Vault', self)
        for label, value in [('Vault name', record['name']), ('Encrypted folder', record['path'])]:
            field = dialog.text(label, value); field.setReadOnly(True); field.setCursorPosition(0)
        dialog.note('This will permanently delete this vault’s encrypted folder and its saved records from this computer. This cannot be undone.')
        confirmed = QCheckBox('I understand')
        dialog.form.addRow(confirmed)
        proceed = dialog.buttons.button(QDialogButtonBox.Ok); proceed.setText('Continue'); proceed.setEnabled(False)
        confirmed.toggled.connect(proceed.setEnabled)
        if dialog.exec() != QDialog.Accepted: return
        request = dict(action='delete-vault', record_id=record['id'], confirmed=True,
            expected_path=record['path'], expected_uuid=record['uuid'], expected_public=record['signing_public'])
        if (record.get('delete_transaction') or {}).get('phase') == 'finalizing':
            self.window.submit(request, origin=self, close_on_success=True); return
        def checked(info):
            authorization = AuthDialog('Authorize Deletion', self.window.devices, self, record=record)
            authorization.note('Unlock this vault to confirm deletion.')
            authorization.buttons.button(QDialogButtonBox.Ok).setText('Delete Vault')
            if authorization.exec() != QDialog.Accepted: return
            credentials = authorization.values()
            self.window.submit(dict(request, **credentials), origin=self, close_on_success=True)
        self.window.before_auth(request, self, checked)

    def reject(self):
        if self.can_close(): super().reject()

    def can_close(self):
        if self.busy or self.window.owns_operation(self):
            self.window.task_dialog.raise_(); return False
        if not self.dirty_preferences(): return True
        return QMessageBox.question(self, 'Unsaved Changes', 'You have unsaved changes. Discard them and close?',
            QMessageBox.Cancel | QMessageBox.Discard, QMessageBox.Cancel) == QMessageBox.Discard

    def closeEvent(self, event):
        if self.can_close(): QDialog.reject(self); event.accept()
        else: event.ignore()

    def locate(self):
        dialog = Form('Locate Moved Vault', self)
        dialog.note('Vault: ' + self.record['name'])
        field = QLineEdit(); row = QHBoxLayout(); row.addWidget(field)
        browse = QPushButton('Browse…'); row.addWidget(browse)
        dialog.form.addRow('New vault key file (.yka-key)', row)
        def choose():
            path, _ = QFileDialog.getOpenFileName(dialog, 'Select Vault Key File at New Location', '', 'Vault key (.yka-key);;All files (*)')
            if path: field.setText(path)
        browse.clicked.connect(choose)
        ok = dialog.buttons.button(QDialogButtonBox.Ok); ok.setText('Update'); ok.setEnabled(False)
        field.textChanged.connect(lambda text: ok.setEnabled(bool(text.strip()) and not dialog.busy))
        def submit():
            path = field.text().strip()
            if not path: return
            if Path(path).name.casefold() != '.yka-key':
                show_error(dialog, 'relocate', 'Select the .yka-key file inside your encrypted vault folder.'); return
            self.authorize(dict(action='relocate', new_path=str(Path(path).parent)), 'Verify Moved Vault', origin=dialog, close_on_success=True)
        dialog.submit_handler = submit; dialog.adjustSize(); dialog.exec()

    def move_vault(self):
        dialog = Form('Move Vault', self)
        dialog.note('Vault: ' + self.record['name'] + '\n' + self.record['path'])
        destination = dialog.folder('New vault folder', new=True, leaf=Path(self.record['path']).name)
        dialog.buttons.button(QDialogButtonBox.Ok).setText('Move')
        def submit():
            if not destination.text().strip(): return
            self.authorize(dict(action='move-vault', destination=destination.text().strip()), 'Authorize Vault Move', origin=dialog, close_on_success=True)
        dialog.submit_handler = submit; dialog.adjustSize(); dialog.exec()

    def add_key(self):
        dialog = Form('Add Key — Use Existing PIV Key', self); name = dialog.text('Device name', next_passkey_name(self.record))
        def submit():
            request = dict(action='add-device', record_id=self.record_id, device_name=name.text())
            def checked(info):
                new = auth(dialog, 'Select Existing PIV Key', recovery=False, new_key=True,
                    exclude_tags=info.get('key_tags', ()), exclude_devices=info.get('exclude_devices', ()))
                if new is None: return
                credentials = auth(dialog, 'Authorize Key Change', record=dict(self.record, **info))
                if credentials is None: new.clear(); return
                self.window.submit(dict(request, **credentials, new_serial=new['serial'], new_slot=new['slot'], new_pin=new['pin']),
                    origin=dialog, close_on_success=True)
                credentials.clear(); new.clear()
            self.window.before_auth(request, dialog, checked)
        dialog.submit_handler = submit; dialog.exec()

    def unlock_or_test_key(self):
        if not self.test_unlock_button.isEnabled(): return
        if self.record.get('metadata_available', bool(self.record.get('authorized_keys'))):
            self.test_key()
        else:
            self.authorize(dict(action='test-unlock'), 'Unlock Vault', notify_success=False)

    def test_password(self):
        if self.password_test_button.isEnabled():
            self.authorize(dict(action='test-unlock'), 'Test Password', password_only=True)

    def test_key(self):
        key = self.selected_key()
        if not key: return
        self.authorize(dict(action='test-unlock'), 'Independent key test', only_device=key, recovery=False)

    def rename_key(self):
        key = self.selected_key()
        if not key: return
        dialog = Form('Device name', self); name = dialog.text('Name', self.record.get('devices', {}).get(key['public_key'], {}).get('name', 'YubiKey'))
        dialog.submit_handler = lambda: self.window.submit(dict(action='device-label', record_id=self.record_id, public_key=key['public_key'], name=name.text()), origin=dialog, close_on_success=True)
        dialog.exec()

    def revoke(self):
        key = self.selected_key()
        if not key: return
        if len(self.record.get('authorized_keys', [])) == 1 and not self.record.get('recovery'):
            QMessageBox.warning(self, 'Unlock method required', 'This is the last unlock method. Add and successfully test another key or password before removing it.'); return
        if QMessageBox.warning(self, 'Revoke key', 'Remove this key’s authorization for the current vault?', QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes: return
        self.authorize(dict(action='remove-device', remove_serial=key['serial'], remove_slot=key['slot']),
            'Use a surviving unlock method', exclude_device=key)

    def set_recovery(self):
        if not self.password_buttons[0].isEnabled(): return
        self.window.before_auth(dict(action='set-recovery', record_id=self.record_id), self, lambda _: self._set_recovery())

    def _set_recovery(self):
        dialog = Form('Password', self)
        current = dialog.text('Current password', secret=True) if self.record.get('recovery') else None
        password = dialog.text('New password', secret=True); confirm = dialog.text('Confirm password', secret=True)
        def submit():
            if len(password.text()) < 8 or password.text() != confirm.text():
                QMessageBox.warning(dialog, 'Check Password', 'Enter at least 8 characters and make sure both passwords match.'); return
            if current is not None:
                if not current.text():
                    QMessageBox.warning(dialog, 'Current Password Required', 'Enter your current password to change it.'); return
                credentials = {'passphrase': current.text()}; current.clear()
            else:
                credentials = auth(dialog, 'Authorize Password Change', record=self.record, recovery=False)
            if credentials is None: return
            value = password.text(); password.clear(); confirm.clear()
            self.window.submit(dict(action='set-recovery', record_id=self.record_id, new_passphrase=value, **credentials), origin=dialog, close_on_success=True)
            credentials.clear()
        dialog.submit_handler = submit; dialog.exec()

    def remove_recovery(self):
        if not self.password_buttons[1].isEnabled(): return
        if not self.record.get('authorized_keys'):
            QMessageBox.warning(self, 'Unlock method required', 'Add and test a YubiKey first.'); return
        if QMessageBox.question(self, 'Remove password', 'Remove password authentication for this vault?') != QMessageBox.Yes: return
        self.authorize(dict(action='remove-recovery'), 'Verify surviving YubiKey', recovery=False)


class KeyDetails(Form):
    def __init__(self, key, parent=None):
        super().__init__('Advanced Key Details', parent)
        values = {k: v for k, v in key.items() if k not in ('certificate', 'envelope')}
        if key.get('public_key'): values['fingerprint'] = hashlib.sha256(base64.b64decode(key['public_key'])).hexdigest()
        text = QTextEdit(); text.setReadOnly(True); text.setPlainText(json.dumps(values, indent=2)); self.form.addRow(text)
        copy = QPushButton('Copy Full Details'); copy.clicked.connect(lambda: QApplication.clipboard().setText(text.toPlainText())); self.form.addRow(copy)


class KeyCreationTask(QThread):
    progress = Signal(str)
    completed = Signal(object, str)
    def __init__(self, credentials, parent): super().__init__(parent); self.credentials = credentials
    def run(self):
        from .piv_setup import create_key, replace_key
        from .windows import VaultError
        journal = task = None
        try:
            from .tasks import Tasks
            from .registry import Registry
            journal = Tasks(Registry().directory)
            task = journal.start('piv-replace' if 'expected_public' in self.credentials else 'piv-create',
                serial=self.credentials.get('serial'), slot=self.credentials.get('slot'))
            operation = replace_key if 'expected_public' in self.credentials else create_key
            result = operation(**self.credentials, progress=self.progress.emit)
            journal.finish(task, 'Completed', 'The selected key was created and checked.')
            self.completed.emit(result, '')
        except Exception as error:
            message = str(error) if isinstance(error, VaultError) else "The key operation stopped. Inspect the device before retrying."
            if task:
                try: journal.finish(task, 'Needs attention', message)
                except Exception: pass  # The durable Running record remains for recovery.
            self.completed.emit(None, message)
        finally: self.credentials.clear()


class NewKeyDialog(Form):
    def __init__(self, device, slot, parent, *, replacing=False):
        super().__init__('Replace Existing PIV Key' if replacing else 'Create a New PIV Key', parent)
        self.device = dict(device); self.slot = dict(slot); self.task = None; self.replacing = replacing
        self.progress_dialog = TaskDialog(self, lambda: None, cancellable=False)
        self.window = parent.window
        self.target_text = f"YubiKey {device['serial']} · Slot {slot['slot']:02X}"
        self.note(self.target_text)
        if replacing:
            self.fingerprint = hashlib.sha256(base64.b64decode(slot['key_public_der'])).hexdigest()
            visible_id = hashlib.sha256(base64.b64decode(slot.get('public_key') or slot['key_public_der'])).hexdigest()
            self.note('Existing key ID: ' + visible_id.upper())
            dependencies = [r['name'] + ' — ' + r['path'] for r in self.window.model.records
                if any(k['serial'] == device['serial'] and k['slot'] == slot['slot'] and k.get('public_key') == slot.get('public_key')
                    for k in r.get('authorized_keys', []))]
            text = QTextEdit(); text.setReadOnly(True); text.setMaximumHeight(100)
            text.setPlainText('Known registered vaults using this key:\n' + ('\n'.join(dependencies) or 'No dependencies were found in the current list.'))
            self.form.addRow(text)
            self.confirm_text = 'CONFIRM REPLACEMENT'
            self.note(f'Type "{self.confirm_text}" to confirm replacement.')
            self.typed = QLineEdit(); self.form.addRow(self.typed)
        else: self.note("Create a P-256 private key in this confirmed empty slot.")
        self.note('You can change your PIV PIN, PUK, and management key using Yubico Authenticator.')
        self.pin = self.text('PIV PIN', secret=True)
        self.pin.setToolTip('The PIV PIN permits access to your private keys and PIN-protected management credentials.')
        self.mode = QComboBox(); self.mode.addItems(['Protect with PIN (recommended)', 'Enter management key manually'])
        self.form.addRow('Management authorization', self.mode)
        self.management = self.text('Management key (hex)', secret=True)
        self.management.setToolTip('This device-wide credential authorizes key creation and replacement. It is not your PIN.')
        self.mode.currentIndexChanged.connect(self.management_mode); self.management_mode()
        self.status = QLabel(); self.status.setWordWrap(True); self.form.addRow(self.status)
        self.bar = QProgressBar(); self.bar.setRange(0, 0); self.bar.hide(); self.form.addRow(self.bar)
        self.buttons.button(QDialogButtonBox.Ok).setText('Replace' if replacing else 'Review and Create')

    def management_mode(self):
        manual = self.mode.currentIndex() == 1
        self.form.setRowVisible(self.management, manual)
        if not manual: self.management.clear()

    def accept(self):
        if self.task: return
        if not self.pin.text(): self.status.setText('Please enter your PIV PIN.'); return
        if self.replacing and self.typed.text() != self.confirm_text:
            self.status.setText(f'Enter "{self.confirm_text}" to continue.'); return
        try: key = bytes.fromhex(self.management.text().strip()) if self.mode.currentIndex() else b''
        except ValueError: self.status.setText('Enter the management key as hexadecimal characters.'); return
        if self.mode.currentIndex() and len(key) not in (16, 24, 32):
            self.status.setText('Enter a management key of the correct length for your device.'); return
        if self.replacing:
            warnings = [('Permanently Replace Private Key', self.target_text + '\nThe old private key will be permanently lost. It cannot be restored. Continue?'),
                ('Dependent Data May Become Inaccessible', 'Vaults, historical backups and other applications that depend on this private key may become permanently inaccessible. YKA cannot verify all dependencies. Have you tested an independent recovery method and do you want to replace this exact key?')]
        else: warnings = [('Create PIV Key', self.target_text + '\nCreate a new key and certificate in this empty slot?')]
        for title, warning in warnings:
            if QMessageBox.warning(self, title, warning, QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes: return
        credentials = dict(serial=self.device['serial'], slot=self.slot['slot'], pin=self.pin.text(), management_key=key,
            confirmation=f"YKA-NEW-KEY:{self.device['serial']}:{self.slot['slot']:02X}")
        if self.replacing:
            credentials.update(expected_public=self.slot['key_public_der'],
                confirmation=f"YKA-REPLACE-KEY:{self.device['serial']}:{self.slot['slot']:02X}:{self.fingerprint}")
        self.pin.clear(); self.management.clear(); key = None
        self.outcome = (None, 'The key operation did not return a result.')
        self.task = KeyCreationTask(credentials, self); self.task.progress.connect(self.key_progress)
        self.task.completed.connect(self.finished_key)
        self.task.finished.connect(self.refresh_after_write)
        self.window.hardware_busy = True
        if hasattr(self.window, 'update_actions'): self.window.update_actions(); self.window.execution_state()
        self.buttons.setEnabled(False); self.bar.show()
        self.progress_dialog.begin('Replacing PIV Key' if self.replacing else 'Creating PIV Key')
        self.task.start()

    def key_progress(self, message):
        self.status.setText(message); self.progress_dialog.update_message(message)
        self.progress_dialog.present(attention=True)

    def refresh_after_write(self):
        self.progress_dialog.hide()
        result, error = getattr(self, 'outcome', (None, 'The key operation did not return a result.'))
        self.task = None
        self.window.hardware_busy = False; self.window.refresh_devices()
        if hasattr(self.window, 'update_actions'): self.window.update_actions(); self.window.execution_state()
        self.bar.hide(); self.buttons.setEnabled(True)
        if result and not error:
            parent = self.parentWidget()
            parent.pending_slot = (result['serial'], result['slot'])
            parent.notice.setText(f"The new key in slot {result['slot']:02X} was verified. Refreshing the device list…")
            QDialog.accept(self)
            show_result(parent, 'piv-replace' if self.replacing else 'piv-create', 'Key created and tested.')
        else:
            self.status.setText(error)
            self.buttons.button(QDialogButtonBox.Ok).setText('Replace' if self.replacing else 'Review and Retry')
            show_error(self, 'piv-replace' if self.replacing else 'piv-create', error)

    def finished_key(self, result, error):
        self.outcome = (result, error)
        # UI completion waits for QThread.finished, including credential cleanup.

    def reject(self):
        if self.task and self.task.isRunning():
            self.status.setText('Please wait for the hardware operation to finish. It cannot safely be cancelled after writing starts.'); return
        super().reject()
    def closeEvent(self, event):
        if self.task and self.task.isRunning(): self.reject(); event.ignore()
        else: event.accept()


class DeviceDialog(ModalDialog):
    def __init__(self, window):
        super().__init__(window); self.window = window; self.setWindowTitle('Manage PIV Keys'); self.resize(800, 520); self.setMinimumWidth(680)
        layout = QVBoxLayout(self)
        self.devices = QComboBox(); layout.addWidget(self.devices)
        self.notice = QLabel(); self.notice.setWordWrap(True); layout.addWidget(self.notice)
        info = QLabel('You can change your PIV PIN, PUK, and management key using Yubico Authenticator.'); info.setWordWrap(True); layout.addWidget(info)
        self.table = QTableWidget(0, 5); self.table.setHorizontalHeaderLabels(['Slot', 'Status', 'Key ID', 'PIN / Touch', 'Origin'])
        style_table(self.table); self.table.setHorizontalHeader(AdjacentHeader(self.table))
        for column, width in enumerate((65, 170, 180, 150, 170)): self.table.setColumnWidth(column, width)
        layout.addWidget(self.table)
        self.guidance = QLabel(); self.guidance.setWordWrap(True); layout.addWidget(self.guidance)
        row = QHBoxLayout(); layout.addLayout(row)
        self.create = QPushButton('Create New Key…'); self.create.clicked.connect(self.create_key); row.addWidget(self.create)
        self.replace = QPushButton('Replace Existing Key…'); self.replace.clicked.connect(self.replace_key); row.addWidget(self.replace)
        self.details_button = QPushButton('Advanced Details…'); self.details_button.clicked.connect(self.details); row.addWidget(self.details_button)
        refresh = QPushButton('Refresh Devices'); refresh.clicked.connect(window.refresh_devices); row.addWidget(refresh)
        self.devices.currentIndexChanged.connect(self.populate)
        self.table.itemSelectionChanged.connect(self.selected_changed)
        window.controller.result.connect(self.updated)
        if hasattr(window.controller, 'changed'): window.controller.changed.connect(self.selected_changed)
        self.load()
        close = QDialogButtonBox(QDialogButtonBox.Close); close.rejected.connect(self.close); layout.addWidget(close)

    def updated(self, action, result, context):
        if action == 'inspect':
            self.load()
            target = getattr(self, 'pending_slot', None)
            if target:
                index = self.devices.findData(target[0])
                if index >= 0: self.devices.setCurrentIndex(index); self.populate()
                for row in range(self.table.rowCount()):
                    if tuple(self.table.item(row, 0).data(Qt.UserRole)) == target:
                        self.table.selectRow(row); self.table.scrollToItem(self.table.item(row, 0)); break
                self.notice.setText(f"The new key in slot {target[1]:02X} was created and verified. Authorize it for a vault under Manage → Authorized Keys → Add Key.")
                self.pending_slot = None

    def load(self):
        selected = self.devices.currentData(); self.devices.blockSignals(True); self.devices.clear()
        for d in self.window.devices: self.devices.addItem(f"YubiKey {d['serial']} · Firmware {d['firmware']}", d['serial'])
        if self.devices.findData(selected) >= 0: self.devices.setCurrentIndex(self.devices.findData(selected))
        self.devices.blockSignals(False); self.populate()

    def device(self): return next((d for d in self.window.devices if d['serial'] == self.devices.currentData()), None)
    def slot(self):
        d = self.device(); selected = self.table.selectionModel().selectedRows()
        if not d or not selected: return None
        serial, number = self.table.item(selected[0].row(), 0).data(Qt.UserRole)
        if serial != d['serial']: return None
        return next((s for s in d['slots'] if s['slot'] == number), None)

    def populate(self):
        d = self.device(); self.table.clearSelection(); self.table.setSortingEnabled(False); self.table.setRowCount(0)
        if not d:
            self.notice.setText('Connect a YubiKey and click Refresh Devices. Inspection does not attempt your PIN or change the device.'); self.selected_changed(); return
        defaults = [name for field, name in [('pin_default', 'PIN'), ('puk_default', 'PUK'), ('management_default', 'management key')] if d.get(field)]
        self.notice.setText('Change these factory-default credentials before creating keys: ' + ', '.join(defaults) + '.' if defaults else
            'These keys are stored on your device. Authorize a key for each vault under Manage → Authorized Keys → Add Key.')
        for slot in d['slots']:
            row = self.table.rowCount(); self.table.insertRow(row)
            state = 'Empty' if slot.get('empty') else 'Unknown' if slot.get('unknown') else 'Compatible' if slot.get('age_compatible_candidate') else 'Not compatible with YKA'
            public = slot.get('public_key') or slot.get('key_public_der')
            fp = hashlib.sha256(base64.b64decode(public)).hexdigest().upper() if public else ''
            values = [f"{slot['slot']:02X}", state, fp[:8] + '…' + fp[-4:] if fp else '—',
                slot.get('pin_policy', 'Unknown') + ' / ' + slot.get('touch_policy', 'Unknown'), slot.get('origin', 'Unknown')]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value); item.setToolTip(fp if col == 2 else value)
                item.setData(Qt.UserRole, (d['serial'], slot['slot'])); self.table.setItem(row, col, item)
        self.table.setSortingEnabled(True); self.selected_changed()

    def selected_changed(self):
        s = self.slot(); d = self.device(); ready = not self.window.controller.busy and not getattr(self.window, 'hardware_busy', False)
        secured = bool(d and not any(d.get(k, True) for k in ('pin_default', 'puk_default', 'management_default')))
        self.create.setEnabled(bool(ready and secured and s and s.get('empty')))
        self.replace.setEnabled(bool(ready and secured and s and not s.get('unknown') and s.get('key_public_der')))
        self.details_button.setEnabled(bool(s))
        self.guidance.setText('Select a slot to view its available actions.' if not s else
            'This slot is confirmed empty. Create a key after securing the device credentials.' if s.get('empty') else
            'The slot state could not be verified. Creating or replacing a key is blocked.' if s.get('unknown') else
            'This key can be authorized for a vault without changing it. Replacing it permanently destroys the existing private key.')

    def create_key(self):
        d, s = self.device(), self.slot()
        if self.create.isEnabled() and d and s: NewKeyDialog(d, s, self).exec()

    def replace_key(self):
        d, s = self.device(), self.slot()
        if self.replace.isEnabled() and d and s: NewKeyDialog(d, s, self, replacing=True).exec()

    def details(self):
        s = self.slot()
        if s: KeyDetails(dict(s, serial=self.devices.currentData()), self).exec()
