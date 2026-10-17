"""Native Qt Widgets vault list; crypto and filesystem work stay in the worker."""
import ctypes
from ctypes import wintypes
from pathlib import Path
import sys
import win32api
import os
from PySide6.QtCore import QLocale, QTimer, Qt, QSortFilterProxyModel, QProcess, QSettings
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTableView, QAbstractItemView, QHeaderView, QMenu, QMessageBox,
    QFileDialog, QDialog, QTextEdit, QComboBox, QCheckBox, QSystemTrayIcon, QStyle)
from .controller import Controller
from .models import VaultModel, VaultActionDelegate
from .mount_recovery import RECOVERY_STATES, REMOVABLE_STATES
from .dialogs import Form, ManageDialog, DeviceDialog, MountSettingsDialog, AddExistingDialog, auth
from .native import PROJECT
from .ui_common import TaskDialog, style_table, show_error, show_result, StatusLabel, TimestampLog, AdjacentHeader
from .appearance import tray_icon, notification_icon, app_settings, SettingsDialog

ctypes.windll.wtsapi32.WTSRegisterSessionNotification.argtypes = [ctypes.c_void_p, wintypes.DWORD]
ctypes.windll.wtsapi32.WTSRegisterSessionNotification.restype = wintypes.BOOL
ctypes.windll.wtsapi32.WTSUnRegisterSessionNotification.argtypes = [ctypes.c_void_p]
ctypes.windll.kernel32.SetThreadExecutionState.argtypes = [wintypes.DWORD]
ctypes.windll.kernel32.SetThreadExecutionState.restype = wintypes.DWORD


class Window(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle('YKA Vault Manager'); self.resize(1060, 480)
        self.setMinimumSize(760, 360)
        self.settings = app_settings()
        # This release changes the old always-on default at the user's request.
        # Subsequent explicit changes in Settings remain persistent.
        if self.settings.value('idle_sleep_policy', 0, type=int) < 2:
            self.settings.setValue('prevent_idle_sleep', False)
            self.settings.setValue('idle_sleep_policy', 2)
        if self.settings.value('geometry'): self.restoreGeometry(self.settings.value('geometry'))
        self.operation_ui = {}; self.devices = []; self.security_unconfirmed = False; self.worker_dead = False; self.close_attempted = False
        self.mount_batch = None
        self.exiting = False; self.allow_close = False; self.shutdown_started = False; self.destination_dialog = None; self.last_result_time = 0
        central = QWidget(); layout = QVBoxLayout(central); self.setCentralWidget(central)
        toolbar = QHBoxLayout(); layout.addLayout(toolbar); self.buttons = []
        for label, handler in [('Create Vault', self.create), ('Add Existing Vault', self.add_existing), ('Import .yka', self.import_archive)]:
            button = QPushButton(label); button.clicked.connect(handler); toolbar.addWidget(button); self.buttons.append(button)
        toolbar.addStretch(); refresh = QPushButton('Refresh'); refresh.clicked.connect(self.refresh_devices); toolbar.addWidget(refresh)
        self.model = VaultModel(self); self.proxy = QSortFilterProxyModel(self); self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(Qt.UserRole + 1)
        self.proxy.setSortCaseSensitivity(Qt.CaseInsensitive)
        self.table = QTableView(); self.table.setModel(self.proxy); self.table.setSortingEnabled(True)
        self.table.setHorizontalHeader(AdjacentHeader(self.table))
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows); self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers); self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False); self.table.setTextElideMode(Qt.ElideMiddle)
        style_table(self.table)
        self.table.verticalHeader().hide(); self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        for i, width in enumerate((100, 55, 180, 95, 180, 210, 100, 85)): self.table.setColumnWidth(i, width)
        self.table.setColumnWidth(self.model.action_column, 90)
        self.table.setColumnHidden(1, True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.row_actions = VaultActionDelegate(lambda: not hasattr(self, 'controller') or self.controller.busy or self.worker_dead, self.table)
        self.table.setItemDelegateForColumn(self.model.action_column, self.row_actions); self.row_actions.triggered.connect(self.row_action)
        self.table.doubleClicked.connect(self.double_click)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu); self.table.customContextMenuRequested.connect(self.context_menu)
        layout.addWidget(self.table)
        row = QHBoxLayout(); layout.addLayout(row)
        self.mount_button = QPushButton('Mount'); self.mount_button.clicked.connect(lambda: self.vault_operation('mount'))
        self.unmount_button = QPushButton('Unmount'); self.unmount_button.clicked.connect(self.selected_unmount)
        self.open_button = QPushButton('Open Folder'); self.open_button.clicked.connect(self.open_folder)
        self.manage_button = QPushButton('Manage…'); self.manage_button.clicked.connect(self.manage)
        for button in (self.mount_button, self.unmount_button, self.open_button, self.manage_button): row.addWidget(button)
        row.addStretch(); self.cancel_button = QPushButton('Cancel task'); self.cancel_button.clicked.connect(lambda: self.controller.cancel()); row.addWidget(self.cancel_button)
        self.state = StatusLabel('Loading vaults…'); layout.addWidget(self.state)
        self.menuBar().setStyleSheet('QMenuBar { padding: 0px; border-bottom: 1px solid palette(mid); } QMenuBar::item { padding: 2px 8px; }')
        self.menu_actions = {}
        menus = {
            'Vault': [('Mount All', self.mount_all, 'mount-all'), ('Unmount All', lambda: self.power_event('unmount-all'), 'unmount-all')],
            'Tools': [('Safe Transfer…', self.safe_transfer, 'transfer'), ('Manage PIV Keys…', self.devices_window, 'piv'), ('Diagnostics…', self.diagnostics, 'diagnostics')],
            'Application': [('Settings…', self.preferences, 'preferences'), ('About', self.about, 'about'), ('Exit', self.request_exit, 'exit')]}
        for title, entries in menus.items():
            menu = self.menuBar().addMenu(title)
            for label, handler, key in entries:
                action = menu.addAction(label); action.triggered.connect(handler); self.menu_actions[key] = action
        self.logs = TimestampLog(); self.logs.setReadOnly(True); self.logs.document().setMaximumBlockCount(1000)
        self.logs_window = QDialog(self); self.logs_window.setWindowTitle('Diagnostics'); self.logs_window.resize(760, 420); self.logs_window.setMinimumWidth(600)
        log_layout = QVBoxLayout(self.logs_window); log_layout.addWidget(self.logs)
        self.controller = Controller(self); self.controller.result.connect(self.completed)
        self.controller.error.connect(self.failed); self.controller.progress.connect(self.task_progress)
        self.controller.destination.connect(self.choose_export_destination)
        self.task_dialog = TaskDialog(self, self.controller.cancel)
        self.controller.changed.connect(self.update_actions); self.controller.changed.connect(self.execution_state); self.controller.stopped.connect(self.worker_stopped)
        self.controller.process.finished.connect(self.worker_finished)
        from .size_controller import SizeController
        self.sizes = SizeController(self); self.sizes.changed.connect(self.size_changed)
        self.table.selectionModel().selectionChanged.connect(self.update_actions)
        self.heartbeat = QTimer(self); self.heartbeat.timeout.connect(self.poll_status); self.heartbeat.start(5000)
        self.device_timer = QTimer(self); self.device_timer.timeout.connect(self.poll_devices); self.device_timer.start(15000)
        self.session_registered = bool(ctypes.windll.wtsapi32.WTSRegisterSessionNotification(int(self.winId()), 0))
        if not self.session_registered: self.logs.append('Lock notifications unavailable. Unmount manually.')
        self.tray = QSystemTrayIcon(notification_icon(self.settings), self)
        self.tray_menu = QMenu(self); self.tray.setContextMenu(self.tray_menu)
        self.setup_tray_menu()
        self.tray_menu.aboutToShow.connect(self.rebuild_tray)
        self.tray.activated.connect(lambda reason: self.show_main() if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick) else None)
        self.tray.show(); self.update_tray()
        QTimer.singleShot(300, self.refresh_devices); self.update_actions()

    def selected(self):
        rows = self.table.selectionModel().selectedRows()
        index = rows[0] if rows else self.proxy.index(-1, -1)
        return dict(self.model.records[self.proxy.mapToSource(index).row()]) if index.isValid() else None

    def owns_operation(self, widget):
        for item in self.operation_ui.values():
            owner = item['origin']
            while owner is not None:
                if owner is widget: return True
                owner = owner.parentWidget()
        return False

    def submit(self, request, *, origin=None, close_on_success=False, on_success=None, notify_success=True):
        origin = origin or self
        if self.controller.busy:
            QMessageBox.information(origin, 'Task in Progress', 'Wait for the current operation to finish, or cancel it before starting another.'); return False
        title = {'preferences': 'Saving changes', 'test-unlock': 'Verifying the selected unlock method', 'export': 'Exporting your vault',
            'delete-vault': 'Delete Vault',
            'restore-backup': 'Authenticating and checking your backup',
            'check-restore-backup': 'Checking the backup identity',
            'check-operation': 'Checking the operation',
            'transfer': 'Safe Transfer', 'move-vault': 'Moving your vault', 'recover-move': 'Finishing the interrupted move',
            'mount': 'Mounting your vault', 'create': 'Creating your vault', 'unmount': 'Safely unmounting your vault',
            'add-device': 'Authorizing a new YubiKey', 'import': 'Authenticating and checking your archive'}.get(request['action'], 'Updating your vault')
        def prepare(context):
            silent = request['action'] == 'preferences'
            self.operation_ui[context['id']] = dict(origin=origin, close_on_success=close_on_success, silent=silent, on_success=on_success,
                notify_success=notify_success)
            if hasattr(origin, 'set_busy'): origin.set_busy(True)
            if silent: return
            # A native Windows dialog must keep one owner for its lifetime.
            # Reparenting this shared dialog before closing a Form can destroy
            # its HWND while Qt still reports isVisible() == True.
            self.task_dialog.hide(); self.task_dialog.deleteLater()
            self.task_dialog = TaskDialog(origin, self.controller.cancel, transfer=request['action'] in ('transfer', 'export', 'restore-backup', 'import'),
                cancellable=request['action'] != 'delete-vault')
            self.state.setText(title + '…'); self.task_dialog.begin(title, authentication_first=request['action'] in ('check-operation', 'check-restore-backup', 'restore-backup', 'import'))
            if request['action'] == 'export':
                self.task_dialog.message.setText('Preparing your backup…'); self.task_dialog.summary.clear()
            elif request['action'] in ('restore-backup', 'import'):
                self.task_dialog.message.setText('Authenticating your vault…'); self.task_dialog.summary.clear()
        self.controller.send(request, before_send=prepare)
        return True

    def before_auth(self, request, origin, callback):
        """Freeze the target before preflight; never retain credentials here."""
        request = dict(request)
        def checked(info):
            from shiboken6 import isValid
            if (not isValid(origin) or not origin.isVisible() or self.worker_dead or self.controller.busy
                or self.security_unconfirmed or self.exiting or self.close_attempted or self.shutdown_started):
                self.mount_batch = None; self.update_actions(); return
            callback(info)
        return self.submit(dict(request, action='check-operation', operation=request['action']), origin=origin, on_success=checked)

    def finish_operation(self, action, context, message, *, failed=False, result=None):
        from shiboken6 import isValid
        item = self.operation_ui.pop(context.get('id'), None)
        if not item: return
        continue_requested = self.task_dialog.cancel_button.isEnabled() or self.task_dialog.committing
        owner = item['origin']
        if not isValid(owner): owner = self
        if not item.get('silent'):
            self.task_dialog.hide(); self.task_dialog.deleteLater()
            self.task_dialog = TaskDialog(self, lambda: self.controller.cancel())
        if hasattr(owner, 'set_busy'): owner.set_busy(False)
        if not failed and item.get('on_success'):
            if continue_requested: item['on_success'](result or {})
            else:
                self.state.setText('The operation was cancelled.')
                if action == 'check-operation': self.mount_batch = None
            return
        if hasattr(owner, 'operation_feedback') and owner.operation_feedback(action, message, failed=failed, result=result, context=context): return
        if not failed and hasattr(owner, 'operation_succeeded'): owner.operation_succeeded(action, result or {})
        cancelled = failed and 'cancelled' in message.lower()
        # Exit already confirms cancellation and waits for safe unmount. An
        # informational modal here would interrupt that shutdown sequence.
        if cancelled and (self.exiting or self.close_attempted or self.shutdown_started): return
        if not failed and item['close_on_success'] and isinstance(owner, QDialog):
            parent = owner.parentWidget(); QDialog.accept(owner); owner = parent or self
        if not failed and item.get('silent'): return
        if not owner.isVisible(): owner = self; self.show_main()
        if hasattr(owner, 'notice'): owner.notice.setText(message)
        owner.raise_(); owner.activateWindow()
        if failed and not cancelled: show_error(owner, action, message)
        elif not failed and (result or {}).get('keyring_cleanup_pending'):
            QMessageBox.warning(owner, 'Keyring Cleanup', message)
        elif owner is not self or action in ('test-unlock', 'export', 'delete-vault') or cancelled:
            if cancelled or item.get('notify_success', True):
                show_result(owner, action, message, cancelled=cancelled)

    def polling_intervals(self):
        visible = (self.isVisible() and not self.isMinimized()) or QApplication.activeModalWidget() is not None
        active = self.controller.busy or self.security_unconfirmed or any(
            r.get('state') not in ('Unmounted', 'Verification pending', 'Offline', 'Deletion incomplete') for r in self.model.records)
        return (5000 if active else 15000 if visible else 30000, 15000 if visible or active else 60000)

    def update_polling(self):
        if not hasattr(self, 'heartbeat'): return
        for timer, interval in zip((self.heartbeat, self.device_timer), self.polling_intervals()):
            if timer.isActive() and timer.interval() != interval: timer.setInterval(interval)

    def poll_status(self):
        self.refresh()
        self.heartbeat.setInterval(self.polling_intervals()[0])

    def poll_devices(self):
        self.refresh_devices()
        self.device_timer.setInterval(self.polling_intervals()[1])

    def refresh(self):
        if not self.worker_dead and not any(v['action'] in ('status', 'list') for v in self.controller.pending.values()):
            self.controller.send({'action': 'list'})
        self.execution_state()

    def size_changed(self):
        for record in self.model.records: self.sizes.decorate(record)
        if self.model.records:
            column = next(i for i, (_, field) in enumerate(self.model.columns) if field == 'size')
            self.model.dataChanged.emit(self.model.index(0, column), self.model.index(len(self.model.records)-1, column))

    def refresh_size(self, record_id):
        if not self.worker_dead: self.sizes.refresh(record_id)

    def refresh_devices(self):
        if not getattr(self, 'hardware_busy', False) and not self.controller.busy and not self.worker_dead and not any(v['action'] == 'inspect' for v in self.controller.pending.values()):
            self.controller.send({'action': 'inspect'}); self.refresh()

    def create(self):
        dialog = Form('Create Vault', self); name = dialog.text('Name', 'My Vault'); root = dialog.folder('Vault folder', new=True, name=name)
        mode = QComboBox(); mode.addItems(['Lite', 'Full']); dialog.form.addRow('Format', mode)
        automatic = QCheckBox('Unmount when Windows locks or sleeps'); dialog.form.addRow(automatic)
        def submit():
            if not root.text().strip(): return
            request = dict(action='create', name=name.text().strip(), root=root.text().strip(), mode=mode.currentText().lower(), auto_unmount=automatic.isChecked())
            def checked(_):
                credentials = auth(dialog, 'Choose Unlock Methods', create=True)
                if credentials is not None: self.submit(dict(request, **credentials), origin=dialog, close_on_success=True)
            self.before_auth(request, dialog, checked)
        dialog.submit_handler = submit; dialog.exec()

    def add_existing(self):
        AddExistingDialog(self).exec()

    def import_archive(self):
        source, _ = QFileDialog.getOpenFileName(self, 'Import .yka', '', 'YKA archive (*.yka)')
        if not source: return
        dialog = Form('Import Archive', self)
        name = dialog.text('Name', Path(source).stem)
        root = dialog.folder('New vault folder', new=True, name=name)
        def submit():
            if not root.text().strip(): return
            request = dict(action='import', archive=source, destination=root.text().strip(), name=name.text().strip(), accept_backup_authorization=True)
            def checked(info):
                if QMessageBox.question(dialog, 'Import Backup',
                    'Import using the keys and password saved in this backup?',
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes: return
                credentials = auth(dialog, 'Unlock Archive', record=dict(name=request['name'], path=source, **info))
                if credentials is not None: self.submit(dict(request, **credentials), origin=dialog, close_on_success=True)
            self.before_auth(request, dialog, checked)
        dialog.submit_handler = submit; dialog.exec()

    def vault_operation(self, action, record=None, *, origin=None, batch=False):
        origin = origin or self
        record = dict(record or self.selected() or {})
        if not record or self.controller.busy: return
        request = dict(action=action, record_id=record['id'])
        if action == 'export' and record.get('state') not in ('Unmounted', 'Verification pending'):
            QMessageBox.information(self, 'Unmount before exporting', 'Please unmount this vault before starting an export.'); return
        if action == 'restore-backup':
            if record.get('state') != 'Unmounted' or not record.get('trusted'):
                QMessageBox.information(origin, 'Unmount before restoring', 'Restore requires an authenticated, unmounted vault.'); return
            source, _ = QFileDialog.getOpenFileName(origin, 'Restore Backup', '', 'YKA archive (*.yka)')
            if not source: return
            def checked(info):
                from shiboken6 import isValid
                if (not isValid(origin) or not origin.isVisible() or self.worker_dead or self.controller.busy
                    or self.security_unconfirmed or self.exiting or self.close_attempted or self.shutdown_started): return
                message = 'Restore this backup? Current vault contents will be permanently replaced, and unlock methods will return to the backup state.'
                if QMessageBox.warning(origin, 'Restore Backup', message, QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes: return
                backup = dict(name=record['name'], path=source, **info)
                credentials = auth(origin, 'Unlock Backup', record=backup)
                if credentials is not None:
                    self.submit(dict(request, archive=source, confirmed=True, **credentials), origin=origin)
            return self.submit(dict(action='check-restore-backup', record_id=record['id'], archive=source), origin=origin, on_success=checked)
        if action == 'mount':
            from .mount_settings import validate_settings, available_point
            from .windows import VaultError
            try:
                config = validate_settings(record.get('mount_settings', {}))
                available_point(config['mount_point'], record['path'])
            except (VaultError, ValueError):
                dialog = MountSettingsDialog(record, self, require_available=True)
                if dialog.exec() != QDialog.Accepted: return
                config = dialog.values(); record['name'] = dialog.name.text().strip() or record['name']
            record['mount_settings'] = config
            request.update(mount_settings=config, name=record['name'])
        if action == 'unmount': return self.submit(request, origin=origin)
        def checked(info):
            if batch and self.mount_batch is None: return
            current = dict(record, **info)
            credentials = auth(origin, 'Mount Vault' if action == 'mount' else 'Authorize operation', record=current)
            if credentials is None:
                if batch: self.mount_batch = None; self.update_actions()
                return
            if batch and self.mount_batch is None: return
            self.submit(dict(request, **credentials), origin=origin)
        if action == 'export':
            def selected(output):
                from shiboken6 import isValid
                if not output or not isValid(origin) or not origin.isVisible(): return
                if self.worker_dead or self.exiting or self.close_attempted or self.shutdown_started or self.security_unconfirmed: return
                request['output'] = output
                self.before_auth(request, origin, checked)
            self.choose_export_destination(dict(action=action, record_id=record['id'], origin=origin, name=record['name']), on_selected=selected)
            return True
        return self.before_auth(request, origin, checked)

    def mount_all(self):
        if self.controller.busy or self.worker_dead or self.mount_batch is not None or getattr(self, 'hardware_busy', False): return
        if self.security_unconfirmed:
            QMessageBox.information(self, 'Check Vault Status', 'Resolve the unconfirmed mount status before using Mount All.'); return
        seen = {r.get('uuid') for r in self.model.records if r.get('state') not in ('Unmounted', 'Verification pending', 'Offline', 'Deletion incomplete') and r.get('uuid')}
        queue = []; skipped = 0
        for record in self.model.records:
            if record.get('state') == 'mounted': continue
            identity = record.get('uuid')
            if record.get('state') not in ('Unmounted', 'Verification pending') or (identity and identity in seen):
                skipped += 1; continue
            queue.append(record['id'])
            if identity: seen.add(identity)
        if not queue:
            QMessageBox.information(self, 'Mount All', 'No available unmounted vaults were found. Offline vaults and duplicate copies are skipped.'); return
        self.show_main()
        self.mount_batch = dict(queue=queue, mounted=0, skipped=skipped, waiting=False)
        self.mount_next()

    def mount_next(self):
        batch = self.mount_batch
        if batch is None: return
        if self.worker_dead or self.security_unconfirmed:
            self.mount_batch = None; self.update_actions(); return
        if self.controller.busy: return
        if not batch['queue']:
            import time
            self.mount_batch = None; self.last_result_time = time.monotonic()
            self.state.setText(f"Mount All finished. {batch['mounted']} vault(s) mounted; {batch['skipped']} unavailable or duplicate copies skipped.")
            self.update_actions(); return
        record_id = batch['queue'].pop(0)
        record = next((dict(r) for r in self.model.records if r['id'] == record_id), None)
        if not record or record.get('state') not in ('Unmounted', 'Verification pending'):
            batch['skipped'] += 1; QTimer.singleShot(0, self.mount_next); return
        if not self.vault_operation('mount', record, batch=True):
            self.state.setText(f"Mount All stopped. {batch['mounted']} vault(s) were mounted; remaining vaults were skipped.")
            self.mount_batch = None; self.update_actions()

    def choose_export_destination(self, context, *, on_selected=None):
        if on_selected is None: self.task_dialog.hide()
        record = next((r for r in self.model.records if r['id'] == context.get('record_id')), {})
        owner = context.get('origin') or self.operation_ui.get(context.get('id'), {}).get('origin', self)
        suffix = '.yka'
        dialog = QFileDialog(owner, 'Save Archive', context.get('name', record.get('name', 'Vault')) + suffix, 'YKA archive (*.yka)')
        dialog.setAcceptMode(QFileDialog.AcceptSave); dialog.setDefaultSuffix(suffix.lstrip('.'))
        self.destination_dialog = dialog
        def finished(result):
            output = dialog.selectedFiles()[0] if result == QDialog.Accepted else None
            selection_error = None
            if output:
                from .windows import output_identity, VaultError
                try: output = dict(path=output, replace_existing=output_identity(output))
                except Exception as error:
                    output = None
                    selection_error = str(error) if isinstance(error, VaultError) else 'The destination file could not be checked. Close any program using it or choose another location.'
            if self.destination_dialog is dialog: self.destination_dialog = None
            if on_selected is None and context['id'] in self.controller.pending:
                self.controller.export_destination(context['id'], output)
                self.task_dialog.show(); self.task_dialog.update_message('Saving the authenticated backup…' if output else 'Cancelling the operation…')
            dialog.deleteLater()
            if selection_error: show_error(owner, context['action'], selection_error)
            elif on_selected is not None: on_selected(output)
        dialog.finished.connect(finished)
        # Native, non-blocking dialog: worker timeout and security events still run.
        dialog.open()

    def manage(self):
        record = self.selected()
        if record and not self.controller.busy: ManageDialog(self, record).exec()

    def row_action(self, record_id):
        record = next((dict(r) for r in self.model.records if r['id'] == record_id), None)
        if not record: return
        if record['state'] == 'mounted': self.vault_operation('unmount', record)
        elif record['state'] in RECOVERY_STATES: self.recover_mount(record)
        elif record['state'] in ('Unmounted', 'Verification pending'): self.vault_operation('mount', record)
        else: ManageDialog(self, record).exec()

    def double_click(self, _):
        record = self.selected()
        if record and record['state'] == 'mounted': self.open_folder()
        elif record and record['state'] in RECOVERY_STATES: self.recover_mount(record)
        elif record and record['state'] in ('Unmounted', 'Verification pending'): self.vault_operation('mount', record)
        else: self.manage()

    def context_menu(self, position):
        index = self.table.indexAt(position)
        if not index.isValid(): return
        self.table.setCurrentIndex(index); menu = QMenu(self)
        for button in (self.mount_button, self.unmount_button, self.open_button, self.manage_button):
            action = menu.addAction(button.text()); action.setEnabled(button.isEnabled()); action.triggered.connect(button.click)
        record = self.selected(); menu.addSeparator()
        refresh_size = menu.addAction('Refresh Size')
        refresh_size.setEnabled(not self.controller.busy and not self.worker_dead and record.get('state') in ('mounted', 'Unmounted'))
        refresh_size.triggered.connect(lambda: self.refresh_size(record['id']))
        remove = menu.addAction('Remove from List'); remove.setEnabled(not self.controller.busy and not self.worker_dead and record.get('state') in REMOVABLE_STATES)
        remove.triggered.connect(lambda: self.remove_from_list(record))
        try: menu.exec(self.table.viewport().mapToGlobal(position))
        finally: menu.deleteLater()

    def remove_from_list(self, record, *, origin=None):
        origin = origin or self
        if self.controller.busy: return False
        if record.get('state') not in REMOVABLE_STATES:
            QMessageBox.information(self, 'Unmount First', 'Confirm that this vault is unmounted before removing it from your list.'); return False
        if QMessageBox.question(origin, 'Remove from List', 'This vault will be removed from your saved list. Its encrypted files will not be deleted.', QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes: return False
        self.submit(dict(action='remove-record', record_id=record['id']), origin=origin, close_on_success=origin is not self); return True

    def open_folder(self, record=None):
        record = dict(record or self.selected() or {})
        if record.get('state') != 'mounted': return
        point = record['mount_point']
        if len(point) == 2 and point[1] == ':': point += '\\'
        # QDesktopServices waits synchronously for ShellExecute. Shell/DDE
        # delays must not block YKA's event loop or its security notifications.
        # Start Explorer directly; do not probe the mount or wait for Explorer.
        windows = win32api.GetWindowsDirectory()
        started, _ = QProcess.startDetached(str(Path(windows) / 'explorer.exe'), [point], windows)
        if not started:
            show_error(self, 'open-folder', 'Windows Explorer could not be started. Open the mounted drive manually, then try again.')

    def connection_labels(self, records):
        records = [dict(record) for record in records]
        for record in records:
            keys = record.get('authorized_keys', [])
            connected = sum(any(d['serial'] == key['serial'] and any(s['slot'] == key['slot'] and s.get('public_key') == key['public_key'] for s in d['slots']) for d in self.devices) for key in keys)
            if keys:
                record['unlock_methods'] = f'YubiKey ({connected}/{len(keys)} connected)' + (' · Password' if record.get('recovery') else '')
        return records

    def completed(self, action, result, context):
        if getattr(self, 'shutdown_started', False): return
        self.execution_state()
        import time
        if action == 'registration-info': return
        if action == 'size-cache': self.refresh(); return
        if action in ('check-restore-backup', 'check-operation'):
            self.state.setText('The backup identity matches the selected vault.' if action == 'check-restore-backup' else '')
            self.finish_operation(action, context, '', result=result)
            self.update_actions()
            return
        if action == 'inspect':
            self.devices = result.get('devices', [])
            self.device_check_incomplete = result.get('inspection_incomplete', False)
            self.model.replace(self.connection_labels(self.model.records))
            if result.get('message'): self.state.setText(result['message'])
        elif action in ('status', 'list'):
            records = result.get('records', [])
            self.sizes.update(records)
            if (result.get('security_pending') is False and not self.worker_dead
                and not any(c['action'] in ('security', 'resume') for c in self.controller.pending.values())
                and all(r.get('state') in ('mounted', 'Unmounted', 'Verification pending', 'Offline', 'Deletion incomplete') for r in records)):
                self.security_unconfirmed = False
            records = self.connection_labels(records)
            selected = self.selected()
            if getattr(self, 'select_after_refresh', None): selected = {'id': self.select_after_refresh}
            self.model.replace(records)
            if selected:
                for row, item in enumerate(self.model.records):
                    if item['id'] == selected['id']:
                        self.table.setCurrentIndex(self.proxy.mapFromSource(self.model.index(row, 0))); self.select_after_refresh = None; break
            if not self.controller.busy and not self.security_unconfirmed and time.monotonic() - self.last_result_time > 15: self.state.setText(('1 vault is saved in your list.' if len(self.model.records) == 1 else f'{len(self.model.records)} vaults are saved in your list.'))
        elif action in ('security', 'resume'):
            self.mount_batch = None
            self.security_unconfirmed = bool(result.get('unmount_failed') or result.get('tasks_pending'))
            self.state.setText('Unmount has not been confirmed. Your files may still be accessible.' if result.get('unmount_failed') else
                'Waiting for the current task to stop safely…' if result.get('tasks_pending') else
                'Some vaults remain mounted according to their settings. Their files may still be accessible.' if result.get('kept_mounted') else "All managed vaults were unmounted.")
            if result.get('unmount_failed'): self.tray.showMessage('YKA needs your attention', 'Unmount is not yet confirmed. Your files may still be accessible.', QSystemTrayIcon.Warning)
            if self.exiting:
                if result.get('tasks_pending') and not self.worker_dead:
                    self.state.setText('Waiting for the current task to stop safely before exiting…')
                    QTimer.singleShot(250, self.retry_exit)
                elif not self.security_unconfirmed and not self.worker_dead:
                    self.exiting = False
                    self.controller.send({'action': 'list'}); self.close_attempted = True
                else:
                    self.exiting = False; self.show_main()
                    show_error(self, 'unmount', 'YKA could not confirm that every mount is closed. Select Recover on the affected vault, finish recovery, then exit again.')
            for root in result.get('unmounted', []): self.logs.append('Unmounted: ' + root)
            for root in result.get('unmount_failed', []): self.logs.append('Unmount not confirmed: ' + root)
            if result.get('event') == 'unmount-all':
                lines = ['Unmounted: ' + p for p in result.get('unmounted', [])]
                lines += ['Unmount not confirmed: ' + p for p in result.get('unmount_failed', [])]
                if result.get('tasks_pending'): lines.append('An operation is still stopping. Check vault status again shortly.')
                report = '\n'.join(lines) or 'No managed vaults needed unmounting.'
                if self.security_unconfirmed: show_error(self, 'unmount', report)
                else: show_result(self, 'unmount', report)
            self.refresh()
        elif action != 'cancel':
            if action in ('create', 'register', 'import') and result.get('record'): self.select_after_refresh = result['record']['id']
            message = {'recover-unmount': 'The mount is closed and its session was cleared. You can mount again or remove the vault from your list.', 'transfer': result.get('message', 'The copy completed.'), 'create': 'The vault was created and saved in your list.', 'mount': "The vault is mounted.", 'unmount': 'The vault was safely unmounted.',
                'import': "The encrypted files were imported.", 'export': "Backup exported and verified.",
                'restore-backup': 'The backup was restored to the original folder.',
                'delete-vault': 'The vault and its saved records were deleted.',
                'move-vault': result.get('message', 'The vault move finished.'), 'recover-move': result.get('message', 'Move recovery finished.'),
                'test-unlock': 'Unlock successful.', 'add-device': 'Key added and tested.',
                'remove-device': 'Authorization was removed.', 'set-recovery': 'Password updated.',
                'remove-recovery': 'The password was removed from this vault.'}.get(action, 'Saved.')
            if action == 'restore-backup' and result.get('cleanup_pending'): message += '\nRestoration completed. Some temporary files could not be removed.'
            if action == 'restore-backup': message += '\nRestored folder: ' + result['path']
            if action == 'export' and result.get('path'): message += '\nSaved to: ' + result['path']
            if result.get('keyring_cleanup_pending'):
                from .keyring_cleanup import WARNING
                message += '\n' + WARNING
            self.state.setText(message); self.logs.append(message); self.refresh()
            self.finish_operation(action, context, message, result=result)
            if action == 'recover-unmount' and self.security_unconfirmed:
                self.controller.send({'action': 'resume', 'event': 'mount-recovered'})
            if action == 'mount' and self.mount_batch is not None:
                self.mount_batch['mounted'] += 1
                self.mount_batch['waiting'] = True
            self.last_result_time = time.monotonic()
            if not self.isVisible(): self.tray.showMessage('YKA Vault Manager', message)
        if action == 'cancel': self.state.setText('Cancellation was requested. Waiting for the operation to stop safely…')
        if action in ('list', 'status') and self.mount_batch is not None and self.mount_batch['waiting']:
            self.mount_batch['waiting'] = False
            QTimer.singleShot(0, self.mount_next)
        if action in ('list', 'status') and self.close_attempted:
            self.close_attempted = False
            if not self.risk(): self.allow_close = True; self.close()
            else:
                self.show_main(); QMessageBox.warning(self, 'YKA is still running', 'Some vaults are mounted or their status is unknown. Resolve their status before exiting.')
        self.update_actions(); self.execution_state()
        self.update_tray()

    def failed(self, action, message, context):
        self.execution_state()
        from .native import diagnostic_fields
        diagnostic = diagnostic_fields(context)
        if diagnostic: self.logs.append('Backend: ' + ', '.join(f'{k}={v}' for k, v in diagnostic.items()))
        if action == 'registration-info': return
        if action == 'inspect':
            self.devices = []; self.device_check_incomplete = True
            self.controller.result.emit('inspect', {'devices': [], 'inspection_incomplete': True, 'message': message}, context)
        if action == 'size-cache':
            self.logs.append('Size cache: ' + message); return
        if self.mount_batch is not None and action in ('check-operation', 'mount', 'list', 'status', 'security', 'resume', 'protocol'):
            message += f"\nMount All stopped after {self.mount_batch['mounted']} successful mount(s)."
            self.mount_batch = None
        if context.get('id') in self.operation_ui or action == 'protocol':
            self.task_dialog.hide()
            if self.destination_dialog: self.destination_dialog.reject()
        self.logs.append(message); self.state.setText(message)
        if action in ('mount', 'unmount', 'security', 'resume', 'protocol'): self.security_unconfirmed = True
        if action not in ('list', 'status', 'inspect'):
            if context.get('id') in self.operation_ui: self.finish_operation(action, context, message, failed=True)
            elif not ('cancelled' in message.lower() and (self.exiting or self.close_attempted or self.shutdown_started)):
                show_error(self, action, message)
        self.update_actions(); self.execution_state()

    def task_progress(self, message, context):
        if context.get('id') not in self.operation_ui: return
        if self.operation_ui[context['id']].get('silent'): return
        self.state.setText(message); self.logs.append(message)
        if 'transfer_progress' in context: self.task_dialog.update_transfer(context['transfer_progress'])
        else: self.task_dialog.update_message(message)
        if context.get('transfer_progress', {}).get('cancellable') is False:
            self.operation_ui[context['id']]['committing'] = True
            self.update_actions()
        if self.destination_dialog is None:
            self.task_dialog.present(attention='touch' in message.lower())
    def update_actions(self, *_):
        if not hasattr(self, 'controller'): return
        self.update_polling()
        ready = not self.controller.busy and not self.worker_dead and self.mount_batch is None and not getattr(self, 'hardware_busy', False); record = self.selected(); state = record.get('state', '') if record else ''
        for button in self.buttons: button.setEnabled(ready)
        self.mount_button.setEnabled(ready and state in ('Unmounted', 'Verification pending'))
        self.unmount_button.setEnabled(ready and bool(record) and state not in ('Unmounted', 'Verification pending', 'Offline', 'Deletion incomplete'))
        self.unmount_button.setText('Clean Up' if state == 'unmounted-awaiting-cleanup' else 'Recover Mount' if state in RECOVERY_STATES else 'Unmount')
        self.open_button.setEnabled(state == 'mounted' and not self.worker_dead)
        self.manage_button.setEnabled(ready and bool(record)); self.cancel_button.setEnabled(self.controller.busy and not any(c['action'] == 'delete-vault' for c in self.controller.pending.values()) and not any(item.get('committing') for item in self.operation_ui.values()))
        if hasattr(self, 'menu_actions'):
            for key in ('piv',): self.menu_actions[key].setEnabled(ready)
            self.menu_actions['mount-all'].setEnabled(ready and not self.security_unconfirmed and any(r.get('state') in ('Unmounted', 'Verification pending') for r in self.model.records))
            self.menu_actions['unmount-all'].setEnabled(not self.worker_dead and (self.controller.busy or self.security_unconfirmed or any(r.get('state') not in ('Unmounted', 'Verification pending', 'Offline', 'Deletion incomplete') for r in self.model.records)))
            self.menu_actions['transfer'].setEnabled(ready and not self.security_unconfirmed and any(r.get('state') == 'mounted' for r in self.model.records))
        self.update_tray_actions()
        self.table.viewport().update()

    def risk(self):
        return getattr(self, 'hardware_busy', False) or self.security_unconfirmed or self.controller.busy or any(v.get('state') not in ('Unmounted', 'Verification pending', 'Offline', 'Deletion incomplete') for v in self.model.records)
    def execution_state(self):
        transferring = not self.worker_dead and any(c['action'] in ('transfer', 'export', 'restore-backup', 'import', 'move-vault', 'recover-move') for c in self.controller.pending.values())
        mounted = any(v.get('state') not in ('Unmounted', 'Verification pending', 'Offline', 'Deletion incomplete') for v in self.model.records)
        prevent = transferring or (mounted and self.settings.value('prevent_idle_sleep', False, type=bool))
        ctypes.windll.kernel32.SetThreadExecutionState(0x80000001 if prevent else 0x80000000)
    def preferences(self): SettingsDialog(self).exec()
    def show_main(self):
        self.showNormal(); self.raise_(); self.activateWindow()
        self.heartbeat.setInterval(5000); self.device_timer.setInterval(15000)
        self.refresh_devices()
        active = QApplication.activeModalWidget()
        if active: active.showNormal(); active.raise_(); active.activateWindow()
    def safe_transfer(self):
        from .recovery_ui import TransferDialog
        TransferDialog(self).exec()
    def recover_mount(self, record=None, *, origin=None):
        origin = origin or self
        ident = (record or {}).get('id')
        record = next((r for r in self.model.records if r['id'] == ident), None)
        if not record or self.controller.busy or self.worker_dead: return
        if record.get('state') not in RECOVERY_STATES:
            QMessageBox.information(origin, 'Mount Recovery', 'Refresh this vault and use Unmount for a normal mount.'); return
        request = dict(action='recover-unmount', record_id=ident, confirm='unmount-known-orphan')
        message = 'Check and clear the stopped mount session? Your encrypted files will not be deleted.' if record['state'] == 'unmounted-awaiting-cleanup' else 'Close programs using this mount, then continue to unmount and clear its session. YKA will recheck the mount before making changes.'
        if not (record.get('last_mount') or {}).get('mount_device') and record.get('observed_mount_device'):
            message = ('This location is mounted, but its original ownership record is missing. YKA cannot verify which vault owns it.\n\n'
                + 'Mount location: ' + record['mount_point'] + '\n\nClose programs using this location. Unmount this specific location and clear the saved session? No encrypted files will be deleted.')
            request.update(confirm='unmount-selected-location', expected_mount_device=record['observed_mount_device'])
        elif record.get('lease_unavailable') and record.get('observed_mount_device'):
            message = ('A remaining filesystem process may still hold this vault lock. YKA will first check that its supervisor has stopped.\n\n'
                + 'Mount location: ' + record['mount_point'] + '\n\nClose programs using this location. Unmount it and clear the saved session? No encrypted files will be deleted.')
            request.update(confirm='unmount-selected-location', expected_mount_device=record['observed_mount_device'])
        if QMessageBox.question(origin, 'Recover Mount', message, QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes:
            self.submit(request, origin=origin)

    def selected_unmount(self):
        record = self.selected()
        if record and record.get('state') in RECOVERY_STATES: self.recover_mount(record)
        else: self.vault_operation('unmount', record)
    def update_tray(self):
        if not hasattr(self, 'tray'): return
        signature = ctypes.windll.user32.GetSystemMetrics(49)
        if getattr(self, '_icon_signature', None) != signature:
            self._icon_signature = signature
            icon = tray_icon(self.settings); self.tray.setIcon(notification_icon(self.settings)); self.setWindowIcon(icon); QApplication.instance().setWindowIcon(icon)
        mounted = sum(r.get('state') == 'mounted' for r in self.model.records)
        self.tray.setToolTip(f'YKA Vault Manager — {mounted} mounted' + (' — Please check vault status' if self.security_unconfirmed else ''))
    def setup_tray_menu(self):
        # Keep menu/action ownership local. Clearing a second QMenu containing
        # a shared QAction invalidates its cached wrapper on PySide 6.10.2.
        self.tray_menu.addAction('Open YKA Vault Manager', self.show_main)
        self.tray_vault_menus = {}
        for title, operation, states in [('Mount Vault', 'mount', ('Unmounted', 'Verification pending')),
            ('Open Mounted Vault', 'open', ('mounted',)), ('Unmount Vault', 'unmount', ('mounted',))]:
            self.tray_vault_menus[operation] = (self.tray_menu.addMenu(title), states)
        self.tray_batch_actions = {}
        for key in ('mount-all', 'unmount-all'):
            original = self.menu_actions[key]
            action = self.tray_menu.addAction(original.text())
            action.triggered.connect(original.trigger)
            self.tray_batch_actions[key] = action
        self.tray_menu.addAction('Settings…', self.preferences); self.tray_menu.addSeparator()
        self.tray_menu.addAction('Exit', self.request_exit)
        self.tray_vault_actions = []

    def update_tray_actions(self):
        if not hasattr(self, 'tray_batch_actions'): return
        for key, action in self.tray_batch_actions.items():
            action.setEnabled(self.menu_actions[key].isEnabled())
        ready = not self.controller.busy and not self.worker_dead and self.mount_batch is None and not getattr(self, 'hardware_busy', False)
        records = {r['id']: r for r in self.model.records}
        for action, snapshot in self.tray_vault_actions:
            current = records.get(snapshot['id'], {})
            unchanged = all(current.get(k) == snapshot.get(k) for k in ('state', 'path', 'mount_point', 'uuid', 'signing_public'))
            action.setEnabled(ready and unchanged)

    def rebuild_tray(self):
        self.tray_vault_actions.clear()
        for operation, (menu, states) in self.tray_vault_menus.items():
            menu.clear()
            for r in self.model.records:
                if r.get('state') not in states: continue
                record = dict(r)
                action = menu.addAction(record['name'] + ' — ' + record['path'])
                action.triggered.connect(lambda checked=False, r=record, op=operation: self.tray_operation(op, r))
                self.tray_vault_actions.append((action, record))
            menu.setEnabled(bool(menu.actions()))
        self.update_tray_actions()
    def tray_operation(self, operation, record):
        if operation == 'open': self.open_folder(record)
        else: self.show_main(); self.vault_operation(operation, record)
    def request_exit(self):
        import time
        if getattr(self, 'hardware_busy', False):
            self.show_main(); QMessageBox.information(self, 'PIV Operation in Progress', 'Wait for the YubiKey operation to finish before exiting. Interrupting it may leave a key without its certificate.'); return
        if self.exiting: return
        self.show_main()
        if self.risk() and QMessageBox.question(self, 'Unmount and Exit', 'YKA will stop the current task and try to unmount all managed vaults. Continue?', QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes: return
        if self.worker_dead:
            from .exit_check import start
            start(self); return
        self.exiting = True; self.exit_deadline = time.monotonic() + 40; self.power_event('application-exit')
    def retry_exit(self):
        import time
        if not self.exiting: return
        if time.monotonic() >= self.exit_deadline or self.worker_dead:
            self.exiting = False; self.show_main()
            show_error(self, 'unmount', 'The task is still stopping. YKA remains open because mount safety has not been confirmed. Use Recover Mount when the task finishes, then exit again.')
        elif self.controller.busy:
            QTimer.singleShot(250, self.retry_exit)
        else:
            self.power_event('application-exit')
    def diagnostics(self): self.logs_window.show(); self.logs_window.raise_()
    def devices_window(self): DeviceDialog(self).exec()
    def about(self):
        from .about import AboutDialog
        AboutDialog(self).exec()
    def power_event(self, event):
        self.mount_batch = None
        if self.destination_dialog: self.destination_dialog.reject()
        self.security_unconfirmed = True; self.state.setText('YKA is checking mount status and applying the vault security settings…')
        self.controller.send({'action': 'resume' if event in ('unmount-all', 'application-exit') else 'security', 'event': event}); self.execution_state()
    def nativeEvent(self, event_type, message):
        msg = wintypes.MSG.from_address(int(message))
        if hasattr(self, 'controller'):
            if msg.message == 0x02B1:
                if msg.wParam in (2, 4, 7): self.power_event('session-lock' if msg.wParam == 7 else 'session-disconnect')
                elif msg.wParam == 8: self.controller.send({'action': 'resume', 'event': 'session-unlock'})
            elif msg.message == 0x0218:
                if msg.wParam == 4: self.power_event('suspend-or-hibernate')
                elif msg.wParam in (7, 18): self.controller.send({'action': 'resume', 'event': 'resume'})
            elif msg.message in (0x0011, 0x0016): self.power_event('shutdown')
        return super().nativeEvent(event_type, message)
    def worker_stopped(self):
        self.sizes.stop()
        if self.allow_close: return
        self.worker_dead = True; self.execution_state()
        self.mount_batch = None
        self.task_dialog.hide()
        if self.destination_dialog: self.destination_dialog.reject()
        for task_id in list(self.operation_ui):
            self.finish_operation('operation', {'id': task_id}, 'The background worker stopped. Check vault status before trying again.', failed=True)
        self.worker_dead = True; self.security_unconfirmed = True
        self.model.replace([dict(record, state='Unknown / worker stopped') for record in self.model.records]); self.state.setText('YKA lost contact with its background process. Mount status needs to be checked.'); self.update_actions(); self.execution_state()
    def worker_finished(self, *_):
        if self.shutdown_started: QTimer.singleShot(0, self.close)

    def check_shutdown(self):
        if self.shutdown_started and self.controller.process.state() != QProcess.NotRunning:
            self.show_main()
            self.state.setText('Waiting for the background worker to finish cleanup. YKA will close automatically when it stops.')

    def closeEvent(self, event):
        if not self.allow_close:
            if QSystemTrayIcon.isSystemTrayAvailable():
                self.settings.setValue('geometry', self.saveGeometry()); self.hide(); event.ignore()
                if not self.settings.value('tray_tip_shown', False, type=bool):
                    self.tray.showMessage('YKA is running in the background', "Use the tray icon to open YKA or choose Exit.")
                    self.settings.setValue('tray_tip_shown', True)
            else:
                event.ignore(); self.request_exit()
            return
        if self.risk():
            self.allow_close = False; event.ignore(); self.request_exit(); return
        self.sizes.stop()
        self.settings.setValue('geometry', self.saveGeometry())
        if self.controller.process.state() != QProcess.NotRunning:
            event.ignore()
            if not self.shutdown_started:
                self.shutdown_started = True
                self.heartbeat.stop(); self.device_timer.stop()
                self.centralWidget().setEnabled(False); self.menuBar().setEnabled(False)
                self.state.setText('Finishing background cleanup before closing YKA…')
                self.controller.shutdown()
                QTimer.singleShot(10000, self.check_shutdown)
            return
        if self.session_registered: ctypes.windll.wtsapi32.WTSUnRegisterSessionNotification(int(self.winId()))
        self.tray.hide(); ctypes.windll.kernel32.SetThreadExecutionState(0x80000000); event.accept(); QApplication.instance().quit()


def main():
    import win32event
    from .instance import Instance, worker_available
    app = QApplication(sys.argv); app.setQuitOnLastWindowClosed(False)
    from .ui_common import install_message_widths
    install_message_widths(app)
    instance = Instance()
    if not instance.primary:
        if not instance.request_activation():
            QMessageBox.warning(None, 'YKA is already running', "The existing YKA window did not respond. Check the original session and any mounted vaults before closing it.")
        instance.close(); return
    if not worker_available():
        QMessageBox.warning(None, 'YKA is still stopping', "A YKA worker is still running. Wait for it to stop, then reopen YKA.")
        instance.close(); return
    running_mutex = win32event.CreateMutex(None, False, "Local\\YKA.VaultManager.Running")
    if win32api.GetLastError() == 183 and not os.environ.get('YKA_STATE_DIR'):
        QMessageBox.warning(None, 'An older YKA instance is running', 'Exit the existing YKA version safely before opening this version.')
        instance.close(); return
    QLocale.setDefault(QLocale(QLocale.English, QLocale.UnitedStates))
    window = Window()
    activation = QTimer(window); activation.timeout.connect(lambda: instance.poll(window.show_main)); activation.start(200)
    if '--tray' not in sys.argv or not QSystemTrayIcon.isSystemTrayAvailable(): window.show()
    if '--smoke-test' in sys.argv:
        def capture():
            output = PROJECT / 'test-output/gui.png'; output.parent.mkdir(exist_ok=True)
            window.grab().save(str(output)); window.allow_close = True; window.close()
        QTimer.singleShot(2500, capture)
    result = app.exec(); instance.close(); sys.exit(result)


if __name__ == '__main__': main()
