"""Shared Windows controls and readable task feedback; no cryptographic state."""
from .windows import available_drives
from PySide6.QtCore import Qt, QObject, QEvent, QModelIndex
from PySide6.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout, QComboBox, QLineEdit,
    QPushButton, QFileDialog, QDialog, QLabel, QProgressBar, QAbstractItemView, QMessageBox, QSizePolicy, QTextEdit, QSpacerItem)


class ModalDialog(QDialog):
    """One-shot modal forms; values remain readable immediately after exec."""
    def exec(self):
        try: return super().exec()
        finally: self.deleteLater()


class MessageWidthFilter(QObject):
    """Give all Qt message boxes a readable layout width, including static helpers."""
    def eventFilter(self, watched, event):
        if isinstance(watched, QMessageBox) and event.type() == QEvent.Polish and not watched.property('ykaReadableWidth'):
            watched.setProperty('ykaReadableWidth', True)
            screen = watched.screen().availableGeometry().width()
            width = min(440, max(240, screen - 80))
            layout = watched.layout()
            layout.addItem(QSpacerItem(width, 0, QSizePolicy.Minimum, QSizePolicy.Minimum),
                           layout.rowCount(), 0, 1, layout.columnCount())
        return False


def install_message_widths(app):
    if not hasattr(app, '_yka_message_widths'):
        app._yka_message_widths = MessageWidthFilter(app)
        app.installEventFilter(app._yka_message_widths)


class BlankSelectionFilter(QObject):
    def eventFilter(self, watched, event):
        view = self.parent()
        if event.type() == QEvent.MouseButtonPress and not view.indexAt(event.position().toPoint()).isValid():
            view.clearSelection(); view.setCurrentIndex(QModelIndex())
        return False


def clear_on_blank(view):
    view._blank_selection = BlankSelectionFilter(view)
    view.viewport().installEventFilter(view._blank_selection)


class TimestampLog(QTextEdit):
    def append(self, text):
        from datetime import datetime
        from PySide6.QtGui import QTextCursor
        cursor = self.textCursor(); cursor.movePosition(QTextCursor.End)
        if not self.document().isEmpty(): cursor.insertBlock()
        cursor.insertText(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '  ' + str(text))
        self.setTextCursor(cursor)


class MountPicker(QWidget):
    def __init__(self, preferred='', parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self); layout.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout(); layout.addLayout(row)
        self.kind = QComboBox(); self.kind.addItems(['Drive letter', 'Custom folder'])
        self.drives = QComboBox(); self.drives.addItems(available_drives())
        if self.drives.findText('Z:') >= 0: self.drives.setCurrentText('Z:')
        row.addWidget(self.kind); row.addWidget(self.drives)
        self.folder = QLineEdit(); self.folder.setPlaceholderText('Choose an empty folder outside the encrypted vault')
        layout.addWidget(self.folder)
        self.browse = QPushButton('Choose folder…'); layout.addWidget(self.browse)
        self.browse.clicked.connect(self.choose)
        self.kind.currentIndexChanged.connect(self.update_fields)
        if preferred: self.setText(preferred)
        self.update_fields()

    def update_fields(self):
        folder = self.kind.currentIndex() == 1
        self.folder.setVisible(folder); self.browse.setVisible(folder); self.drives.setVisible(not folder)

    def choose(self):
        path = QFileDialog.getExistingDirectory(self, 'Choose an empty mount folder', self.folder.text())
        if path: self.folder.setText(path)

    def text(self): return self.folder.text() if self.kind.currentIndex() else self.drives.currentText()
    def setText(self, value):
        if len(value) == 2 and value[1] == ':':
            self.kind.setCurrentIndex(0)
            if self.drives.findText(value.upper()) < 0: self.drives.addItem(value.upper())
            self.drives.setCurrentText(value.upper())
        else: self.kind.setCurrentIndex(1); self.folder.setText(value)


def style_table(table):
    clear_on_blank(table)
    table.verticalHeader().hide(); table.verticalHeader().setDefaultSectionSize(32)
    table.setAlternatingRowColors(True); table.setWordWrap(False)
    table.setTextElideMode(Qt.ElideMiddle)
    table.setStyleSheet('QTableView::item:selected { background: #005fb8; color: white; }')
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)


class TaskDialog(QDialog):
    def __init__(self, parent, cancel, *, cancellable=True, transfer=False):
        super().__init__(parent); self.setWindowTitle('Vault operation'); self.resize(500, 160); self.setMinimumWidth(500)
        self.cancellable = cancellable
        self.transfer = transfer
        self.awaiting_restore = False
        if not cancellable: self.setWindowFlag(Qt.WindowCloseButtonHint, False)
        self.setWindowModality(Qt.WindowModal)
        layout = QVBoxLayout(self)
        self.message = StatusLabel('', self) if transfer else QLabel()
        if transfer:
            self.resize(660, 160); self.setMinimumWidth(600); self.message.elide_mode = Qt.ElideMiddle
        else: self.message.setWordWrap(True)
        self.message.setTextFormat(Qt.PlainText); layout.addWidget(self.message)
        self.bar = QProgressBar(); self.bar.setRange(0, 0)
        self.cancel_button = QPushButton('Cancel' if transfer else 'Cancel operation')
        self.summary = StatusLabel('', self); self.summary.setTextFormat(Qt.PlainText); self.summary.setVisible(transfer)
        if transfer:
            layout.addWidget(self.summary)
            row = QHBoxLayout(); row.addWidget(self.bar, 1); row.addWidget(self.cancel_button); layout.addLayout(row)
        else:
            layout.addWidget(self.bar); layout.addWidget(self.cancel_button)
        self.cancel_button.setVisible(cancellable)
        def request_cancel():
            self.cancel_button.setEnabled(False)
            self.message.setText('Cancelling…' if transfer else 'Cancellation was requested. Please wait while the operation stops safely.')
            cancel()
        self.cancel_button.clicked.connect(request_cancel)

    def begin(self, title, *, authentication_first=False):
        self.setWindowTitle(title); self.message.setText('Preparing the operation. Please wait…')
        if self.transfer:
            self.message.setText('Calculating total size…')
            self.summary.setText('0 copied · 0 skipped · 0 overwritten · 0.0 MiB/s')
        self.awaiting_restore = authentication_first
        self.bar.setVisible(not authentication_first)
        self.bar.setRange(0, 0)
        self.cancel_button.setEnabled(True); self.present(attention=True)

    def present(self, *, attention=False):
        owner = self.parentWidget()
        owner_window = QWidget.window(owner) if owner is not None else None
        if owner_window is not None and (owner_window.isMinimized() or not owner_window.isVisible()):
            owner_window.showNormal()
        hidden = not self.isVisible() or self.isMinimized()
        if hidden:
            if owner is not None:
                self.move(owner.frameGeometry().center() - self.rect().center())
            self.showNormal()
        if hidden or attention:
            self.raise_(); self.activateWindow()

    def update_message(self, text):
        if self.cancel_button.isEnabled():
            import re
            self.message.setText(text)
            if self.awaiting_restore and text.startswith('Restoring encrypted files'):
                self.awaiting_restore = False
                self.setWindowTitle('Restoring your backup'); self.bar.show()
            percent = re.search(r'\((\d{1,3})%\)', text)
            if percent: self.bar.setRange(0, 100); self.bar.setValue(min(100, int(percent[1])))
            else: self.bar.setRange(0, 0)

    def update_transfer(self, value):
        if not self.transfer or not self.cancel_button.isEnabled(): return
        self.message.setText(value['current']); self.summary.setText(value['summary'])
        percent = value.get('percent')
        if percent is None: self.bar.setRange(0, 0)
        else: self.bar.setRange(0, 100); self.bar.setValue(percent)

    def reject(self):
        if self.cancellable and self.cancel_button.isEnabled(): self.cancel_button.click()

    def closeEvent(self, event): self.reject(); event.ignore()


ACTION_NAMES = {'piv-create': 'PIV key creation', 'piv-replace': 'PIV key replacement', 'transfer': 'File transfer', 'recover-unmount': 'Mount recovery', 'create': 'Vault creation', 'register': 'Vault registration', 'import': 'Archive import',
    'mount': 'Mount', 'unmount': 'Unmount', 'export': 'Archive export',
    'restore-backup': 'Backup restore', 'check-restore-backup': 'Backup check', 'test-unlock': 'Unlock verification', 'add-device': 'Key authorization',
    'remove-device': 'Authorization removal', 'set-recovery': 'Password update', 'remove-recovery': 'Password removal',
    'preferences': 'Settings update', 'device-label': 'Key rename', 'relocate': 'Vault relocation',
    'move-vault': 'Vault move', 'recover-move': 'Move recovery', 'remove-record': 'List update', 'open-folder': 'Opening folder'}


def error_text(action, detail):
    # Worker messages are already sanitized. Ordinary reasons belong in the body.
    title = ACTION_NAMES.get(action, 'Operation') + ' failed'
    return title, detail


def show_error(parent, action, detail):
    title, reason = error_text(action, detail)
    message = QMessageBox(parent); message.setIcon(QMessageBox.Warning)
    message.setWindowTitle(title); message.setTextFormat(Qt.PlainText); message.setText(reason)
    try: message.exec()
    finally: message.deleteLater()


def show_result(parent, action, text, *, cancelled=False):
    message = QMessageBox(parent); message.setIcon(QMessageBox.Information)
    message.setWindowTitle(ACTION_NAMES.get(action, 'Operation') + (' cancelled' if cancelled else ' complete'))
    message.setTextFormat(Qt.PlainText); message.setText(text)
    try: message.exec()
    finally: message.deleteLater()


class StatusLabel(QLabel):
    """One line of status; full text remains available without resizing the layout."""
    def __init__(self, text, parent=None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        self.setMinimumHeight(self.fontMetrics().height() + 4)
        self.setText(text)
    def setText(self, text):
        self.message = text; self.setToolTip(text)
        super().setText(self.fontMetrics().elidedText(text, getattr(self, 'elide_mode', Qt.ElideRight), max(1, self.width())))
    def resizeEvent(self, event):
        self.setText(self.message); super().resizeEvent(event)


def style_form(form):
    form.setHorizontalSpacing(max(20, form.horizontalSpacing()))
    form.setVerticalSpacing(max(10, form.verticalSpacing()))
