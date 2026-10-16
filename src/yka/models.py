from PySide6.QtCore import QAbstractTableModel, Qt, Signal, QEvent
from PySide6.QtWidgets import QStyledItemDelegate, QStyleOptionButton, QStyle, QApplication
from .mount_recovery import RECOVERY_STATES, recovery_hint


class VaultModel(QAbstractTableModel):
    columns = [('Name', 'name'), ('Format', 'mode'), ('Encrypted folder', 'path'),
        ('Status', 'state'), ('Mount point', 'mount_point'), ('Unlock methods', 'unlock_methods'),
        ('Auto unmount', 'auto_unmount'), ('Size', 'size'), ('', 'action')]
    action_column = len(columns) - 1

    def __init__(self, parent=None): super().__init__(parent); self.records = []
    def rowCount(self, parent=None): return len(self.records)
    def columnCount(self, parent=None): return len(self.columns)
    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role in (Qt.DisplayRole, Qt.ToolTipRole) and orientation == Qt.Horizontal: return self.columns[section][0]
    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid(): return None
        record = self.records[index.row()]
        if role == Qt.UserRole + 1:
            if self.columns[index.column()][1] == 'size':
                from .vault_size import cache
                value = cache(record)
                return value['bytes'] if value else -1
            return self.data(index, Qt.DisplayRole)
        if role == Qt.UserRole: return record['id']
        if role == Qt.ToolTipRole and index.column() in (3, self.action_column) and record['state'] in RECOVERY_STATES:
            return recovery_hint(record)
        if role in (Qt.DisplayRole, Qt.ToolTipRole):
            if index.column() == self.action_column:
                if record['state'] == 'unmounted-awaiting-cleanup': return 'Clean Up'
                if record['state'] in RECOVERY_STATES: return 'Recover'
                return 'Unmount' if record['state'] == 'mounted' else 'Mount' if record['state'] in ('Unmounted', 'Verification pending') else 'Check'
            field = self.columns[index.column()][1]
            if field == 'size':
                from .vault_size import display
                text, detail = display(record)
                return detail if role == Qt.ToolTipRole else text
            if field == 'auto_unmount':
                enabled = record.get('auto_unmount', True)
                if role == Qt.ToolTipRole:
                    return 'Unmount when Windows locks or sleeps: ' + ('On' if enabled else 'Off')
                return 'On' if enabled else 'Off'
            value = record.get(field, '')
            if index.column() == 3:
                return {'mounted': 'Mounted', 'mounted-supervisor-lost': 'Warning: supervisor lost',
                    'unknown-mount-owner': 'Unknown: mount owner', 'unmounted-awaiting-cleanup': 'Unmounted: cleanup pending',
                    'mount-stopping': 'Stopping mount: recovery available', 'unknown': 'Unknown'}.get(value, str(value))
            return str(value).capitalize() if index.column() == 1 else str(value)
    def replace(self, records):
        self.beginResetModel(); self.records = records; self.endResetModel()


class VaultActionDelegate(QStyledItemDelegate):
    triggered = Signal(str)

    def __init__(self, busy, parent=None): super().__init__(parent); self.busy = busy
    def paint(self, painter, option, index):
        button = QStyleOptionButton(); button.rect = option.rect.adjusted(4, 2, -4, -2)
        button.text = index.data(Qt.DisplayRole)
        button.state = QStyle.State_Enabled if not self.busy() else QStyle.State_None
        QApplication.style().drawControl(QStyle.CE_PushButton, button, painter)
    def editorEvent(self, event, model, option, index):
        if event.type() == QEvent.MouseButtonRelease and event.button() == Qt.LeftButton and not self.busy():
            self.triggered.emit(index.data(Qt.UserRole)); return True
        return False
