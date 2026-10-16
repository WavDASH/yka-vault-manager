"""Built-in icons and per-user startup settings."""
import os
import sys
import subprocess
import winreg
from pathlib import Path
from PySide6.QtCore import Qt, QRectF, QSettings
from PySide6.QtGui import QImage, QPainter, QColor, QIcon, QPixmap, QPen
from .ui_common import ModalDialog
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QLabel,
    QCheckBox, QDialogButtonBox, QMessageBox)


def app_settings():
    # QSettings(org, app) uses native registry storage even after setDefaultFormat.
    # Tests/portable state overrides must never write the real user's settings.
    directory = os.environ.get('YKA_STATE_DIR')
    if directory:
        from .windows import safe_path
        path = safe_path(Path(directory) / 'ui-settings.ini')
        path.parent.mkdir(parents=True, exist_ok=True)
        return QSettings(str(path), QSettings.IniFormat)
    return QSettings('YKA', 'VaultManager')


ICON_SIZES = (16, 20, 24, 32, 48, 64, 256)


def default_image(size=64, *, compact=True):
    # Render vector geometry independently at each physical resolution.
    image = QImage(size, size, QImage.Format_ARGB32); image.fill(Qt.transparent)
    p = QPainter(image)
    p.setRenderHint(QPainter.Antialiasing); p.scale(size / 64, size / 64)
    p.setPen(Qt.NoPen); p.setBrush(QColor('#1768a6')); p.drawRoundedRect(QRectF(2, 2, 60, 60), 12, 12)
    p.setPen(QPen(QColor('white'), 5)); p.setBrush(Qt.NoBrush); p.drawRoundedRect(QRectF(22, 13, 20, 25), 9, 9)
    p.setPen(Qt.NoPen); p.setBrush(QColor('white')); p.drawRoundedRect(QRectF(16, 29, 32, 24), 4, 4)
    p.setBrush(QColor('#1768a6')); p.drawEllipse(QRectF(29, 35, 6, 6)); p.drawRect(QRectF(30, 39, 4, 8)); p.end()
    return image


def tray_icon(settings):
    icon = QIcon()
    for size in ICON_SIZES: icon.addPixmap(QPixmap.fromImage(default_image(size)))
    return icon


def notification_icon(settings):
    import ctypes
    # Preserve the tray's physical-size frame and established artwork.
    size = max(16, ctypes.windll.user32.GetSystemMetrics(49))
    pixmap = QPixmap.fromImage(default_image(size, compact=False)); pixmap.setDevicePixelRatio(1)
    return QIcon(pixmap)


def write_default_ico(path):
    import struct
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice
    frames = []
    for size in ICON_SIZES:
        data = QByteArray(); buffer = QBuffer(data); buffer.open(QIODevice.WriteOnly)
        default_image(size).save(buffer, 'PNG'); frames.append((size, bytes(data)))
    offset = 6 + 16 * len(frames); entries = []; payload = []
    for size, data in frames:
        entries.append(struct.pack('<BBBBHHII', size % 256, size % 256, 0, 0, 1, 32, len(data), offset))
        payload.append(data); offset += len(data)
    Path(path).write_bytes(struct.pack('<HHH', 0, 1, len(frames)) + b''.join(entries + payload))


class SettingsDialog(ModalDialog):
    def __init__(self, window):
        super().__init__(window); self.window = window; self.setWindowTitle('Settings'); self.resize(460, 150); self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        self.startup = QCheckBox('Start YKA when I sign in to Windows')
        self.startup.setChecked(self.startup_enabled()); self.startup.setEnabled(bool(getattr(sys, 'frozen', False)))
        if not getattr(sys, 'frozen', False): self.startup.setToolTip('Startup is available in the packaged application.')
        layout.addWidget(self.startup)
        self.prevent_sleep = QCheckBox('Prevent idle sleep while vaults are mounted')
        self.prevent_sleep.setChecked(window.settings.value('prevent_idle_sleep', False, type=bool))
        layout.addWidget(self.prevent_sleep)
        layout.setContentsMargins(20, 18, 20, 18); layout.setSpacing(14)
        layout.addStretch()
        box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        box.accepted.connect(self.accept); box.rejected.connect(self.reject); layout.addWidget(box)

    def startup_enabled(self):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run') as key:
                return winreg.QueryValueEx(key, 'YkaVaultManager')[0] == subprocess.list2cmdline([sys.executable, '--tray'])
        except OSError: return False

    def accept(self):
        try:
            if self.startup.isEnabled():
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run') as key:
                    if self.startup.isChecked(): winreg.SetValueEx(key, 'YkaVaultManager', 0, winreg.REG_SZ, subprocess.list2cmdline([sys.executable, '--tray']))
                    else:
                        try: winreg.DeleteValue(key, 'YkaVaultManager')
                        except FileNotFoundError: pass
            self.window.settings.remove('tray_icon'); self.window.settings.remove('tray_icon_pixel_art')
            self.window.settings.setValue('prevent_idle_sleep', self.prevent_sleep.isChecked())
            self.window.settings.sync(); self.window.update_tray(); self.window.execution_state()
        except Exception:
            QMessageBox.warning(self, 'Settings could not be saved', 'Check that your Windows account can write its settings folder.'); return
        super().accept()
