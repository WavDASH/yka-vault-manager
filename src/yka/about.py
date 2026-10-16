"""Product information and bundled license texts, available offline in every build."""
import json
import platform
import re
import PySide6
import pywintypes
from PySide6.QtCore import Qt, qVersion
from PySide6.QtGui import QPixmap
from .ui_common import ModalDialog
from PySide6.QtWidgets import (QApplication, QDialog, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QDialogButtonBox, QComboBox, QTextBrowser, QLineEdit)
from . import __version__
from .native import PROJECT
from .appearance import default_image


def version_info():
    lines = [f'YKA Vault Manager {__version__}', f'Platform: {platform.platform()}',
             f'Architecture: {platform.machine()}', f'Python: {platform.python_version()}',
             f'PySide6: {PySide6.__version__}', f'Qt: {qVersion()}']
    try:
        dependencies = json.loads((PROJECT / 'vendor/dependencies.json').read_text(encoding='utf-8'))
        for item in dependencies:
            if item.get('name') in ('securefs', 'age-plugin-yubikey'):
                match = re.search(r'/v(\d+\.\d+\.\d+)/', item.get('url', ''))
                if match: lines.append(f"{item['name']} (bundled): {match[1]}")
    except (OSError, ValueError):
        lines.append('Bundled component versions: unavailable')
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\WinFsp') as key:
            directory = winreg.QueryValueEx(key, 'InstallDir')[0]
        import win32api
        from pathlib import Path
        data = win32api.GetFileVersionInfo(str(Path(directory) / 'bin/winfsp-x64.dll'), '\\')
        ms, ls = data['FileVersionMS'], data['FileVersionLS']
        lines.append(f'WinFsp (installed): {ms >> 16}.{ms & 65535}.{ls >> 16}.{ls & 65535}')
    except (OSError, KeyError, pywintypes.error):
        lines.append('WinFsp: installed version unavailable')
    return '\n'.join(lines)


class CreditsDialog(ModalDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Licenses & Credits'); self.resize(780, 580); self.setMinimumWidth(600)
        layout = QVBoxLayout(self)
        self.search = QLineEdit(); self.search.setPlaceholderText('Find a component or license')
        layout.addWidget(self.search)
        self.entries = QComboBox(); layout.addWidget(self.entries)
        self.viewer = QTextBrowser(); self.viewer.setOpenExternalLinks(True); layout.addWidget(self.viewer)
        self.documents = [('Overview', PROJECT / 'docs/THIRD_PARTY.md'), ('YKA — GNU GPL v3', PROJECT / 'LICENSE')]
        self.documents += [(p.name, p) for p in sorted((PROJECT / 'docs/licenses').glob('*')) if p.is_file()]
        self.entries.currentIndexChanged.connect(self.display)
        self.search.textChanged.connect(self.filter)
        box = QDialogButtonBox(QDialogButtonBox.Close); box.rejected.connect(self.reject); layout.addWidget(box)
        self.filter('')

    def filter(self, text):
        self.entries.blockSignals(True); self.entries.clear()
        for name, path in self.documents:
            if text.casefold() in name.casefold(): self.entries.addItem(name, path)
        self.entries.blockSignals(False); self.display()

    def display(self):
        path = self.entries.currentData()
        if path is None: self.viewer.setPlainText('No matching licenses.'); return
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
            if path.name == 'THIRD_PARTY.md':
                # Keep the recorded sources and terms, without internal file paths.
                text = text.replace('see `LICENSE`', 'see YKA — GNU GPL v3 in the list above')
                text = re.sub(r'Other versions and notices are in .*?SBOM\.',
                    'The list includes third-party license and copyright texts, including development and cross-target dependencies. It is not a final binary inventory.', text)
                text = re.sub(r'Official download URLs.*?runtime\.', 'The application does not download executables at runtime.', text)
                text = text.replace(' using `scripts/prepare_plugin.py`', '')
                self.viewer.setMarkdown(text)
            else: self.viewer.setPlainText(text)
        except OSError:
            self.viewer.setPlainText('This license could not be loaded. Reinstall YKA from the complete release package.')


class AboutDialog(ModalDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('About YKA Vault Manager'); self.setMinimumWidth(540)
        layout = QVBoxLayout(self); layout.setContentsMargins(28, 28, 28, 20); layout.setSpacing(24)
        row = QHBoxLayout(); row.setSpacing(24); layout.addLayout(row)
        icon = QLabel(); image = default_image(round(80 * self.devicePixelRatioF()))
        image.setDevicePixelRatio(self.devicePixelRatioF()); icon.setPixmap(QPixmap.fromImage(image))
        row.addWidget(icon, 0, Qt.AlignTop)
        text = QVBoxLayout(); text.setSpacing(8); row.addLayout(text, 1)
        title = QLabel('YKA Vault Manager'); font = title.font(); font.setPointSizeF(font.pointSizeF() + 5); font.setBold(True); title.setFont(font)
        text.addWidget(title); text.addWidget(QLabel(f'Version {__version__}'))
        description = QLabel('Manage encrypted folders with YubiKey protection and secure backups.')
        description.setWordWrap(True); text.addWidget(description)
        buttons = QHBoxLayout(); layout.addLayout(buttons)
        credits = QPushButton('Licenses && Credits'); credits.clicked.connect(lambda: CreditsDialog(self).exec()); buttons.addWidget(credits)
        copy = QPushButton('Copy Version Info'); copy.clicked.connect(lambda: QApplication.clipboard().setText(version_info())); buttons.addWidget(copy)
        buttons.addStretch(); close = QPushButton('Close'); close.clicked.connect(self.accept); close.setDefault(True); buttons.addWidget(close)
