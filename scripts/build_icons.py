"""Reproduce all native-size icon frames; no upscaled small source image."""
import sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'src'))
from PySide6.QtWidgets import QApplication
from yka.appearance import write_default_ico, default_image
app = QApplication([])
write_default_ico(root / 'assets/yka.ico')
default_image(256).save(str(root / 'assets/yka.png'))
