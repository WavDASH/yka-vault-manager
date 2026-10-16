"""Opt-in native Windows icon diagnostics, with isolated settings and no vault access."""
import ctypes
import json
import os
from pathlib import Path
import re
import sys
from PySide6.QtCore import QTimer, QLoggingCategory, qInstallMessageHandler
from PySide6.QtGui import QImage
from PySide6.QtWidgets import QApplication, QWidget, QSystemTrayIcon
from .appearance import app_settings, tray_icon, notification_icon


def main():
    if not os.environ.get('YKA_STATE_DIR'): raise SystemExit('Set an isolated YKA_STATE_DIR for icon checks.')
    output = Path(os.environ['YKA_STATE_DIR']); output.mkdir(parents=True, exist_ok=True)
    logs = []
    def handler(kind, context, message):
        if context.category == 'qt.qpa.trayicon': logs.append(message)
    qInstallMessageHandler(handler); QLoggingCategory.setFilterRules('qt.qpa.trayicon.debug=true')
    app = QApplication(sys.argv); settings = app_settings()
    application = tray_icon(settings); app.setWindowIcon(application)
    window = QWidget(); window.setWindowTitle('YKA Icon Check'); window.setWindowIcon(application); window.resize(360, 160); window.show()
    tray = QSystemTrayIcon(notification_icon(settings), window); tray.setToolTip('YKA Icon Check'); tray.show()
    result = dict(frozen=bool(getattr(sys,'frozen',False)), executable=sys.executable,
        source=settings.value('tray_icon','built-in optical rendering'),
        dpr=app.primaryScreen().devicePixelRatio(), native_tray_size=ctypes.windll.user32.GetSystemMetrics(49), icons={})
    def record(name, handle):
        if not handle: result['icons'][name] = {'available':False}; return
        image = QImage.fromHICON(handle)
        image.save(str(output/(name+'.png')))
        result['icons'][name] = dict(available=not image.isNull(), width=image.width(), height=image.height())
    def capture():
        import win32gui
        record('titlebar',win32gui.SendMessage(int(window.winId()),0x7F,0,0))
        record('taskbar_window',win32gui.SendMessage(int(window.winId()),0x7F,1,0))
        # Qt debug messages contain this process's actual HICON passed to Shell_NotifyIcon.
        tray.setToolTip('YKA Icon Check — capture')
        handles = [int(m,16) for line in logs for m in re.findall(r'm_hIcon=(0x[0-9a-fA-F]+)',line) if int(m,16)]
        record('notification_area',handles[-1] if handles else 0)
        if getattr(sys,'frozen',False):
            extract = ctypes.windll.user32.PrivateExtractIconsW
            extract.argtypes=[ctypes.c_wchar_p,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(ctypes.c_uint),ctypes.c_uint,ctypes.c_uint]
            destroy = ctypes.windll.user32.DestroyIcon; destroy.argtypes=[ctypes.c_void_p]
            for size in (16,20,24,32,48,64,256):
                handle = ctypes.c_void_p(); ident = ctypes.c_uint()
                extract(sys.executable,0,size,size,ctypes.byref(handle),ctypes.byref(ident),1,0)
                record('exe-'+str(size),handle.value)
                if handle.value: destroy(handle)
        rect = tray.geometry(); result['tray_visible'] = not rect.isEmpty()
        if not rect.isEmpty():
            app.primaryScreen().grabWindow(0,rect.x()-40,rect.y()-4,rect.width()+80,rect.height()+8).save(str(output/'tray-neighborhood.png'))
        window.grab().save(str(output/'window.png'))
        (output/'icons.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        tray.hide(); window.close(); app.quit()
    QTimer.singleShot(1200,capture); app.exec()


if __name__ == '__main__': main()
