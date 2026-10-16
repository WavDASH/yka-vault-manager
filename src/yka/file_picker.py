"""Windows Common Item Dialog with mixed filesystem-item selection.

The existing confirmation button accepts files and folders. Folder double-click
and navigation remain native. Read the Shell view's selection directly: the
file-name field can contain only one name when multiple folders are selected.
"""
import ctypes as C
from ctypes import wintypes as W
import uuid

HRESULT = C.c_long
PTR = C.c_void_p
GUID = C.c_ubyte * 16

def guid(value): return GUID.from_buffer_copy(uuid.UUID(value).bytes_le)
def checked(result):
    if result < 0: raise OSError(f'Windows dialog error 0x{result & 0xffffffff:08X}')
    return result

def invoke(obj, index, types=(), args=(), result=HRESULT):
    table = C.cast(obj, C.POINTER(C.POINTER(PTR))).contents
    return C.WINFUNCTYPE(result, PTR, *types)(table[index])(obj, *args)

def release(obj):
    if obj: invoke(obj, 2, result=W.ULONG)

IID_UNKNOWN = guid('00000000-0000-0000-C000-000000000046')
IID_EVENTS = guid('973510DB-7D7F-452B-8975-74A85828D354')

def folder_view(dialog):
    """Return the current IFolderView2; the caller owns its COM reference."""
    provider = PTR(); browser = PTR(); view = PTR(); folder = PTR()
    try:
        checked(invoke(dialog, 0, (PTR, C.POINTER(PTR)),
            (guid('6D5140C1-7436-11CE-8034-00AA006009FA'), C.byref(provider))))
        checked(invoke(provider, 3, (PTR, PTR, C.POINTER(PTR)),
            (guid('4C96BE40-915C-11CF-99D3-00AA004AE837'),
             guid('000214E2-0000-0000-C000-000000000046'), C.byref(browser))))
        checked(invoke(browser, 15, (C.POINTER(PTR),), (C.byref(view),)))
        checked(invoke(view, 0, (PTR, C.POINTER(PTR)),
            (guid('1AF3A467-214F-4298-908E-06B03E0B39F9'), C.byref(folder))))
        return folder
    finally:
        release(view); release(browser); release(provider)

class Events:
    """Own the COM callbacks and native button handler until Show returns."""
    def __init__(self, dialog, owner, ole):
        self.dialog, self.owner, self.ole = dialog, owner, ole
        self.paths = []; self.error = None; self.references = 1; self.callbacks = []
        self.hwnd = None; self.window_handle = None; self.hook = None; self.accepting = False
        class Interface(C.Structure): _fields_ = [('table', C.POINTER(PTR))]
        def callback(return_type, types, function):
            wrapped = C.WINFUNCTYPE(return_type, PTR, *types)(function)
            self.callbacks.append(wrapped); return C.cast(wrapped, PTR).value
        def query(this, iid, output):
            output[0] = None
            raw = C.string_at(iid, 16)
            if raw in (bytes(IID_UNKNOWN), bytes(IID_EVENTS)): output[0] = C.addressof(self.events)
            else: return -2147467262  # E_NOINTERFACE
            self.references += 1; return 0
        def addref(this): self.references += 1; return self.references
        def drop(this): self.references -= 1; return self.references
        common = [callback(HRESULT, (PTR, C.POINTER(PTR)), query),
                  callback(W.ULONG, (), addref), callback(W.ULONG, (), drop)]
        def file_ok(this, dialog): return self.accept(False)
        def folder_changed(this, dialog):
            try: self.install_button_handler()
            except Exception as error: self.fail(error)
            return 0
        def response(this, dialog, item, output): output[0] = 0; return 0
        self.event_table = (PTR * 10)(*common,
            callback(HRESULT, (PTR,), file_ok),
            callback(HRESULT, (PTR, PTR), lambda *_: 0),
            callback(HRESULT, (PTR,), folder_changed),
            callback(HRESULT, (PTR,), lambda *_: 0),
            callback(HRESULT, (PTR, PTR, C.POINTER(W.DWORD)), response),
            callback(HRESULT, (PTR,), lambda *_: 0),
            callback(HRESULT, (PTR, PTR, C.POINTER(W.DWORD)), response))
        self.events = Interface(self.event_table)

    def install_button_handler(self):
        if self.hwnd: return
        window = PTR(); hwnd = W.HWND()
        checked(invoke(self.dialog, 0, (PTR, C.POINTER(PTR)),
            (guid('00000114-0000-0000-C000-000000000046'), C.byref(window))))
        try: checked(invoke(window, 3, (C.POINTER(W.HWND),), (C.byref(hwnd),)))
        finally: release(window)
        self.window_handle = hwnd.value
        self.user = C.WinDLL('user32', use_last_error=True)
        self.user.GetDlgItem.argtypes = [W.HWND, C.c_int]; self.user.GetDlgItem.restype = W.HWND
        self.user.GetFocus.restype = W.HWND
        self.user.PostMessageW.argtypes = [W.HWND, W.UINT, C.c_size_t, C.c_ssize_t]
        self.user.RegisterWindowMessageW.argtypes = [W.LPCWSTR]
        self.accept_message = self.user.RegisterWindowMessageW('YKA.SafeTransfer.AcceptSelection')
        if not self.accept_message: raise C.WinError(C.get_last_error())
        self.comctl = C.WinDLL('comctl32', use_last_error=True)
        procedure = C.WINFUNCTYPE(C.c_ssize_t, W.HWND, W.UINT, C.c_size_t, C.c_ssize_t, C.c_size_t, C.c_size_t)
        self.comctl.SetWindowSubclass.argtypes = [W.HWND, procedure, C.c_size_t, C.c_size_t]
        self.comctl.RemoveWindowSubclass.argtypes = [W.HWND, procedure, C.c_size_t]
        self.comctl.DefSubclassProc.argtypes = [W.HWND, W.UINT, C.c_size_t, C.c_ssize_t]
        self.comctl.DefSubclassProc.restype = C.c_ssize_t
        def dispatch(handle, message, wp, lp, ident, data):
            try:
                # Only the existing OK button. Shell double-click/Enter navigation
                # does not originate from this button and stays with Windows.
                if message == 0x111 and wp == 1:
                    button = self.user.GetDlgItem(handle, 1)
                    if button and (lp == button or (not lp and self.user.GetFocus() == button)):
                        if not self.user.PostMessageW(handle, self.accept_message, 0, 0): raise C.WinError(C.get_last_error())
                        return 0
                if message == self.accept_message:
                    self.accept(True); return 0
                if message == 0x82: self.remove_button_handler()  # WM_NCDESTROY
            except Exception as error:
                self.fail(error); return 0
            return self.comctl.DefSubclassProc(handle, message, wp, lp)
        self.hook = procedure(dispatch)
        if not self.comctl.SetWindowSubclass(hwnd, self.hook, 1, 0): raise C.WinError(C.get_last_error())
        self.hwnd = hwnd.value

    def remove_button_handler(self):
        if self.hwnd:
            self.comctl.RemoveWindowSubclass(self.hwnd, self.hook, 1)
            self.hwnd = None

    def fail(self, error):
        # Error cleanup itself must never escape a COM/window callback. Preserve
        # the operation error and never return a selection after partial failure.
        self.error = error; self.paths = []
        hwnd = self.window_handle
        for cleanup in (self.remove_button_handler,
                        lambda: checked(invoke(self.dialog, 23, (HRESULT,), (-2147467259,)))):
            try: cleanup()
            except Exception as cleanup_error: error.add_note('Dialog cleanup failed: ' + str(cleanup_error))
        if hwnd:
            try:
                if not self.user.PostMessageW(hwnd, 0x10, 0, 0): raise C.WinError(C.get_last_error())
            except Exception as cleanup_error: error.add_note('Dialog dismissal failed: ' + str(cleanup_error))

    def view_selection(self):
        view = folder_view(self.dialog); array = PTR()
        try:
            hr = invoke(view, 32, (W.BOOL, C.POINTER(PTR)), (False, C.byref(array)))
            if hr & 0xffffffff == 0x80070490: return []  # No selection in the view.
            checked(hr)
            return self.array_paths(array) if array else []
        finally: release(array); release(view)

    def selected(self, method):
        array = PTR()
        hr = invoke(self.dialog, method, (C.POINTER(PTR),), (C.byref(array),))
        if method == 28 and hr == -2147467259:  # Shell returns E_FAIL for an empty selection.
            name = PTR()
            invoke(self.dialog, 16, (C.POINTER(PTR),), (C.byref(name),))
            try:
                if not name or not C.wstring_at(name).strip(): return []
            finally: self.ole.CoTaskMemFree(name)
        checked(hr)
        try: return self.array_paths(array)
        finally: release(array)

    def array_paths(self, array):
        count = W.DWORD(); checked(invoke(array, 7, (C.POINTER(W.DWORD),), (C.byref(count),)))
        paths = []
        for i in range(count.value):
            item = PTR(); checked(invoke(array, 8, (W.DWORD, C.POINTER(PTR)), (i, C.byref(item))))
            try:
                name = PTR()
                checked(invoke(item, 5, (W.DWORD, C.POINTER(PTR)), (0x80058000, C.byref(name))))
                try: paths.append(C.wstring_at(name))
                finally: self.ole.CoTaskMemFree(name)
            finally: release(item)
        return paths


    def accept(self, explicit):
        # Never allow a Python exception to cross the native callback boundary.
        if self.accepting: return 1
        self.accepting = True
        try:
            paths = (self.view_selection() or self.selected(28)) if explicit else self.selected(27)
            if not paths:
                user = C.WinDLL('user32', use_last_error=True)
                user.MessageBoxW.argtypes = [W.HWND, W.LPCWSTR, W.LPCWSTR, W.UINT]
                user.MessageBoxW(self.hwnd or self.owner, 'Select at least one file.', 'Safe Transfer', 0x30)
                return 1
            self.paths = paths
            if explicit:
                # We already own the complete selection. Let the native dialog
                # dismiss normally, without running its file-only Open handler.
                hwnd = self.hwnd
                self.remove_button_handler()
                if not self.user.PostMessageW(hwnd, 0x10, 0, 0): raise C.WinError(C.get_last_error())
            return 0
        except Exception as error:
            self.fail(error)
            return 1
        finally: self.accepting = False


def choose_items(parent, initial=''):
    ole = C.OleDLL('ole32')
    ole.CoInitializeEx.argtypes = [PTR, W.DWORD]
    ole.CoCreateInstance.argtypes = [PTR, PTR, W.DWORD, PTR, C.POINTER(PTR)]
    ole.CoTaskMemFree.argtypes = [PTR]; ole.CoTaskMemFree.restype = None
    checked(ole.CoInitializeEx(None, 2))
    dialog = PTR(); cookie = W.DWORD(); advised = False; events = None
    try:
        checked(ole.CoCreateInstance(guid('DC1C5A9C-E88A-4DDE-A5A1-60F82A20AEF7'), None, 1,
            guid('D57C7288-D4AD-4768-BE02-9D969532D960'), C.byref(dialog)))
        flags = W.DWORD(); checked(invoke(dialog, 10, (C.POINTER(W.DWORD),), (C.byref(flags),)))
        # Filesystem-only, multiple selection, no recent-item persistence, no link dereference.
        checked(invoke(dialog, 9, (W.DWORD,), (flags.value | 0x40 | 0x200 | 0x02000000 | 0x00100000,)))
        checked(invoke(dialog, 17, (W.LPCWSTR,), ('Choose files and folders.',)))
        checked(invoke(dialog, 18, (W.LPCWSTR,), ('Add',)))
        if initial:
            shell = C.OleDLL('shell32'); shell.SHCreateItemFromParsingName.argtypes = [W.LPCWSTR, PTR, PTR, C.POINTER(PTR)]
            folder = PTR()
            checked(shell.SHCreateItemFromParsingName(initial, None, guid('43826D1E-E718-42EE-BC55-A1E261C37BFE'), C.byref(folder)))
            try: checked(invoke(dialog, 12, (PTR,), (folder,)))
            finally: release(folder)
        events = Events(dialog, int(parent.winId()), ole)
        checked(invoke(dialog, 7, (PTR, C.POINTER(W.DWORD)), (C.byref(events.events), C.byref(cookie))))
        advised = True
        hr = invoke(dialog, 3, (W.HWND,), (int(parent.winId()),))
        if events.error: raise OSError('Windows selection failed') from events.error
        if hr & 0xffffffff == 0x800704C7: return events.paths
        checked(hr)
        return events.paths
    finally:
        if events: events.remove_button_handler()
        if advised: invoke(dialog, 8, (W.DWORD,), (cookie,))
        release(dialog)
        ole.CoUninitialize()
