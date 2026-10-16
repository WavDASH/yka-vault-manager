"""Frozen entry point, with pipe-only worker mode and no secret argv options."""
import sys


def attach_pipe(name, handle_id, mode):
    import ctypes
    import msvcrt
    import os
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetStdHandle.restype = ctypes.c_void_p
    kernel.GetFileType.argtypes = [ctypes.c_void_p]
    handle = kernel.GetStdHandle(handle_id)
    if kernel.GetFileType(handle) != 3: raise SystemExit('Worker requires inherited anonymous pipes')
    # Python windowed bootloader leaves std streams None; attach to its inherited pipe handles.
    descriptor = msvcrt.open_osfhandle(handle, (os.O_RDONLY if mode == 'r' else os.O_WRONLY) | os.O_BINARY)
    setattr(sys, name, os.fdopen(descriptor, mode, encoding='utf-8', buffering=1))


if __name__ == '__main__':
    if '--worker' in sys.argv or '--measure-size' in sys.argv:
        if sys.stdin is None: attach_pipe('stdin', -10, 'r')
        if sys.stdout is None: attach_pipe('stdout', -11, 'w')
        if '--measure-size' in sys.argv:
            from yka.vault_size import main
        else:
            from yka.worker import main
    elif '--check-icons' in sys.argv:
        from yka.icon_check import main
    else:
        from yka.gui import main
    main()
