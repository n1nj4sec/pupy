# -*- coding: utf-8 -*-

from contextlib import contextmanager

from ctypes import *
from ctypes.wintypes import *

from win32file import CreateFile, ReadFile, WriteFile, CloseHandle
from win32file import GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING

from win32pipe import PeekNamedPipe

import pupy

WINPTY_ERROR_SUCCESS = 0
WINPTY_ERROR_OUT_OF_MEMORY = 1
WINPTY_ERROR_SPAWN_CREATE_PROCESS_FAILED = 2
WINPTY_ERROR_LOST_CONNECTION = 3
WINPTY_ERROR_AGENT_EXE_MISSING = 4
WINPTY_ERROR_UNSPECIFIED = 5
WINPTY_ERROR_AGENT_DIED = 6
WINPTY_ERROR_AGENT_TIMEOUT = 7
WINPTY_ERROR_AGENT_CREATION_FAILED = 8

WINPTY_FLAG_CONERR = 0x1
WINPTY_FLAG_PLAIN_OUTPUT = 0x2
WINPTY_FLAG_COLOR_ESCAPES = 0x4
WINPTY_FLAG_ALLOW_CURPROC_DESKTOP_CREATION = 0x8

WINPTY_MOUSE_MODE_NONE = 0
WINPTY_MOUSE_MODE_AUTO = 1
WINPTY_MOUSE_MODE_FORCE = 2

WINPTY_SPAWN_FLAG_AUTO_SHUTDOWN = 1
WINPTY_SPAWN_FLAG_EXIT_AFTER_SHUTDOWN = 2

DLLNAME = 'WINPTY.DLL'

_functions = {
    'winpty_error_code': CFUNCTYPE(DWORD, c_void_p),
    'winpty_error_msg': CFUNCTYPE(LPCWSTR, c_void_p),
    'winpty_error_free': CFUNCTYPE(None, c_void_p),
    'winpty_config_new': CFUNCTYPE(c_void_p, c_ulonglong, c_void_p),
    'winpty_config_free': CFUNCTYPE(None, c_void_p),
    'winpty_config_set_initial_size': CFUNCTYPE(None, c_void_p, c_int, c_int),
    'winpty_config_set_mouse_mode': CFUNCTYPE(None, c_void_p, c_int),
    'winpty_config_set_agent_timeout': CFUNCTYPE(None, c_void_p, c_uint),
    'winpty_open': CFUNCTYPE(c_void_p, c_void_p, c_void_p),
    'winpty_free': CFUNCTYPE(None, c_void_p),
    'winpty_agent_process': CFUNCTYPE(HWND, c_void_p),
    'winpty_spawn_config_new': CFUNCTYPE(
        c_void_p, c_ulonglong, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, c_void_p),
    'winpty_spawn_config_free': CFUNCTYPE(None, c_void_p),
    'winpty_spawn': CFUNCTYPE(c_int, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p),
    'winpty_set_size': CFUNCTYPE(c_int, c_void_p, c_int, c_int, c_void_p),
    'winpty_conin_name': CFUNCTYPE(LPCWSTR, c_void_p),
    'winpty_conout_name': CFUNCTYPE(LPCWSTR, c_void_p),
    'winpty_conerr_name': CFUNCTYPE(LPCWSTR, c_void_p)
}

for funcname, definition in _functions.iteritems():
    funcaddr = pupy.find_function_address(DLLNAME, funcname)
    if not funcaddr:
        raise ImportError("Couldn't find function {} at winpty.dll".format(funcname))
    globals()[funcname] = definition(funcaddr)

class WinPTYException(Exception):
    def __init__(self, code, message):
        Exception.__init__(self, message)
        self.code = code

@contextmanager
def winpty_error():
    error = c_void_p(None)
    try:
        yield pointer(error)
        code = winpty_error_code(error)
        if code != WINPTY_ERROR_SUCCESS:
            message = winpty_error_msg(error)
            raise WinPTYException(code, message)
    finally:
        winpty_error_free(error)

class WinPTY(object):
    def __init__(self, program,
            cmdline=None, cwd=None, env=None,
            spawn_flags=WINPTY_SPAWN_FLAG_AUTO_SHUTDOWN|WINPTY_SPAWN_FLAG_EXIT_AFTER_SHUTDOWN,
            pty_flags=0, pty_size=(80,25), pty_mouse=WINPTY_MOUSE_MODE_NONE):

        self._closed = False

        config = None
        try:
            with winpty_error() as error:
                config = winpty_config_new(pty_flags, error)

            cols, rows = pty_size
            if cols and rows:
                winpty_config_set_initial_size(config, cols, rows)
            winpty_config_set_mouse_mode(config, pty_mouse)

            with winpty_error() as error:
                self._pty = winpty_open(config, error)
        finally:
            winpty_config_free(config)

        self._conin = winpty_conin_name(self._pty)
        self._conout = winpty_conout_name(self._pty)
        self._conerr = winpty_conerr_name(self._pty)

        try:
            self._conin_pipe = CreateFile(
                self._conin,
                GENERIC_WRITE,
                0, None,
                OPEN_EXISTING,
                0, None
            )

            self._conout_pipe = CreateFile(
                self._conout,
                GENERIC_READ,
                0, None,
                OPEN_EXISTING,
                0, None
            )

            if self._conerr:
                self._conerr_pipe = CreateFile(
                    self._conerr,
                    GENERIC_READ,
                    0, None,
                    OPEN_EXISTING,
                    0, None
                )
            else:
                self._conerr_pipe = None

            try:
                spawn_ctx = None
                process_handle = HANDLE()
                thread_handle = HANDLE()
                create_process_error = DWORD()

                with winpty_error() as error:
                    spawn_ctx = winpty_spawn_config_new(
                        spawn_flags, program, cmdline, cwd, env, error
                    )

                with winpty_error() as error:
                    winpty_spawn(
                        self._pty, spawn_ctx,
                        pointer(process_handle),
                        pointer(thread_handle),
                        pointer(create_process_error),
                        error
                    )

            finally:
                winpty_spawn_config_free(spawn_ctx)

        except:
            self.close()
            raise

    def write(self, data):
        if self._closed:
            return False

        try:
            WriteFile(self._conin_pipe, data)
            return True
        except:
            return False

    def read(self, amount=8192):
        if self._closed:
            return False

        try:
            error, data = ReadFile(self._conout_pipe, amount)
        except:
            data = None

        return data

    def resize(self, cols, rows):
        if self._closed:
            return False

        with winpty_error() as error:
            winpty_set_size(self._pty, rows, cols, error)

    def close(self):
        if self._closed:
            return False

        self._closed = True

        CloseHandle(self._conin_pipe)
        CloseHandle(self._conout_pipe)
        if self._conerr_pipe:
            CloseHandle(self._conerr_pipe)
        winpty_free(self._pty)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
