# -*- coding: utf-8 -*-

import pupy

from threading import Thread

from ctypes import (
    c_void_p, byref, Structure, HRESULT, POINTER,
    WinError, get_last_error, create_string_buffer
)

from ctypes.wintypes import (
    HANDLE, DWORD, SHORT, BOOL
)

from pupwinutils.security import (
    CloseHandle, CreatePipe, TerminateProcess, WaitForSingleObject,
    ReadFile, WriteFile,
    start_proc_with_token, kernel32,
    StartupInfoAttribute, GetExitCodeProcess,
    impersonate_token, CreateFile,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, S_OK,
    INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    STILL_ACTIVE, INVALID_HANDLE, GENERIC_READ, OPEN_EXISTING,

)

if hasattr(pupy, 'get_logger'):
    logger = pupy.get_logger('conpty')
else:
    import logging
    logger = logging.getLogger('conpty')

PHANDLE = POINTER(HANDLE)
HPCON = c_void_p

ENABLE_PROCESSED_OUTPUT = 0x1
ENABLE_WRAP_AT_EOL_OUTPUT = 0x2
ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x4
ENABLE_MOUSE_INPUT = 0x10


class COORD(Structure):
    _fields_ = (
        ('X', SHORT),
        ('Y', SHORT)
    )


try:
    GetConsoleMode = kernel32.GetConsoleMode
    GetConsoleMode.restype = BOOL
    GetConsoleMode.argtypes = (
        HANDLE, POINTER(DWORD)
    )

    GetFileType = kernel32.GetFileType
    GetFileType.restype = DWORD
    GetFileType.argtypes = (HANDLE,)

    GetStdHandle = kernel32.GetStdHandle
    GetStdHandle.restype = HANDLE
    GetStdHandle.argtype = (DWORD,)

    SetStdHandle = kernel32.SetStdHandle
    SetStdHandle.restype = HANDLE
    SetStdHandle.argtype = (DWORD, HANDLE)

    SetConsoleMode = kernel32.SetConsoleMode
    SetConsoleMode.restype = BOOL
    SetConsoleMode.argtypes = (
        HANDLE, DWORD
    )

    CreatePseudoConsole = kernel32.CreatePseudoConsole
    CreatePseudoConsole.restype = HRESULT
    CreatePseudoConsole.argtypes = (
        COORD, HANDLE, HANDLE, DWORD, POINTER(HPCON)
    )

    ResizePseudoConsole = kernel32.ResizePseudoConsole
    ResizePseudoConsole.result = HRESULT
    ResizePseudoConsole.argtypes = (
        HPCON, COORD
    )

    ClosePseudoConsole = kernel32.ClosePseudoConsole
    ClosePseudoConsole.argtypes = (HPCON,)

except AttributeError:
    raise ImportError('PseudoConsole is not supported')


def fix_stdin():
    hHandleStdin = GetStdHandle(-10)
    if hHandleStdin == INVALID_HANDLE:
        return

    hStdinFileType = GetFileType(hHandleStdin)
    if hStdinFileType != 3:
        return

    # Need to reopen CONNIN$
    hHandleStdin = CreateFile(
        'CONIN$', GENERIC_READ, OPEN_EXISTING,
        0, 4, 0, 0
    )

    if hHandleStdin != INVALID_HANDLE:
        SetStdHandle(-10, hHandleStdin)


class ConPTY(object):
    __slots__ = (
        '_closed', '_conout_pipe', '_conin_pipe', '_pty', '_lpInfo', '_reader'
    )

    def _create_pty(self, pty_size):
        hPipePTYOut = HANDLE(INVALID_HANDLE_VALUE)
        hPipePTYIn = HANDLE(INVALID_HANDLE_VALUE)

        hPipeOut = HANDLE(INVALID_HANDLE_VALUE)
        hPipeIn = HANDLE(INVALID_HANDLE_VALUE)

        hPTY = HPCON(INVALID_HANDLE_VALUE)

        try:
            if not CreatePipe(byref(hPipePTYIn), byref(hPipeIn), None, 0):
                raise WinError(get_last_error())

            if not CreatePipe(byref(hPipeOut), byref(hPipePTYOut), None, 0):
                raise WinError(get_last_error())

            if CreatePseudoConsole(
                    COORD(*pty_size), hPipePTYIn, hPipePTYOut, 0, byref(hPTY)) != S_OK:
                raise WinError(get_last_error())

            logger.info('hPTY: %x', hPTY.value)

            if hPTY.value == INVALID_HANDLE_VALUE:
                raise WinError(get_last_error())

        except WinError:
            for handle in (hPipePTYOut, hPipePTYIn, hPipeOut, hPipeIn):
                if handle.value != INVALID_HANDLE_VALUE:
                    CloseHandle(handle)

            raise

        CloseHandle(hPipePTYIn)
        CloseHandle(hPipePTYOut)

        self._pty = hPTY
        self._conout_pipe = hPipeOut
        self._conin_pipe = hPipeIn

    def __init__(self, program,
            cmdline=None, cwd=None, env=None, htoken=None,
            pty_flags=0, pty_size=(80,25)):

        self._closed = False
        self._lpInfo = None
        self._create_pty(pty_size)

        requested_htoken = None

        if htoken:
            caller_thread_htoken, requested_htoken = htoken
            impersonate_token(caller_thread_htoken)

        fix_stdin()

        self._lpInfo = start_proc_with_token(
            cmdline, requested_htoken,
            lpInfo=True,
            # Important - will not work otherwise
            hidden=False,
            application=program,
            attributes=[
                StartupInfoAttribute(
                    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                    self._pty
                )
            ]
        )

    @property
    def pid(self):
        return self._lpInfo.dwProcessId

    def active(self):
        if not self._lpInfo:
            logger.error('Child process was not initialized')
            return None

        status = DWORD()
        return GetExitCodeProcess(
            self._lpInfo.hProcess, byref(status)) and status.value == STILL_ACTIVE

    def _read_loop(self, read_cb):
        while True:
            try:
                data = self.read()
                if not data:
                    break

                read_cb(data)

            except Exception as e:
                logger.exception('Read from pipe: %s', e)
                break

    def read_loop(self, read_cb):
        logger.info('Start info loop')

        self._reader = Thread(target=self._read_loop, args=(read_cb,))
        self._reader.start()

        while self.active() and self._reader.isAlive():
            result = WaitForSingleObject(self._lpInfo.hProcess, 1000)
            if result == WAIT_TIMEOUT:
                logger.info('Timeout!')
                continue

            elif result == WAIT_OBJECT_0:
                status = DWORD(-1)
                GetExitCodeProcess(self._lpInfo.hProcess, byref(status))
                logger.info(
                    'Exited (%08x, hPTY=%x)!', status.value, self._pty.value
                )
                break

            else:
                raise WinError(get_last_error())

        CloseHandle(self._conin_pipe)
        self._conin_pipe = INVALID_HANDLE_VALUE

        logger.info('Everything completed')

    def write(self, data):
        if self._closed or self._conin_pipe == INVALID_HANDLE_VALUE:
            logger.info('Write - invalid state')
            return False

        written = DWORD()

        if not WriteFile(self._conin_pipe, data, len(data), byref(written), None):
            error = get_last_error()
            logger.info('Write error (%d)', error)
            raise WinError(error)

    def read(self, amount=8192):
        buffer = create_string_buffer(amount)
        read = DWORD()

        if not ReadFile(self._conout_pipe, buffer, amount, byref(read), None):
            error = get_last_error()
            logger.info('Read error (%d)', error)

            # Closed pipe
            if error == 109:
                return ''

            raise WinError(error)

        if not read.value:
            return ''

        return buffer[:read.value]

    def resize(self, cols, rows):
        if self._closed:
            return False

        if ResizePseudoConsole(self._pty, COORD(cols, rows)) != S_OK:
            error = get_last_error()
            logger.info('Resize error (%d)', error)
            raise WinError(error)

    def close(self):
        if self._closed:
            return False

        self._closed = True

        if self._conin_pipe != INVALID_HANDLE_VALUE:
            CloseHandle(self._conin_pipe)

        if self.active():
            TerminateProcess(self._lpInfo.hProcess, 0)
            CloseHandle(self._lpInfo.hProcess)
            CloseHandle(self._lpInfo.hThread)

        if self.active():
            logger.error('Child process was not terminated')

        if self._pty != INVALID_HANDLE_VALUE:
            ClosePseudoConsole(self._pty)

        if self._reader:
            # Read all the pipe if there is any to read
            self._reader.join()

        if self._conout_pipe.value != INVALID_HANDLE_VALUE:
            CloseHandle(self._conout_pipe)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
