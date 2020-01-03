# -*- coding: utf-8 -*-


from fsutils import has_xattrs
from os import stat, path
from junctions import islink, readlink
from struct import pack, unpack

from pupyutils.basic_cmds import mode_to_letter, try_exc_utf8

from pupwinutils.security import (
    getfileowneracls, kernel32,
    get_last_error, WinError, byref, cast, sizeof, addressof,
    WinDLL, create_string_buffer, Structure, _bit,
    BOOL, WORD, DWORD, LPCWSTR, LPVOID, PDWORD,
    POINTER, HANDLE, BYTE, ULONG
)

FILE_VER_GET_LOCALISED = 0x01
FILE_VER_GET_NEUTRAL = 0x02
FILE_VER_GET_PREFETCHED = 0x04

VS_FF_DEBUG = 0x00000001
VS_FF_INFOINFERRED = 0x00000010
VS_FF_PATCHED = 0x00000004
VS_FF_PRERELEASE = 0x00000002
VS_FF_PRIVATEBUILD = 0x00000008
VS_FF_SPECIALBUILD = 0x00000020

VS_FF_STR = {
    VS_FF_DEBUG: 'DEBUG',
    VS_FF_INFOINFERRED: 'INFOINFERRED',
    VS_FF_PATCHED: 'PATCHED',
    VS_FF_PRERELEASE: 'PRERELEASE',
    VS_FF_PRIVATEBUILD: 'PRIVATEBUILD',
    VS_FF_SPECIALBUILD: 'SPECIALBUILD'
}

VFT_APP = 0x00000001
VFT_DLL = 0x00000002
VFT_DRV = 0x00000003
VFT_FONT = 0x00000004
VFT_STATIC_LIB = 0x00000007
VFT_UNKNOWN = 0x00000000
VFT_VXD = 0x00000005

VFT_STR = {
    VFT_APP: 'APP',
    VFT_DLL: 'DLL',
    VFT_DRV: 'DRV',
    VFT_FONT: 'FONT',
    VFT_STATIC_LIB: 'STATIC_LIB',
    VFT_UNKNOWN: 'UNKNOWN',
    VFT_VXD: 'VXD'
}

VFT2_DRV_COMM = 0x0000000A
VFT2_DRV_DISPLAY = 0x00000004
VFT2_DRV_INSTALLABLE = 0x00000008
VFT2_DRV_KEYBOARD = 0x00000002
VFT2_DRV_LANGUAGE = 0x00000003
VFT2_DRV_MOUSE = 0x00000005
VFT2_DRV_NETWORK = 0x00000006
VFT2_DRV_PRINTER = 0x00000001
VFT2_DRV_SOUND = 0x00000009
VFT2_DRV_SYSTEM = 0x00000007
VFT2_DRV_VERSIONED_PRINTER = 0x0000000C
VFT2_UNKNOWN = 0x00000000

VFT2_DRV_STR = {
    VFT2_DRV_COMM: 'COMM',
    VFT2_DRV_DISPLAY: 'DISPLAY',
    VFT2_DRV_INSTALLABLE: 'INSTALLABLE',
    VFT2_DRV_KEYBOARD: 'KEYBOARD',
    VFT2_DRV_LANGUAGE: 'LANGUAGE',
    VFT2_DRV_MOUSE: 'MOUSE',
    VFT2_DRV_NETWORK: 'NETWORK',
    VFT2_DRV_PRINTER: 'PRINTER',
    VFT2_DRV_SOUND: 'SOUND',
    VFT2_DRV_SYSTEM: 'SYSTEM',
    VFT2_DRV_VERSIONED_PRINTER: 'VERSIONED_PRINTER',
    VFT2_UNKNOWN: 'UNKNOWN',
}

VFT2_FONT_RASTER = 0x00000001
VFT2_FONT_TRUETYPE = 0x00000003
VFT2_FONT_VECTOR = 0x00000002

VFT2_FONT_STR = {
    VFT2_FONT_RASTER: 'RASTER',
    VFT2_FONT_TRUETYPE: 'TRUETYPE',
    VFT2_FONT_VECTOR: 'VECTOR'
}

LOCALIZED_STRINGS = (
    'Comments',
    'InternalName',
    'ProductName',
    'CompanyName',
    'LegalCopyright',
    'ProductVersion',
    'FileDescription',
    'LegalTrademarks',
    'PrivateBuild',
    'FileVersion',
    'OriginalFilename',
    'SpecialBuild'
)

CERT_QUERY_OBJECT_FILE = 1

CERT_QUERY_CONTENT_CERT = 1
CERT_QUERY_CONTENT_CTL = 2
CERT_QUERY_CONTENT_CRL = 3
CERT_QUERY_CONTENT_SERIALIZED_STORE = 4
CERT_QUERY_CONTENT_SERIALIZED_CERT = 5
CERT_QUERY_CONTENT_SERIALIZED_CTL = 6
CERT_QUERY_CONTENT_SERIALIZED_CRL = 7
CERT_QUERY_CONTENT_PKCS7_SIGNED = 8
CERT_QUERY_CONTENT_PKCS7_UNSIGNED = 9
CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED = 10
CERT_QUERY_CONTENT_PKCS10 = 11
CERT_QUERY_CONTENT_PFX = 12
CERT_QUERY_CONTENT_CERT_PAIR = 13

CERT_QUERY_CONTENT_FLAG_CERT = (1 << CERT_QUERY_CONTENT_CERT)
CERT_QUERY_CONTENT_FLAG_CTL = (1 << CERT_QUERY_CONTENT_CTL)
CERT_QUERY_CONTENT_FLAG_CRL = (1 << CERT_QUERY_CONTENT_CRL)
CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE = (1 << CERT_QUERY_CONTENT_SERIALIZED_STORE)
CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT = (1 << CERT_QUERY_CONTENT_SERIALIZED_CERT)
CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL = (1 << CERT_QUERY_CONTENT_SERIALIZED_CTL)
CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL = (1 << CERT_QUERY_CONTENT_SERIALIZED_CRL)
CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED = (1 << CERT_QUERY_CONTENT_PKCS7_SIGNED)
CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED = (1 << CERT_QUERY_CONTENT_PKCS7_UNSIGNED)
CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = (1 << CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED)
CERT_QUERY_CONTENT_FLAG_PKCS10 = (1 << CERT_QUERY_CONTENT_PKCS10)
CERT_QUERY_CONTENT_FLAG_PFX = (1 << CERT_QUERY_CONTENT_PFX)
CERT_QUERY_CONTENT_FLAG_CERT_PAIR = (1 << CERT_QUERY_CONTENT_CERT_PAIR)

CERT_QUERY_CONTENT_FLAG_ALL = \
 CERT_QUERY_CONTENT_FLAG_CERT | \
 CERT_QUERY_CONTENT_FLAG_CTL | \
 CERT_QUERY_CONTENT_FLAG_CRL | \
 CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE | \
 CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT | \
 CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL | \
 CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL | \
 CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | \
 CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED | \
 CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | \
 CERT_QUERY_CONTENT_FLAG_PKCS10 | \
 CERT_QUERY_CONTENT_FLAG_PFX | \
 CERT_QUERY_CONTENT_FLAG_CERT_PAIR

CERT_QUERY_FORMAT_BINARY = 1
CERT_QUERY_FORMAT_BASE64_ENCODED = 2
CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED = 3

CERT_QUERY_FORMAT_FLAG_BINARY = (1 << CERT_QUERY_FORMAT_BINARY)
CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED = (1 << CERT_QUERY_FORMAT_BASE64_ENCODED)
CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED = (1 << CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED)

CMSG_ATTR_CERT_COUNT_PARAM = 11
CMSG_ATTR_CERT_PARAM = 12

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1

TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_FAIL = 0x800B010B
TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
TRUST_E_SYSTEM_ERROR = 0x80096001
TRUST_E_NO_SIGNER_CERT = 0x80096002
TRUST_E_COUNTER_SIGNER = 0x80096003
TRUST_E_CERT_SIGNATURE = 0x80096004
TRUST_E_TIME_STAMP = 0x80096005
TRUST_E_BAD_DIGEST = 0x80096010
TRUST_E_BASIC_CONSTRAINTS = 0x80096019
TRUST_E_FINANCIAL_CRITERIA = 0x8009601E
TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
TRUST_E_ACTION_UNKNOWN = 0x800B0002
TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
TRUST_E_NOSIGNATURE = 0x800B0100
CERT_E_UNTRUSTEDROOT = 0x800B0109
CERT_E_CHAINING = 0x800B010A

TRUST_E_STR = {
    TRUST_E_NOSIGNATURE: 'NOSIGNATURE',
    TRUST_E_FAIL: 'FAIL',
    TRUST_E_EXPLICIT_DISTRUST: 'EXPLICIT_DISTRUST',
    TRUST_E_SYSTEM_ERROR: 'SYSTEM_ERROR',
    TRUST_E_NO_SIGNER_CERT: 'NO_SIGNER_CERT',
    TRUST_E_COUNTER_SIGNER: 'COUNTER_SIGNER',
    TRUST_E_CERT_SIGNATURE: 'CERT_SIGNATURE',
    TRUST_E_TIME_STAMP: 'TIME_STAMP',
    TRUST_E_BAD_DIGEST: 'BAD_DIGEST',
    TRUST_E_BASIC_CONSTRAINTS: 'BASIC_CONSTRAINTS',
    TRUST_E_FINANCIAL_CRITERIA: 'FINANCIAL_CRITERIA',
    TRUST_E_PROVIDER_UNKNOWN: 'PROVIDER_UNKNOWN',
    TRUST_E_ACTION_UNKNOWN: 'ACTION_UNKNOWN',
    TRUST_E_SUBJECT_FORM_UNKNOWN: 'SUBJECT_FORM_UNKNOWN',
    TRUST_E_SUBJECT_NOT_TRUSTED: 'SUBJECT_NOT_TRUSTED',
    TRUST_E_NOSIGNATURE: 'NOSIGNATURE',
    CERT_E_UNTRUSTEDROOT: 'UNTRUSTEDROOT',
    CERT_E_CHAINING: 'CHAINING',
}

crypt32 = WinDLL('crypt32', use_last_error=True)
wintrust = WinDLL('wintrust', use_last_error=True)

CryptQueryObject = crypt32.CryptQueryObject
CryptQueryObject.restype = BOOL
CryptQueryObject.argtypes = (
    DWORD, LPCWSTR, DWORD, DWORD,
    DWORD, PDWORD, PDWORD, PDWORD,
    LPVOID,
    POINTER(LPVOID),
    POINTER(LPVOID)
)

CryptMsgGetParam = crypt32.CryptMsgGetParam
CryptMsgGetParam.restype = BOOL
CryptMsgGetParam.argtypes = (
    LPVOID,
    DWORD, DWORD,
    LPVOID, PDWORD
)

CertCloseStore = crypt32.CertCloseStore
CertCloseStore.restype = BOOL
CertCloseStore.argtypes = (
    LPVOID, DWORD
)

CryptMsgClose = crypt32.CryptMsgClose
CryptMsgClose.restype = BOOL
CryptMsgClose.argtypes = (
    LPVOID,
)

ver_lib = None

if hasattr(kernel32, 'GetFileVersionInfoSizeExW'):
    ver_lib = kernel32
else:
    try:
        ver_lib = WinDLL(
            'Api-ms-win-core-version-l1-1-0', use_last_error=True)

    except WindowsError:
        pass

if ver_lib:
    GetFileVersionInfoSizeExW = ver_lib.GetFileVersionInfoSizeExW
    GetFileVersionInfoExW = ver_lib.GetFileVersionInfoExW
    VerQueryValueW = ver_lib.VerQueryValueW

    GetFileVersionInfoSizeExW.restype = DWORD
    GetFileVersionInfoSizeExW.argtypes = (
        DWORD, LPCWSTR, PDWORD
    )

    GetFileVersionInfoExW.restype = BOOL
    GetFileVersionInfoExW.argtypes = (
        DWORD, LPCWSTR, DWORD, DWORD, LPVOID
    )

    VerQueryValueW.restype = BOOL
    VerQueryValueW.argtypes = (
        LPVOID, LPCWSTR, POINTER(LPVOID), PDWORD
    )

WinVerifyTrust = wintrust.WinVerifyTrust
WinVerifyTrust.restype = ULONG
WinVerifyTrust.argtypes = (
    LPVOID, LPVOID, LPVOID
)


class FIXEDFILEINFO(Structure):
    _fields_ = (
        ('dwSignature', DWORD),
        ('dwStrucVersion', DWORD),
        ('dwFileVersionMS', DWORD),
        ('dwFileVersionLS', DWORD),
        ('dwProductVersionMS', DWORD),
        ('dwProductVersionLS', DWORD),
        ('dwFileFlagsMask', DWORD),
        ('dwFileFlags', DWORD),
        ('dwFileOS', DWORD),
        ('dwFileType', DWORD),
        ('dwFileSubtype', DWORD),
        ('dwFileDateMS', DWORD),
        ('dwFileDateLS', DWORD)
    )


class LANGANDCODEPAGE(Structure):
    _fields_ = (
        ('wLanguage', WORD),
        ('wCodePage', WORD)
    )


class WINTRUST_FILE_INFO(Structure):
    _fields_ = (
        ('cbStruct', DWORD),
        ('pcwszFilePath', LPCWSTR),
        ('hFile', HANDLE),
        ('pgKnownSubject', LPVOID),
    )

    def __init__(self, filename):
        self.cbStruct = sizeof(self)
        self.pcwszFilePath = filename
        self.hFile = None
        self.pgKnownSubject = None


class WINTRUST_DATA(Structure):
    _fields_ = (
        ('cbStruct', DWORD),
        ('pPolicyCallbackData', LPVOID),
        ('pSIPClientData', LPVOID),
        ('dwUIChoice', DWORD),
        ('fdwRevocationChecks', DWORD),
        ('dwUnionChoice', DWORD),
        ('pvInfo', LPVOID),
        ('dwStateAction', DWORD),
        ('hWVTStateData', HANDLE),
        ('pwszURLReference', LPCWSTR),
        ('dwProvFlags', DWORD),
        ('dwUIContext', DWORD),
        ('pSignatureSettings', LPVOID),
    )

    def __init__(self, filename):
        self._pFile = WINTRUST_FILE_INFO(filename)

        self.cbStruct = DWORD(sizeof(self))
        self.pPolicyCallbackData = None
        self.pSIPClientData = None
        self.dwUIChoice = WTD_UI_NONE
        self.fdwRevocationChecks = WTD_REVOKE_NONE
        self.dwUnionChoice = WTD_CHOICE_FILE
        self.dwStateAction = WTD_STATEACTION_VERIFY
        self.hWVTStateData = None
        self.pwszURLReference = None
        self.dwUIContext = 0
        self.pvInfo = addressof(self._pFile)


class GUID(Structure):
    _fields_ = (
        ('Data1', DWORD),
        ('Data2', WORD),
        ('Data3', WORD),
        ('Data4', BYTE*8)
    )

    def __init__(self, u1, u2, u3, u4):
        self.Data1 = u1
        self.Data2 = u2
        self.Data3 = u3

        if isinstance(u4, bytes):
            self.Data4 = (BYTE*8)(*u4[:8])
        else:
            self.Data4 = (BYTE*8)(*u4)


WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0xaac56b, 0xcd44, 0x11d0, [
        0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee
    ]
)


def getfilever(filepath, flags=FILE_VER_GET_NEUTRAL, throw=False):
    if not ver_lib:
        return {}

    result = {}

    dwReserved = DWORD(0)
    dwVersionSize = GetFileVersionInfoSizeExW(flags, filepath, byref(dwReserved))
    if dwVersionSize == 0:
        if throw:
            raise WinError(get_last_error())

        return result

    pBuffer = create_string_buffer(dwVersionSize)
    bResult = GetFileVersionInfoExW(flags, filepath, 0, dwVersionSize, byref(pBuffer))
    if not bResult:
        if throw:
            raise WinError(get_last_error())

        return result

    info = FIXEDFILEINFO()
    dwSize = DWORD(0)
    pvData = LPVOID()

    bResult = VerQueryValueW(pBuffer, u'\\', byref(pvData), byref(dwSize))
    if bResult:
        info = cast(pvData, POINTER(FIXEDFILEINFO)).contents

        result['FileVersion'] = '{1}.{0}.{3}.{2}'.format(
            *unpack(
                '<HHHH', pack(
                    '<II', info.dwFileVersionMS, info.dwFileVersionLS))
        )

        result['ProductVersion'] = '{1}.{0}.{3}.{2}'.format(
            *unpack(
                '<HHHH', pack(
                    '<II', info.dwProductVersionMS, info.dwProductVersionLS))
        )

        flags = []
        valid_flags = info.dwFileFlags & info.dwFileFlagsMask
        if valid_flags:
            for flag, value in VS_FF_STR.iteritems():
                if _bit(flag, valid_flags):
                    flags.append(value)

        result['Flags'] = flags

        for flag, value in VFT_STR.iteritems():
            if _bit(flag, info.dwFileType):
                if flag == VFT_UNKNOWN:
                    break

                elif flag == VFT_DRV:
                    for subflag, subvalue in VFT2_DRV_STR.iteritems():
                        if _bit(subflag, info.dwFileSubtype):
                            value += '(' + subvalue + ')'
                            break
                elif flag == VFT_FONT:
                    for subflag, subvalue in VFT2_FONT_STR.iteritems():
                        if _bit(subflag, info.dwFileSubtype):
                            value += '(' + subvalue + ')'
                            break

                elif flag == VFT_VXD:
                    value += '(VxD={:08x})'.format(info.dwFileSubtype)

                result['Type'] = value
                break

        timestamp = info.dwFileDateMS << 32 | info.dwFileDateLS
        result['Timestamp'] = timestamp

    bResult = VerQueryValueW(
        pBuffer, u'\\VarFileInfo\\Translation', byref(pvData), byref(dwSize))

    if bResult:
        nRecords = dwSize.value / sizeof(LANGANDCODEPAGE)

        records = cast(pvData, POINTER(LANGANDCODEPAGE * nRecords)).contents
        translations = {}

        for translation in records:
            strings = {}

            for string in LOCALIZED_STRINGS:
                varpath = u'\\\\StringFileInfo\\{:04x}{:04x}\\{}'.format(
                    translation.wLanguage, translation.wCodePage, string
                )

                bResult = VerQueryValueW(pBuffer, varpath, byref(pvData), byref(dwSize))
                if not bResult:
                    continue

                strings[string] = unicode(
                    cast(pvData, LPCWSTR).value
                ).encode('utf-8')

            if strings:
                translations[translation.wLanguage] = strings

        if translations:
            found = False
            for preferred_translation in (0, 2057):
                if preferred_translation in translations:
                    result.update(translations[preferred_translation])
                    found = True
                    break

            if not found:
                # Just pick any
                result.update(next(iter(translations.itervalues())))

    return result


def getfilecert(filepath, throw=False):
    dwEncoding = DWORD()
    dwContentType = DWORD()
    dwFormatType = DWORD()
    hStore = LPVOID()
    hMsg = LPVOID()

    bResult = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        filepath,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        byref(dwEncoding), byref(dwContentType),
        byref(dwFormatType), byref(hStore),
        byref(hMsg), None
    )

    if not bResult:
        if throw:
            raise WinError(get_last_error())

        return {}

    try:
        dwCertsCount = DWORD(-1)
        dwArgSize = DWORD(sizeof(dwCertsCount))

        bResult = CryptMsgGetParam(
            hMsg,
            CMSG_ATTR_CERT_COUNT_PARAM,
            0,
            byref(dwCertsCount), byref(dwArgSize)
        )

        if not bResult:
            if throw:
                raise WinError(get_last_error())

            return {}

        certificates = []

        for idx in xrange(dwCertsCount.value):
            dwArgSize = DWORD(-1)
            CryptMsgGetParam(
                hMsg,
                CMSG_ATTR_CERT_PARAM,
                idx,
                None, byref(dwArgSize)
            )

            if dwArgSize == DWORD(-1):
                if throw:
                    raise WinError(get_last_error())
                break

            pBuffer = create_string_buffer(dwArgSize.value)

            bResult = CryptMsgGetParam(
                hMsg,
                CMSG_ATTR_CERT_PARAM,
                idx,
                byref(pBuffer), byref(dwArgSize)
            )

            if not bResult:
                if throw:
                    raise WinError(get_last_error())

                continue

            certificates.append(pBuffer.raw)

        return {
            'Certificates': certificates
        }

    finally:
        if hStore:
            CertCloseStore(hStore, 0)

        if hMsg:
            CryptMsgClose(hMsg)


def getfiletrust(filepath):
    trust = WINTRUST_DATA(filepath)
    lStatus = WinVerifyTrust(
        None,
        byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
        byref(trust)
    )

    if lStatus == 0:
        return {
            'Signature': 'VALID'
        }

    return {
        'Signature': TRUST_E_STR.get(
            lStatus, 'Error: {:08x}'.format(lStatus))
    }



def getfilesec(filepath):
    header = ''

    filepath = path.expanduser(filepath)
    filepath = path.expandvars(filepath)

    if path.isfile(filepath):
        try:
            with open(filepath) as fileobj:
                header = fileobj.read(4096)
        except (OSError, IOError):
            pass

    try:
        filestat = stat(filepath)
        owner, group, acls = getfileowneracls(filepath)
        streams = has_xattrs(filepath)
        link = None
    except Exception as e:
        try_exc_utf8(e)
        raise

    try:
        if islink(filepath):
            link = readlink(filepath)
    except (WindowsError, ValueError, OSError, IOError):
        pass

    mode = mode_to_letter(filestat.st_mode)

    extras = {
        'ACLs': [unicode(x) for x in acls] if acls else None,
        'Streams': streams,
        'Link': link,
        'Version': getfilever(filepath),
    }

    certs = getfilecert(filepath)
    if certs:
        extras.update(certs)
        extras.update(getfiletrust(filepath))

    return int(filestat.st_ctime), int(filestat.st_atime), \
      int(filestat.st_mtime), filestat.st_size, owner, group, \
      header, mode, {k:v for k,v in extras.iteritems() if v}
