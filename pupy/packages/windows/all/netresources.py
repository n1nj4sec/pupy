# -*- coding: utf-8 -*-

from ctypes import (
    WinDLL, Structure, POINTER, create_string_buffer,
    get_last_error, cast, c_void_p, WinError, byref, addressof
)

from ctypes.wintypes import (
    BOOL, DWORD, LPCWSTR, HANDLE
)

from psutil import disk_usage


class NETRESOURCE(Structure):
    _fields_ = (
        ('dwScope', DWORD),
        ('dwType', DWORD),
        ('dwDisplayType', DWORD),
        ('dwUsage', DWORD),
        ('lpLocalName', LPCWSTR),
        ('lpRemoteName', LPCWSTR),
        ('lpComment', LPCWSTR),
        ('lpProvider', LPCWSTR),
    )

PNETRESOURCE = POINTER(NETRESOURCE)
PHANDLE = POINTER(HANDLE)
PDWORD = POINTER(DWORD)
PVOID = c_void_p

RESOURCE_CONNECTED = 1
RESOURCE_GLOBALNET = 2
RESOURCE_REMEMBERED = 3
RESOURCE_RECENT = 4
RESOURCE_CONTEXT = 5

SCOPE_TEXT = {
    RESOURCE_CONNECTED: 'connected',
    RESOURCE_GLOBALNET: 'global',
    RESOURCE_REMEMBERED: 'remembered',
    RESOURCE_RECENT: 'recent',
    RESOURCE_CONTEXT: 'context'
}

RESOURCETYPE_ANY = 0
RESOURCETYPE_DISK = 1
RESOURCETYPE_PRINT = 2

RESOURCETYPE_TEXT = {
    RESOURCETYPE_ANY: 'any',
    RESOURCETYPE_DISK: 'disk',
    RESOURCETYPE_PRINT: 'print'
}

RESOURCETYPE_RESERVED = 8
RESOURCETYPE_UNKNOWN = 0xFFFFFFFF

RESOURCEUSAGE_CONNECTABLE = 0x00000001
RESOURCEUSAGE_CONTAINER = 0x00000002
RESOURCEUSAGE_NOLOCALDEVICE = 0x00000004
RESOURCEUSAGE_SIBLING = 0x00000008
RESOURCEUSAGE_ATTACHED = 0x00000010

RESOURCEUSAGE_TEXT = {
    RESOURCEUSAGE_CONNECTABLE: 'connectable',
    RESOURCEUSAGE_CONTAINER: 'container',
    RESOURCEUSAGE_NOLOCALDEVICE: 'nolocaldevice',
    RESOURCEUSAGE_SIBLING: 'sibling',
    RESOURCEUSAGE_ATTACHED: 'attached'
}

RESOURCEUSAGE_ALL = \
    RESOURCEUSAGE_CONNECTABLE | \
    RESOURCEUSAGE_CONTAINER | \
    RESOURCEUSAGE_ATTACHED

RESOURCEUSAGE_RESERVED = 0x80000000
RESOURCEDISPLAYTYPE_GENERIC = 0
RESOURCEDISPLAYTYPE_DOMAIN = 1
RESOURCEDISPLAYTYPE_SERVER = 2
RESOURCEDISPLAYTYPE_SHARE = 3
RESOURCEDISPLAYTYPE_FILE = 4
RESOURCEDISPLAYTYPE_GROUP = 5
RESOURCEDISPLAYTYPE_NETWORK = 6
RESOURCEDISPLAYTYPE_ROOT = 7
RESOURCEDISPLAYTYPE_SHAREADMIN = 8
RESOURCEDISPLAYTYPE_DIRECTORY = 9
RESOURCEDISPLAYTYPE_TREE = 10

RESOURCEDISPLAYTYPE_TEXT = {
    RESOURCEDISPLAYTYPE_GENERIC: 'generic',
    RESOURCEDISPLAYTYPE_DOMAIN: 'domain',
    RESOURCEDISPLAYTYPE_SERVER: 'server',
    RESOURCEDISPLAYTYPE_SHARE: 'share',
    RESOURCEDISPLAYTYPE_FILE: 'file',
    RESOURCEDISPLAYTYPE_GROUP: 'group',
    RESOURCEDISPLAYTYPE_NETWORK: 'network',
    RESOURCEDISPLAYTYPE_ROOT: 'root',
    RESOURCEDISPLAYTYPE_SHAREADMIN: 'shareadmin',
    RESOURCEDISPLAYTYPE_DIRECTORY: 'dir',
    RESOURCEDISPLAYTYPE_TREE: 'tree'
}

ERROR_NO_MORE_ITEMS = 259
ERROR_EXTENDED = 1208

mpr = WinDLL('mpr', use_last_error=True)

WNetEnumResource = mpr.WNetEnumResourceW
WNetEnumResource.restype = DWORD
WNetEnumResource.argtypes = (
  HANDLE, PDWORD, PVOID, PDWORD
)

WNetOpenEnum = mpr.WNetOpenEnumW
WNetOpenEnum.restype = DWORD
WNetOpenEnum.argtypes = (
    DWORD, DWORD, DWORD, PNETRESOURCE, PHANDLE
)

WNetCloseEnum = mpr.WNetCloseEnum
WNetCloseEnum.argtypes = (HANDLE,)


def EnumNetResources(scope=RESOURCE_CONNECTED, lpnr=None):
    hEnum = HANDLE()

    dwResult = WNetOpenEnum(
        scope,
        RESOURCETYPE_ANY,
        0,
        lpnr,
        byref(hEnum)
    )

    if dwResult == ERROR_EXTENDED:
        return []
    elif dwResult != 0:
        raise WinError(dwResult)

    results = []

    try:
        while True:
            dEntries = DWORD(-1)
            lpnrLocal = create_string_buffer(128 * 1024)
            cbBuffer = DWORD(len(lpnrLocal))

            dwResultEnum = WNetEnumResource(
                hEnum,
                byref(dEntries),
                byref(lpnrLocal),
                byref(cbBuffer)
            )

            if dwResultEnum == ERROR_NO_MORE_ITEMS:
                break
            elif dwResultEnum != 0:
                raise WinError(dwResultEnum)

            entries = cast(
                lpnrLocal, POINTER(NETRESOURCE * dEntries.value)
            ).contents

            for entry in entries:
                if not entry.lpProvider:
                    break

                usage_flags = []

                for value, name in RESOURCEUSAGE_TEXT.iteritems():
                    if (entry.dwUsage & value) == value:
                        usage_flags.append(name)

                result = {
                    'scope': SCOPE_TEXT.get(entry.dwScope, 'unknown'),
                    'type': RESOURCETYPE_TEXT.get(entry.dwType, 'any'),
                    'displayType': RESOURCEDISPLAYTYPE_TEXT.get(
                        entry.dwDisplayType, 'any'),
                    'usage': usage_flags,
                    'local': unicode(
                        entry.lpLocalName) if entry.lpLocalName else None,
                    'remote': unicode(
                        entry.lpRemoteName) if entry.lpRemoteName else None,
                    'comment': unicode(
                        entry.lpComment) if entry.lpComment else None,
                    'provider': unicode(
                        entry.lpProvider) if entry.lpProvider else None,
                }

                if (entry.dwUsage & RESOURCEUSAGE_CONTAINER) == RESOURCEUSAGE_CONTAINER:
                    result['childs'] = EnumNetResources(scope, byref(entry))

                if result['type'] == 'disk' and result['scope'] == 'connected':
                    try:
                        usage = disk_usage(result['remote'])
                        result.update({
                            'total': usage.total,
                            'used': usage.used,
                            'free': usage.free,
                            'percent': usage.percent
                        })
                    except WindowsError:
                        pass

                results.append(result)

        return results

    finally:
        WNetCloseEnum(hEnum)


def EnumAllNetResources():
    results = {}
    for value, text in SCOPE_TEXT.iteritems():
        try:
           results[text] = EnumNetResources(value)
        except WinError:
            pass

    return results
