from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from _winreg import (
    ConnectRegistry, HKEY_LOCAL_MACHINE,
    OpenKey, QueryValueEx, CloseKey
)

def get_domain_controller():

    aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
    keypath = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History\\"
    subkey_name = 'DCName'
    try:
        aKey = OpenKey(aReg, keypath)
        val, _ = QueryValueEx(aKey, subkey_name)
        CloseKey(aKey)
        return val
    except:
        return False
