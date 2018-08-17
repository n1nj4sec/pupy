# -*- coding: utf-8 -*-

import re

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

def obfs_ps_script(script):
    """
    Strip block comments, line comments, empty lines, verbose statements,
    and debug statements from a PowerShell source file.
    """
    # strip block comments
    strippedCode = re.sub(re.compile('<#.*?#>', re.DOTALL), '', script)
    # strip blank lines, lines starting with #, and verbose/debug statements
    strippedCode = "\n".join([line for line in strippedCode.split('\n') if ((line.strip() != '') and (not line.strip().startswith("#")) and (not line.strip().lower().startswith("write-verbose ")) and (not line.strip().lower().startswith("write-debug ")))])
    return strippedCode

def obfuscatePowershellScript(code):
    '''
    Try to clean powershell script (perhaps in the future 'obfuscation'...).
    Comments are deteleted and some strings are replaced in some powershell functions to bypass AV detection
    '''
    newCode = code
    newCode = remove_comments(newCode)
    newCode = obfs_ps_script(newCode)
    # For Avast detection bypass. Very easy to bypass the AV detection : Shame on you Avast -:)
    # Notice only Avast and Ikarus detect Invoke-ReflectivePEInjection.ps1 as a 'virus' (BV:AndroDrp-B [Drp], HackTool.Win32.Mikatz)
    if "function Invoke-ReflectivePEInjection" in newCode:
        newCode = newCode.replace("$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null", "$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERIS'+'TICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null")
    return newCode
