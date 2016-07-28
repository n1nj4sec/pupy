from rpyc.utils.classic import upload
import base64
from subprocess import PIPE, Popen
import subprocess

def execute_powershell_script(module, content, function):
    fullargs=["powershell.exe", "-C", "-"]
    
    p = module.client.conn.modules.subprocess.Popen(fullargs, stdout=PIPE, stderr=PIPE, stdin=PIPE, bufsize=0, universal_newlines=True, shell=True)
    p.stdin.write("$base64=\"\""+"\n")
    n = 20000
    line = base64.b64encode(content)
    tab = [line[i:i+n] for i in range(0, len(line), n)]
    for t in tab:
        p.stdin.write("$base64+=\"%s\"\n" % t)
        p.stdin.flush()   

    p.stdin.write("$d=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64))\n")
    p.stdin.write("Invoke-Expression $d\n")
    p.stdin.write("$a=Invoke-Expression %s | Format-Table -HideTableHeaders | Out-String\n" % function)
    p.stdin.write("$b=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(\"$a\"))\n")
    p.stdin.write("Write-Host $b\n")

    # Get the result
    output = ""
    for i in p.stdout.readline():
        output += i
    output = base64.b64decode(output)
    p.stdin.write("exit\n")
    return output
