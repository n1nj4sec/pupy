from __future__ import print_function
import sys
import os
import imp

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

print("ROOT: ", ROOT)

PATCHES = os.path.join(ROOT, 'pupy', 'library_patches')

sys.path.insert(0, PATCHES)
sys.path.append(os.path.join(ROOT, 'pupy'))
sys.path.append(os.path.join(ROOT, 'pupy', 'pupylib'))


sys.path.append(os.path.join(ROOT, 'pupy', 'packages', 'all'))

if sys.platform == 'win32':
    sys.path.append(os.path.join(ROOT, 'pupy', 'packages', 'windows', 'all'))
elif sys.platform.startswith('linux'):
    sys.path.append(os.path.join(ROOT, 'pupy', 'packages', 'linux', 'all'))
    sys.path.append(os.path.join(ROOT, 'pupy', 'packages', 'posix', 'all'))
else:
    sys.path.append(os.path.join(ROOT, 'pupy', 'packages', 'posix', 'all'))

from PupyCompile import pupycompile

import additional_imports
import Crypto

try:
    import idna
except ImportError:
    print("[W] idna not found")

try:
    import pp
except ImportError:
    pass

import site
import marshal

sys_modules = [
    (x,sys.modules[x]) for x in sys.modules.keys()
]

compile_map = []

def compile_py(path):
    global compile_map
    global fileid

    fileid = len(compile_map)
    compile_map.append(path)

    data = pupycompile(path, 'f:{:x}'.format(fileid), path=True)
    print("[C] {} -> f:{:x}".format(path, fileid))

    return data

all_dependencies=set(
    [
        x.split('.')[0] for x,m in sys_modules \
            if not '(built-in)' in str(m) and x != '__main__'
    ] + [
        'Crypto', 'rpyc', 'pyasn1', 'rsa', 'stringprep'
    ]
)

all_dependencies.add('site')

all_dependencies = sorted(list(set(all_dependencies)))
all_dependencies.remove('pupy')
all_dependencies.remove('additional_imports')

ignore = {
    '_cffi_backend.so', '_cffi_backend.pyd',
    'network/lib/picocmd/server.py',
    'network/lib/transports/cryptoutils/pyaes/__init__.py',
    'network/lib/transports/cryptoutils/pyaes/aes.py',
    'network/lib/transports/cryptoutils/pyaes/blockfeeder.py',
    'network/lib/transports/cryptoutils/pyaes/util.py',
    'rpyc/utils/teleportation.py',
    'rpyc/utils/zerodeploy.py',
    'rpyc/experemental/__init__.py',
    'rpyc/experemental/retunnel.py',
    'rpyc/experemental/splitbrain.py',
    'json/tool.py',
    'rsa/cli.py',
}

if sys.platform.startswith('linux'):
    ignore.update({
        'psutil/_pswindows.py'
    })
elif sys.platform.startswith('win'):
    ignore.update({
        '_psaix.py',
        '_psbsd.py',
        '_pslinux.py',
        '_psosx.py',
        '_pssunos.py'
    })

for dep in ('cffi', 'pycparser', 'pyaes'):
    if dep in all_dependencies:
        all_dependencies.remove(dep)

print("ALLDEPS: ", all_dependencies)

from distutils.core import setup
from glob import glob
import zipfile
import shutil

zf = zipfile.ZipFile(sys.argv[1], mode='w', compression=zipfile.ZIP_DEFLATED)

if 'win' in sys.platform:
    for root, _, files in os.walk(r'C:\Python27\Lib\site-packages'):
        for file in files:
            if file.lower() == 'pywintypes27.dll':
                zf.write(os.path.join(root, file), 'pywintypes27.dll')

try:
    content = set(ignore)
    for dep in all_dependencies:
        _, mpath, info = imp.find_module(dep)

        print("DEPENDENCY: ", dep, mpath)
        if info[2] == imp.PKG_DIRECTORY:
            print('adding package %s / %s'%(dep, mpath))
            path, root = os.path.split(mpath)
            for root, dirs, files in os.walk(mpath):
                for f in list(set([x.rsplit('.',1)[0] for x in files])):
                    found=False
                    need_compile=True
                    for ext in ('.dll', '.so', '.pyd', '.py', '.pyc', '.pyo'):
                        if ( ext == '.pyc' or ext == '.pyo' ) and found:
                            continue

                        pypath = os.path.join(root,f+ext)
                        if os.path.exists(pypath):
                            ziproot = root[len(path)+1:].replace('\\', '/')
                            zipname = '/'.join([ziproot, f.split('.', 1)[0] + ext])
                            found = True

                            if ziproot.startswith('site-packages'):
                                ziproot = ziproot[14:]

                            if zipname.startswith('network/transports/') and \
                              not zipname.startswith('network/transports/__init__.py'):
                                continue

                            # Remove various testcases if any
                            if any([ '/'+x+'/' in zipname for x in [
                                'tests', 'test', 'SelfTest', 'SelfTests', 'examples',
                                'experimental'
                                ]
                            ]):
                                continue

                            if zipname in content:
                                continue

                            file_root = root

                            if os.path.exists(os.path.join(PATCHES, f+'.py')):
                                print('found [PATCH] for {}'.format(f))
                                file_root = PATCHES
                                ext = '.py'
                            elif os.path.exists(os.path.sep.join([PATCHES] + zipname.split('/'))):
                                print('found [PATCH ZROOT] for {}'.format(f))
                                file_root = os.path.sep.join([PATCHES] + ziproot.split('/'))
                                ext = '.py'

                            print('adding file : {}'.format(zipname))
                            content.add(zipname)

                            if ext == '.py' and need_compile:
                                zf.writestr(
                                    zipname+'o',
                                    compile_py(os.path.join(file_root,f+ext)))
                            else:
                                zf.write(os.path.join(file_root,f+ext), zipname)

                            break
        else:
            if '<memimport>' in mpath:
                continue

            found_patch = None
            for extp in ( '.py', '.pyc', '.pyo' ):
                if os.path.exists(os.path.join(PATCHES, dep+extp)):
                    found_patch = (os.path.join(PATCHES, dep+extp), extp)
                    break

            if found_patch:
                if dep+found_patch[1] in content:
                    continue

                print('adding [PATCH] %s -> %s'%(found_patch[0], dep+found_patch[1]))
                if found_patch[0].endswith('.py'):
                    zf.writestr(
                        dep+found_patch[1]+'o',
                        compile_py(found_patch[0]))
                else:
                    zf.write(found_patch[0], dep+found_patch[1])

            else:
                _, ext = os.path.splitext(mpath)
                if dep+ext in content:
                    continue

                print('adding %s -> %s'%(mpath, dep+ext))
                if mpath.endswith(('.pyc', '.pyo', '.py')):
                    srcfile = mpath
                    if srcfile.endswith(('.pyc', '.pyo')):
                        srcfile = srcfile[:-1]

                    zf.writestr(dep+'.pyo', compile_py(srcfile))
                else:
                    zf.write(mpath, dep+ext)

finally:
    zf.writestr('fid.toc', marshal.dumps(compile_map))
    zf.close()
