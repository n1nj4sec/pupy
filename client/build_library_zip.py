# -*- coding: utf-8 -*-

from __future__ import print_function

import site
import sys
import sysconfig
import os
import imp
import importlib
import marshal

import shutil
import zipfile

from glob import glob
from distutils.core import setup


THIS = os.path.abspath(__file__)
ROOT = os.path.dirname(os.path.dirname(THIS))

print("THIS:", THIS)
print("ROOT: ", ROOT)

PATCHES=None
if sys.version_info[0]==2 :
    PATCHES = os.path.join(ROOT, 'pupy', 'library_patches_py2')
else:
    PATCHES = os.path.join(ROOT, 'pupy', 'library_patches_py3')
sys.path.insert(0, PATCHES)

sys.path.append(os.path.join(ROOT))
#sys.path.append(os.path.join(ROOT, 'pupy', 'pupylib'))


setattr(sys, "__from_build_library_zip_compiler__", True)
from pupy.pupylib.PupyCompile import pupycompile

sys.path.append(os.path.join(ROOT, 'pupy', 'packages', 'all'))

if sys.platform == 'win32':
    sys.path.append(os.path.join(ROOT, 'pupy', 'packages', 'windows', 'all'))
elif sys.platform.startswith('linux'):
    sys.path.append(os.path.join(ROOT, 'pupy', 'packages', 'linux', 'all'))
    sys.path.append(os.path.join(ROOT, 'pupy', 'packages', 'posix', 'all'))
else:
    sys.path.append(os.path.join(ROOT, 'pupy', 'packages', 'posix', 'all'))

import additional_imports

print("Load pupy")

try:
    import pupy.agent
    print("Module loaded")
    pupy.agent.prepare(debug=True)
    print("Prepare called")
except Exception as e:
    print("Load pupy.. FAILED: {}".format(e))
    raise

print("Load pupy.. OK")


sys_modules = [
    (x, sys.modules[x]) for x in sys.modules.keys()
]

compile_map = []


def compile_py(path):
    global compile_map
    global fileid

    fileid = len(compile_map)
    compile_map.append(path)

    data = None

    try:
        data = pupycompile(path, 'f:{:x}'.format(fileid), path=True)
        print("[C] {} -> f:{:x}".format(path, fileid))
    except ValueError:
        print("[C] {} -> failed".format(path))

    return data


all_dependencies = set(
    [
        x.split('.')[0] for x, m in sys_modules
        if '(built-in)' not in str(m) and x != '__main__'
    ] + [
        'Crypto', 'pyasn1', 'rsa', 'stringprep'
    ]
)

all_dependencies.add('site')
all_dependencies.add('sysconfig')
all_dependencies.add('re')

exceptions = (
    'pupy', 'pupy.agent', 'pupy.network', 'pupyimporter', 'additional_imports', 'pupy_hooks', 'pupy_modules',
    'network', 'pupyimporter', 'additional_imports'
)

all_dependencies = sorted(list(set(all_dependencies)))
for dep in list(all_dependencies):
    for excluded in exceptions:
        if dep == excluded or dep.startswith(excluded + '.'):
            try:
                all_dependencies.remove(dep)
            except Exception as e:
                print("could not remove dependency {}: {}".format(dep, e))


ignore = {
    '_cffi_backend.so', '_cffi_backend.pyd',

    # We don't use this anyway
    'Crypto/PublicKey/ElGamal.py',
    'Crypto/PublicKey/RSA.py',
    'Crypto/PublicKey/_openssh.py',
    'Crypto/PublicKey/_ec_ws.so',
    'Crypto/PublicKey/_ec_ws.pyd',
    'Crypto/PublicKey/ECC.py',
    'Crypto/PublicKey/__init__.py',
    'Crypto/PublicKey/DSA.py',

    # If it's known that GSSAPI is used and required during bootstrap,
    # it's worth to comment this line (adds 1MB)
    'kerberos.so',

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

for dep in ('cffi', 'pycparser', 'pyaes', 'distutils'):
    if dep in all_dependencies:
        all_dependencies.remove(dep)

print("ALLDEPS: ", all_dependencies)


zf = zipfile.ZipFile(sys.argv[1], mode='w', compression=zipfile.ZIP_DEFLATED)

zf.writestr(
    'bundlevars.pyo',
    pupycompile(
        'bundlevars={}'.format(repr({
            k: v for k, v in sysconfig.get_config_vars().items()
            if k not in (
                'BINDIR', 'BINLIBDEST', 'CONFINCLUDEDIR', 'CONFINCLUDEPY',
                'COREPYTHONPATH', 'COVERAGE_INFO', 'COVERAGE_REPORT',
                'DESTDIRS', 'DESTLIB', 'DESTSHARED', 'INCLDIRSTOMAKE',
                'INCLUDEDIR', 'INCLUDEPY', 'INSTALL', 'INSTALL_DATA',
                'INSTALL_PROGRAM', 'INSTALL_SCRIPT', 'INSTALL_SHARED',
                'LIBDEST', 'LIBDIR', 'LIBFFI_INCLUDEDIR', 'LIBOBJDIR',
                'LIBP', 'LIBPC', 'LIBPL', 'LIBSUBDIRS', 'MACHDEPPATH',
                'MACHDESTLIB', 'MAKESETUP', 'MANDIR', 'MKDIR_P', 'PLATMACDIRS',
                'PLATMACPATH', 'PYTHONPATH', 'RUNSHARED', 'SCRIPTDIR',
                'SRC_GDB_HOOKS', 'TESTPROG', 'TESTPYTHON', 'abs_builddir',
                'abs_srcdir', 'base', 'datarootdir', 'exec_prefix', 'platbase',
                'prefix', 'projectbase', 'userbase'
            )
        })),
        '<vars>', path=False
    )
)

#TODO: update if needed
if 'win' in sys.platform:
    for root, _, files in os.walk('C:\\Python27\\Lib\\site-packages'):
        for file in files:
            if file.lower().endswith((".dll",".pyd")):
                print("interesting file :", file)
            if file.lower() in ('pywintypes27.dll', '_win32sysloader.pyd'):
                zf.write(os.path.join(root, file), file)

try:
    content = set(ignore)
    for dep in all_dependencies:
        #spec=importlib.util.find_spec(dep)
        #print(spec)
        #print(dir(spec))
        print(dep)
        if dep.startswith("_cython_") or dep in ["cython_runtime", "pywin32_system32"]:
            continue
        _, mpath, info = imp.find_module(dep)
        #print("mpath", mpath, "info", info)
        if mpath == None:
            continue
        print("DEPENDENCY: ", dep, mpath)
        if info[2] == imp.PKG_DIRECTORY:
            print('adding package %s / %s' % (dep, mpath))
            path, root = os.path.split(mpath)
            for root, dirs, files in os.walk(mpath):
                for f in list(set([x.rsplit('.', 1)[0] for x in files])):
                    found = False
                    need_compile = True
                    for ext in ('.dll', '.so', '.pyd', '.py', '.pyc', '.pyo'):
                        if (ext == '.pyc' or ext == '.pyo') and found:
                            continue

                        pypath = os.path.join(root, f+ext)
                        if os.path.exists(pypath):
                            ziproot = root[len(path)+1:].replace('\\', '/')
                            zipname = '/'.join([ziproot,
                                                f.split('.', 1)[0] + ext])
                            found = True

                            if ziproot.startswith('site-packages'):
                                ziproot = ziproot[14:]

                            if zipname.startswith('network/transports/') and \
                                    not zipname.startswith('network/transports/__init__.py'):
                                continue

                            # Remove various testcases if any
                            if any(['/'+x+'/' in zipname for x in [
                                'tests', 'test', 'SelfTest', 'SelfTests', 'examples',
                                'experimental', '__pycache__'
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
                                file_root = os.path.sep.join(
                                    [PATCHES] + ziproot.split('/'))
                                ext = '.py'

                            if ext == '.py' and need_compile:
                                bytecode = compile_py(os.path.join(file_root, f+ext))
                                if not bytecode:
                                    continue

                                zf.writestr(zipname+'o', bytecode)
                            else:
                                zf.write(os.path.join(
                                    file_root, f+ext), zipname)

                            print('adding file : {}'.format(zipname))
                            content.add(zipname)

                            break
        else:
            if '<memimport>' in mpath:
                continue

            found_patch = None
            for extp in ('.py', '.pyc', '.pyo'):
                if os.path.exists(os.path.join(PATCHES, dep+extp)):
                    found_patch = (os.path.join(PATCHES, dep+extp), extp)
                    break

            if found_patch:
                if dep+found_patch[1] in content:
                    continue

                print('adding [PATCH] %s -> %s' %
                      (found_patch[0], dep+found_patch[1]))
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

                print('adding %s -> %s' % (mpath, dep+ext))
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
