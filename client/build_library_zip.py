import sys
import os

PATCHES = os.path.join('..','library_patches')

sys.path.insert(0, PATCHES)
sys.path.insert(0, os.path.join('..','..','pupy'))

import additional_imports
import Crypto
import pp
import site

sys_modules = [
    (x,sys.modules[x]) for x in sys.modules.keys()
]

all_dependencies=set(
    [
        x.split('.')[0] for x,m in sys_modules \
            if not '(built-in)' in str(m) and x != '__main__'
    ] + [
        'Crypto', 'rpyc', 'pyasn1', 'rsa',
        'encodings.idna', 'stringprep',
    ]
)

all_dependencies.add('site')

all_dependencies = sorted(list(set(all_dependencies)))
all_dependencies.remove('pupy')
all_dependencies.remove('additional_imports')

print "ALLDEPS: ", all_dependencies

from distutils.core import setup
from glob import glob
import zipfile
import shutil
import compileall

compileall.compile_dir(PATCHES)

zf = zipfile.ZipFile(os.path.join('resources','library.zip'), mode='w', compression=zipfile.ZIP_DEFLATED)

if 'win' in sys.platform:
    for root, _, files in os.walk(r'C:\Python27\Lib\site-packages'):
        for file in files:
            if file.lower() == 'pywintypes27.dll':
                zf.write(os.path.join(root, file), 'pywintypes27.dll')

try:
    content = set()
    content.add('_cffi_backend.so')
    content.add('_cffi_backend.pyd')

    for dep in all_dependencies:
        mdep = __import__(dep)
        print "DEPENDENCY: ", dep, mdep
        if hasattr(mdep, '__path__') and getattr(mdep, '__path__'):
            print('adding package %s / %s'%(dep, mdep.__path__))
            path, root = os.path.split(mdep.__path__[0])
            for root, dirs, files in os.walk(mdep.__path__[0]):
                for f in list(set([x.rsplit('.',1)[0] for x in files])):
                    found=False
                    for ext in ('.dll', '.so', '.pyo', '.pyd', '.pyc', '.py'):
                        if ( ext == '.py' or ext == '.pyc' ) and found:
                            continue

                        pypath = os.path.join(root,f+ext)
                        if os.path.exists(pypath):
                            if ext == '.py':
                                try:
                                    compileall.compile_file(os.path.relpath(pypath))
                                except ValueError:
                                    compileall.compile_file(pypath)
                                for extc in ( '.pyc', '.pyo' ):
                                    if os.path.exists(os.path.join(root,f+extc)):
                                        ext = extc

                            zipname = '/'.join([root[len(path)+1:], f.split('.', 1)[0] + ext])
                            zipname = zipname.replace('\\', '/')
                            found=True

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
                            for extp in ( '.pyo', '.pyc', '.py' ):
                                if os.path.exists(os.path.join(PATCHES, f+extp)):
                                    print('found [PATCH] for {}'.format(f))
                                    root = PATCHES
                                    ext = extp
                                    break

                            print('adding file : {}'.format(zipname))
                            content.add(zipname)
                            zf.write(os.path.join(root,f+ext), zipname)
        else:
            if '<memimport>' in mdep.__file__:
                continue

            found_patch = None
            for extp in ( '.pyo', '.pyc', '.py' ):
                if os.path.exists(os.path.join(PATCHES, dep+extp)):
                    found_patch = (os.path.join(PATCHES, dep+extp), extp)
                    break

            if found_patch:
                if dep+found_patch[1] in content:
                    continue

                print('adding [PATCH] %s -> %s'%(found_patch[0], dep+found_patch[1]))
                zf.write(found_patch[0], dep+found_patch[1])
            else:
                _, ext = os.path.splitext(mdep.__file__)
                if dep+ext in content:
                    continue

                print('adding %s -> %s'%(mdep.__file__, dep+ext))
                zf.write(mdep.__file__, dep+ext)

finally:
    zf.close()
