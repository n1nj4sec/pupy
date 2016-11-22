import sys
import os

sys.path.insert(0, os.path.join('resources','library_patches'))
sys.path.insert(0, os.path.join('..','..','pupy'))

import additional_imports
import Crypto
import pp
import unicodedata # this is a builtin on linux and .pyd on windows that needs to be embedded
all_dependencies=set(
    [
        x.split('.')[0] for x,m in sys.modules.iteritems() if not '(built-in)' in str(m) and x != '__main__'
    ] + [
        'Crypto', 'yaml', 'rpyc', 'pyasn1', 'rsa',
        'encodings.idna', 'stringprep',
    ]
)

all_dependencies = list(set(all_dependencies))
all_dependencies.remove('pupy')
all_dependencies.remove('additional_imports')

print "ALLDEPS: ", all_dependencies

from distutils.core import setup
from glob import glob
import zipfile
import shutil
import compileall

zf = zipfile.ZipFile(os.path.join('resources','library.zip'), mode='w', compression=zipfile.ZIP_DEFLATED)

if 'win' in sys.platform:
    zf.write(r'C:\Python27\Lib\site-packages\pywin32_system32\pywintypes27.dll', 'pywintypes27.dll')

try:
    for dep in all_dependencies:
        mdep = __import__(dep)
        print "DEPENDENCY: ", dep, mdep
        if hasattr(mdep, '__path__'):
            print('adding package %s'%dep)
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
                                compileall.compile_file(pypath)
                                for extc in ( '.pyc', '.pyo' ):
                                    if os.path.exists(os.path.join(root,f+extc)):
                                        ext = extc

                            zipname = '/'.join([root[len(path)+1:], f.split('.', 1)[0] + ext])
                            zipname = zipname.replace('\\', '/')
                            found=True

                            # Remove various testcases if any
                            if any([ '/'+x+'/' in zipname for x in [
                                'tests', 'test', 'SelfTest', 'examples'
                                ]
                            ]):
                                continue

                            print('adding file : {}'.format(zipname))
                            zf.write(os.path.join(root,f+ext), zipname)
        else:
            if '<memimport>' in mdep.__file__:
                continue

            _, ext = os.path.splitext(mdep.__file__)
            print('adding %s -> %s'%(mdep.__file__, dep+ext))
            zf.write(mdep.__file__, dep+ext)

finally:
    zf.close()
