import sys
from distutils.core import setup
import os
from glob import glob
import zipfile
import shutil

sys.path.insert(0, os.path.join('resources','library_patches'))
sys.path.insert(0, os.path.join('..','..','pupy'))

import pp
import additional_imports
import Crypto

all_dependencies=set(
    [
        x.split('.')[0] for x,m in sys.modules.iteritems() if not '(built-in)' in str(m) and x != '__main__'
    ] + [
        'Crypto', 'yaml', 'rpyc', 'pyasn1', 'rsa'
    ]
)

all_dependencies = list(set(all_dependencies))
all_dependencies.remove('pupy')
all_dependencies.remove('additional_imports')

print "ALLDEPS: ", all_dependencies

zf = zipfile.ZipFile(os.path.join('resources','library.zip'), mode='w', compression=zipfile.ZIP_DEFLATED)
zf.write('C:\\Python27\\Lib\\site-packages\\pywin32_system32\\pywintypes27.dll', 'pywintypes27.dll')
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
                    for ext in ('.pyc', '.pyd', '.pyo', '.py', '.dll', '.so'):
                        if ext == '.py' and found:
                            continue
                        if os.path.exists(os.path.join(root,f+ext)):
                            zipname = os.path.join(root[len(path)+1:], f.split('.', 1)[0] + ext)
                            print('adding file : {}'.format(zipname))
                            zf.write(os.path.join(root, f+ext), zipname)
                            found=True
        else:
            if '<memimport>' in mdep.__file__:
                continue

            _, ext = os.path.splitext(mdep.__file__)
            print('adding %s -> %s'%(mdep.__file__, dep+ext))
            zf.write(mdep.__file__, dep+ext)

finally:
    zf.close()
