import sys
from distutils.core import setup
import py2exe
import os
from glob import glob
import zipfile
import shutil

"""
This setup is not meant to build pupy stubs, but only to generate an adequate library.zip to embed in the real exe/dll stub
please don't use this if you don't want to recompile from sources

NOTE: I had to manually change pyreadline/console/console.py to console2.py and edit __init__.py to change the import because I had a conflict 

"""
if not (len(sys.argv)==3 and sys.argv[1]=="genzip"):
	exit("This setup is not meant to build pupy stubs, but only to generate an adequate library.zip to embed in the real exe/dll stub\nplease don't use this if you don't want to recompile from sources")
if sys.argv[2] == 'x86':
	outname = 'x86'
	platform = 'x86'
elif sys.argv[2] == 'x64':
	outname = 'x64'
	platform = 'amd64'
else:
	exit('unsupported platform')
sys.argv=[sys.argv[0],"py2exe"]


# put necessary library patches/includes/whatever in this directory
sys.path.insert(0, "sources/resources/library_patches")


setup(
	data_files = [(".", glob(r'.\RESOURCES_x86\msvcr90.dll'))],
	console=['reverse_ssl.py'],
	#windows=['reverse_ssl.py'],
	#zipfile=None,
	options={ "py2exe" : {
				"packages":['additional_imports'],
				"compressed" : True,
				"bundle_files" : 3, #3 = don't bundle (default) 2 = bundle everything but the Python interpreter 1 = bundle everything
				"excludes": ["Tkinter"]
				}
		}
)

excluded_files = [
	'crypt32.dll',
	'library.zip',
	'mswsock.dll',
	'python27.dll',
]
def zwalk(path, zf):
	for root, dirs, files in os.walk(path):
		for file in files:
			if file.lower() in excluded_files:
				pass
			else:
				zf.write(os.path.join(root, file))

			
with zipfile.ZipFile('sources/resources/library%s.zip' % outname, 'w', zipfile.ZIP_DEFLATED) as zf:
	root = os.getcwd()
	os.chdir('build/bdist.win-%s/winexe/collect-2.7' % platform)
	zwalk('.', zf)
	os.chdir('%s/dist' % root)
	zwalk('.', zf)
	
print 'cleaning up'
os.chdir(root)
shutil.rmtree('build')
shutil.rmtree('dist')	

