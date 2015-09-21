import sys
from distutils.core import setup
import py2exe
import os
from glob import glob

"""
This setup is not meant to build pupy stubs, but only to generate an adequate library.zip to embed in the real exe/dll stub
please don't use this if you don't want to recompile from sources

NOTE: I had to manually change pyreadline/console/console.py to console2.py and edit __init__.py to change the import because I had a conflict 

"""
if not (len(sys.argv)==2 and sys.argv[1]=="genzip"):
	exit("This setup is not meant to build pupy stubs, but only to generate an adequate library.zip to embed in the real exe/dll stub\nplease don't use this if you don't want to recompile from sources")
sys.argv=[sys.argv[0],"py2exe"]


setup(
	data_files = [(".", glob(r'.\RESOURCES_x86\msvcr90.dll'))],
	console=['reverse_ssl.py'],
	#windows=['reverse_ssl.py'],
	#zipfile=None,
	options={ "py2exe" : {
				"packages":['additional_imports'],
				"compressed" : True,
				"bundle_files" : 2, #3 = don't bundle (default) 2 = bundle everything but the Python interpreter 1 = bundle everything
				}
		}
)

