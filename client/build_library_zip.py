import sys
from distutils.core import setup
import os
from glob import glob
import zipfile
import shutil

# put necessary library patches/includes/whatever in this directory
sys.path.insert(0, os.path.join("sources","resources","library_patches"))
sys.path.insert(0, os.path.join("..","pupy"))
import pp
import additional_imports
import Crypto
if len(sys.argv)!=2:
	exit("usage: python %s (x86|x64)"%sys.argv[0])
if sys.argv[1]=="x86":
	arch="x86"
	print "copying installed python version to sources\\resources\\python27_x86.dll"
	shutil.copy("C:\\Windows\SysWOW64\python27.dll", "sources\\resources\\python27_x86.dll")
	print "copying x86 msvcr90.dll to sources"
	shutil.copy("C:\\Windows\\winsxs\\x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.21022.8_none_bcb86ed6ac711f91\\msvcr90.dll", "sources\\resources\\msvcr90_x86.dll")
elif sys.argv[1]=="x64":
	arch="x64"
	print "copying installed python version to sources\\resources\\python27_x64.dll"
	shutil.copy("C:\\Windows\system32\python27.dll", "sources\\resources\\python27_x64.dll")
	print "copying x64 msvcr90.dll to sources"
	shutil.copy("C:\\Windows\\winsxs\\amd64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.21022.8_none_bcb86ed6ac711f91\\msvcr90.dll", "sources\\resources\\msvcr90_x64.dll")
else:
	exit("usage: python %s (x86|x64)"%sys.argv[0])
	

all_dependencies=list(set([x.split(".")[0] for x in sys.modules.iterkeys()]))
all_dependencies.extend(["win32file", "win32pipe", "Crypto", "yaml", "_yaml", "rpyc", "network", "pyasn1", "rsa"])
all_dependencies=list(set(all_dependencies))

zf = zipfile.ZipFile(os.path.join("sources","resources","library%s.zip"%arch), mode='w', compression=zipfile.ZIP_DEFLATED)
try:
	if arch=="x86":
		print("adding pywintypes.dll")
		zf.write("C:\\Windows\\SysWOW64\\pywintypes27.dll", "pywintypes27.dll")
	else:
		print("adding pywintypes.dll")
		zf.write("C:\\Windows\\system32\\pywintypes27.dll", "pywintypes27.dll")
	for dep in all_dependencies:
		found=False
		for path in sys.path:
			if os.path.isdir(os.path.join(path, dep)):
				print("adding package %s"%dep)
				for root, dirs, files in os.walk(os.path.join(path, dep)):
					for f in list(set([x.rsplit(".",1)[0] for x in files])):
						for ext in (".pyc", ".py", ".pyd", ".pyo"):
							if os.path.exists(os.path.join(root,f+ext)):
								print("adding file : %s"%os.path.join(root[len(path)+1:], f+ext))
								zf.write(os.path.join(path, root, f+ext), os.path.join(root[len(path)+1:], f+ext))
								break
						if f.endswith(".dll"):
							print("adding file : %s"%os.path.join(root[len(path)+1:], f))
							zf.write(os.path.join(path, root, f), os.path.join(root[len(path)+1:], f))
				found=True
			else:
				if os.path.exists(os.path.join(path, dep+".pyc")):
					print("adding %s.pyc"%(dep))
					zf.write(os.path.join(path, dep+".pyc"), dep+".pyc")
					found=True
					break
				elif os.path.exists(os.path.join(path, dep+".py")):
					print("compiling/adding %s.py"%(dep))
					zf.write(os.path.join(path, dep+".py"), dep+".py")
					found=True
					break
				elif os.path.exists(os.path.join(path, dep+".pyd")):
					print("adding %s.pyd"%(dep))
					zf.write(os.path.join(path, dep+".pyd"), dep+".pyd")
					found=True
					break
				elif os.path.exists(os.path.join(path, dep+".pyo")):
					print("adding %s.pyo"%(dep))
					zf.write(os.path.join(path, dep+".pyo"), dep+".pyo")
					found=True
					break
			if found:
				continue
finally:
	zf.close()
exit()
def zwalk(path, zf):
	for root, dirs, files in os.walk(path):
		for file in files:
			if file.lower() in excluded_files:
				pass
			elif file.endswith('.pyd') and "." in file.rsplit(".",1)[0]:
				arch_path="/".join(file.rsplit(".",1)[0].split('.'))
				zf.write(os.path.join(root,file),arcname=arch_path+".pyd")
			else:
				zf.write(os.path.join(root, file))

			
with zipfile.ZipFile('sources/resources/library%s.zip' % outname, 'w', zipfile.ZIP_DEFLATED) as zf:
	root = os.getcwd()
	os.chdir('build/bdist.win%s/winexe/collect-2.7' % platform)
	zwalk('.', zf)
	os.chdir('%s/dist' % root)
	zwalk('.', zf)
	
print 'cleaning up'
os.chdir(root)
shutil.rmtree('build')
shutil.rmtree('dist')	

