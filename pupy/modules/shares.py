# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from netaddr import *

__class_name__="Shares"

@config(category="admin", compat=["windows", "linux"])
class Shares(PupyModule):
	""" List local and remote shared folder and permission """

	def init_argparse(self):
		example = 'Examples:\n'
		example += '>> run shares local\n'
		example += '>> run shares remote -u john -p password1 -d DOMAIN -t 192.168.0.1\n'
		example += '>> run shares remote -u john -H \'aad3b435b51404eeaad3b435b51404ee:da76f2c4c96028b7a6111aef4a50a94d\' -t 192.168.0.1\n'

		self.arg_parser = PupyArgumentParser(prog="shares", description=self.__doc__, epilog=example)
		subparsers = self.arg_parser.add_subparsers(title='Enumerate shared folders')

		local = subparsers.add_parser('local', help='Retrieve local shared folders')
		local.set_defaults(local="list_shared_folders")

		remote = subparsers.add_parser('remote', help='Retrieve remote shared folders and permission')
		remote.add_argument("-u", metavar="USERNAME", dest='user', default='', help="Username, if omitted null session assumed")
		remote.add_argument("-p", metavar="PASSWORD", dest='passwd', default='', help="Password")
		remote.add_argument("-H", metavar="HASH", dest='hash', default='', help='NTLM hash')
		remote.add_argument("-d", metavar="DOMAIN", dest='domain', default="WORKGROUP", help="Domain name (default WORKGROUP)")
		remote.add_argument("-P", dest='port', type=int, choices={139, 445}, default=445, help="SMB port (default 445)")
		remote.add_argument("-t", dest='target', type=str, help="The target range or CIDR identifier")


	def run(self, args):

		# Retrieve local shared folders
		try:
			if args.local:
				if self.client.is_windows():
					self.client.load_package("win32api")
					self.client.load_package("win32com")
					self.client.load_package("pythoncom")
					self.client.load_package("winerror")
					self.client.load_package("wmi")
					self.client.load_package("pupwinutils.drives")

					print self.client.conn.modules['pupwinutils.drives'].shared_folders()

				else:
					self.warning('this module works only for windows. Try using: run shares remote -t 127.0.0.1')
				return
		except:
			pass

		# Retrieve remote shared folders
		if not args.target:
			self.error("target (-t) parameter must be specify")
			return

		if "/" in args.target:
			hosts = IPNetwork(args.target)
		else:
			hosts = list()
			hosts.append(args.target)

		print hosts

		self.client.load_package("impacket")
		self.client.load_package("calendar")
		self.client.load_package("pupyutils.share_enum")
		for host in hosts:
			self.info("Connecting to the remote host: %s" % host)
			print self.client.conn.modules["pupyutils.share_enum"].connect(
				host, args.port, args.user, args.passwd, args.hash, args.domain
			)
