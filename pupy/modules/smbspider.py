# -*- coding: UTF8 -*-
# Code modified from the awesome tool CrackMapExec: /cme/spider/smbspider.py
# Thank you to byt3bl33d3r for its work
from pupylib.PupyModule import *
#from netaddr import *
from netaddr import *
__class_name__="SMBSpider"

@config(cat="admin")
class SMBSpider(PupyModule):
    """ walk through a smb directory and recursively search a string into files """

    daemon=True

    def init_argparse(self):
        
        example = 'Examples:\n'
        example += '>> run smbspider --pattern password --content 192.168.0.1\n'
        example += '>> run smbspider -u john -p password1 -d TEST --regex password.* pwd.* --content -e txt,ini 192.168.0.1\n'
        example += '>> run smbspider -u john --regex password.* -H \'aad3b435b51404eeaad3b435b51404ee:da76f2c4c96028b7a6111aef4a50a94d\' 172.16.0.20\n'

        self.arg_parser = PupyArgumentParser(prog="smbspider", description=self.__doc__, epilog=example)
        self.arg_parser.add_argument("-u", metavar="USERNAME", dest='user', default='', help="Username, if omitted null session assumed")
        self.arg_parser.add_argument("-p", metavar="PASSWORD", dest='passwd', default='', help="Password")
        self.arg_parser.add_argument("-H", metavar="HASH", dest='hash', default='', help='NTLM hash')
        self.arg_parser.add_argument("-d", metavar="DOMAIN", dest='domain', default="WORKGROUP", help="Domain name (default WORKGROUP)")
        self.arg_parser.add_argument("-P", dest='port', type=int, choices={139, 445}, default=445, help="SMB port (default 445)")
        self.arg_parser.add_argument("target", nargs=1, type=str, help="Target range or IP address")

        sgroup = self.arg_parser.add_argument_group("Spidering shares", "Options for spidering shares")
        sgroup.add_argument("-s", metavar="SHARE", dest='share', default="all", help="Specify a share (default C$)")
        sgroup.add_argument("--spider", metavar='FOLDER', nargs='?', default='.', type=str, help='Folder to spider (default: root directory)')
        sgroup.add_argument("--content", action='store_true', help='Enable file content searching')
        sgroup.add_argument("--exclude-dirs", type=str, metavar='DIR_LIST', default='', help='Directories to exclude from spidering')
        sgroup.add_argument("--pattern", nargs='*', help='Pattern(s) to search for in folders, filenames and file content')
        sgroup.add_argument("--regex", nargs='*', help='Regex(s) to search for in folders, filenames and file content')
        sgroup.add_argument('-e','--extensions',metavar='ext1,ext2,...', help='limit to some extensions')
        sgroup.add_argument("--depth", type=int, default=10, help='Spider recursion depth (default: 10)')
        sgroup.add_argument('-m','--max-size', type=int, default=7000000, help='max file size in byte (default 7 Mo)')

    def run(self, args):
        exts=[]
        if args.extensions:
            exts=args.extensions.split(',')

        if "/" in args.target[0]:
            hosts = IPNetwork(args.target[0])
        else:
            hosts = list()
            hosts.append(args.target[0])

        self.info("Loading dependencies")
        self.client.load_package("impacket")
        self.client.load_package("pupyutils.smbspider")

        for host in hosts:
            self.info("Connecting to the remote host: %s:%s" % (host, str(args.port)))
            smbspider = self.client.conn.modules["pupyutils.smbspider"].SMBSpider(host, args.domain, args.port, args.user, args.passwd, args.hash, args.content, args.regex, args.share, args.exclude_dirs, exts, args.pattern, args.max_size)
            logged = smbspider.login()
            if not logged:
                self.error("Connection failed !")
                return
            
            # spider all shares
            if args.share == 'all':
                for share in smbspider.list_share():
                    # self.info("Spidering remote share smb://%s/%s" % (host, share))
                    smbspider.set_share(share)
                    for res in smbspider.spider(args.spider, int(args.depth)):
                        self.success("%s" % res)
            
            # spider only one share
            else:
                for res in smbspider.spider(args.spider, int(args.depth)):
                    self.success("%s" % res)
            
            self.info("search finished !")
            smbspider.logoff()

