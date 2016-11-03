# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from netaddr import *
from pupylib.utils.term import colorize
import os

__class_name__="SMBSpider"

@config(cat="admin")
class SMBSpider(PupyModule):
    
    """ walk through a smb directory and recursively search a string into files """
    
    dependencies = [ 'impacket', 'calendar', 'ntpath', 'pupyutils.smbspider']

    daemon=True
    max_clients=1

    def init_argparse(self):
        
        example = 'Examples:\n'
        example += '>> run smbspider 192.168.0.1 --pattern password --content\n'
        example += '>> run smbspider 192.168.0.1 -u john -p password1 pwd= -d WORKGROUP --content -e txt,ini\n'
        example += '>> run smbspider 172.16.0.20/24 -u john --pattern password.* -H \'aad3b435b51404eeaad3b435b51404ee:da76f2c4c96028b7a6111aef4a50a94d\'\n'

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
        sgroup.add_argument("--pattern", nargs='+', help='Pattern(s) to search for in folders, filenames and file content')
        sgroup.add_argument('-e','--extensions',metavar='ext1,ext2,...', default='', help='Limit to some extensions')
        sgroup.add_argument("--depth", type=int, default=10, help='Spider recursion depth (default: 10)')
        sgroup.add_argument('-m','--max-size', type=int, default=7000000, help='max file size in byte (default 7 Mo)')

    def run(self, args):

        if "/" in args.target[0]:
            hosts = IPNetwork(args.target[0])
        else:
            hosts = [args.target[0]]
        
        if not args.pattern:
            self.error('Specify the pattern to look for')
            return

        if args.extensions:
            args.extensions = tuple(f.strip() for f in args.extensions.split(','))
        
        # if not extension is provided for find commad, try to extract it to gain time during the research
        elif not args.content:
            args.extensions = tuple(os.path.splitext(s)[1].strip() for s in args.pattern)    

        search_str = [s.lower() for s in args.pattern]

        self.info("Search started")
        smb = self.client.conn.modules["pupyutils.smbspider"].Spider(hosts, args.domain, args.port, args.user, args.passwd, args.hash, args.content, args.share, search_str, args.extensions, args.max_size, args.spider, args.depth)
        for files in smb.spider_all_hosts():
            # add color
            for s in search_str:
                if s in files:
                    files = files.replace(s, colorize(s,"green"))
            self.success("%s" % files)
        self.info("Search finished !")