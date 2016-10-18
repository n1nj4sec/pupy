from pupylib.PupyModule import *
from pupylib.utils.credentials import Credentials
import os

__class_name__="Creds"
ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))

@config(category="creds")
class Creds(PupyModule):
    """ database containing all passwords found """
    need_at_least_one_client=False
    is_module=False
    
    def init_argparse(self):
    	example = 'Examples:\n'
        example += '>> creds --search gmail\n'
        example += '>> creds --search plaintext\n'
        example += '>> creds --search hash\n'
        example += '>> creds --search <UID>\n'
        example += '>> creds --sort --search plaintext\n'

        self.arg_parser = PupyArgumentParser(prog="Creds", description=self.__doc__, epilog=example)
        self.arg_parser.add_argument('-s', '--search', default="all", metavar='string', help='default: all (search in any possible field, plaintext or hash word can be specify)')
        self.arg_parser.add_argument('--sort', action='store_true', default=False, help='sort by host')
        self.arg_parser.add_argument('--flush', '-F', action='store_true', help='flush the entire database')
    
    def run(self, args):
        if args.flush:
            warning = raw_input("[!] Are you sure to flush the database ? [y/N]")
            if warning == 'y':
                Credentials().flush()
                self.success("Database removed")
            else:
                 self.warning("Nothing done")
        else:
            Credentials().display(search=args.search, isSorted=args.sort)
        
        
