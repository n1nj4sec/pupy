from pupylib.PupyModule import *
from pupylib.utils.credentials import Credentials
import os

__class_name__="Creds"
ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))

@config(category="creds")
class Creds(PupyModule):
    """ database containing all passwords found """
    
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="Creds", description=self.__doc__)
        self.arg_parser.add_argument('--show','-S',  action='store_true', help='print all passwords on the database')
        self.arg_parser.add_argument('--flush', '-F', action='store_true', help='flush the entire database')
    
    def run(self, args):
        if args.flush:
            warning = raw_input("[!] Are you sure to flush the database ? [y/N]")
            if warning == 'y':
                Credentials().flush()
                self.success("Database removed")
            else:
                 self.warning("Nothing done")
        elif args.show:
            Credentials().show()

        
