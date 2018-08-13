# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.utils.credentials import Credentials

__class_name__="Creds"

@config(category="creds")
class Creds(PupyModule):
    """ database containing all passwords found """
    need_at_least_one_client=False
    is_module=False

    @classmethod
    def init_argparse(cls):
        example = 'Examples:\n'
        example += '>> creds --search gmail\n'
        example += '>> creds --search plaintext\n'
        example += '>> creds --search hash\n'
        example += '>> creds --search <UID>\n'
        example += '>> creds --sort --search plaintext\n'

        cls.arg_parser = PupyArgumentParser(prog="Creds", description=cls.__doc__, epilog=example)
        cls.arg_parser.add_argument('-s', '--search', default="all", metavar='string', help='default: all (search in any possible field, plaintext or hash word can be specify)')
        cls.arg_parser.add_argument('--sort', action='store_true', default=False, help='sort by host')
        cls.arg_parser.add_argument('--flush', '-F', action='store_true', help='flush the entire database')

    def run(self, args):
        credentials = Credentials(config=self.config)
        if args.flush:
            warning = raw_input("[!] Are you sure to flush the database ? [y/N]")
            if warning == 'y':
                credentials.flush()
                self.success("Database removed")
            else:
                 self.warning("Nothing done")
        else:
            credentials.display(search=args.search, isSorted=args.sort)
