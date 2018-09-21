# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__="Beroot"


@config(cat="admin", compat=["linux", "windows"])
class Beroot(PupyModule):
    """Check for privilege escalation path"""

    dependencies = {
        'linux': [
            'beroot'
        ],
        'windows': [
            'pyexpat', 'xml', '_elementtree', 'xml.etree', 'impacket', 'impacket.examples', 'beroot'
        ]
    }

    @classmethod
    def init_argparse(cls):
        """
        Check the project on github: https://github.com/AlessandroZ/BeRoot
        """
        header = '|====================================================================|\n'
        header += '|                                                                    |\n'
        header += '|                        The BeRoot Project                          |\n'
        header += '|                                                                    |\n'
        header += '|                          ! BANG BANG !                             |\n'
        header += '|                                                                    |\n'
        header += '|====================================================================|\n\n'

        cls.arg_parser = PupyArgumentParser(prog="beroot", description=header + cls.__doc__)
        cls.arg_parser.add_argument("-c", "--cmd", action="store", default="whoami", help="Windows only: cmd to execute for the webclient check (default: whoami)")

    def run(self, args):

        run_beroot = self.client.remote('beroot.run', 'run')
        if self.client.is_windows():
            results = run_beroot(args.cmd)
            for r in results:
                self.windows_output(r)
        else:
            results = run_beroot()
            for r in results:
                self.linux_output(level=r[0], msg=r[1])

    def windows_output(self, output):
        to_print = True
        if 'NotPrint' in output:
            to_print = False

        st = '\n-------------- %s --------------\n' % output['Category']
        if 'list' in str(type(output['All'])):
            for results in output['All']:
                st += '\n[!] %s\n' % results['Function'].capitalize()

                results = results['Results']

                # return only one result (True or False)
                if 'bool' in str(type(results)):
                    st += '%s\n' % str(results)

                elif 'dict' in str(type(results)):
                    for result in results:
                        if 'list' in str(type(results[result])):
                            st += '%s\n' % str(result)
                            for w in results[result]:
                                st += '\t- %s\n' % w
                        st += '\n'

                elif 'list' in str(type(results)):
                    for result in results:
                        if 'str' in str(type(result)):
                            st += '%s\n' % result
                        else:
                            for r in sorted(result, key=result.get, reverse=True):
                                if 'list' in str(type(result[r])):
                                    st += '%s:\n' % r
                                    for w in result[r]:
                                        st += '\t- %s\n' % w
                                else:
                                    st += '%s: %s\n' % (r, str(result[r]))
                            st += '\n'
        elif 'str' in str(type(output['All'])):
            st += output['All']

        if to_print:
            self.log(st)

    def linux_output(self, level='', msg=''):
        if level == 'ok':
            self.success(msg)
        elif level == 'error':
            self.error(msg)
        elif level == 'info':
            self.log('[!] {msg}'.format(msg=msg))
        elif level == 'debug':
            self.log('[?] {msg}'.format(msg=msg))
        else:
            self.log(msg)
