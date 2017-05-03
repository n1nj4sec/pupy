# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdio
from pupylib.PupyConfig import PupyConfig
import datetime
import json

__class_name__="Beroot"

@config(cat="admin", compat=["windows"])
class Beroot(PupyModule):
    """ Windows Privilege escalation """

    dependencies = {
        'windows': [
            'pyexpat', 'xml', '_elementtree', 'xml.etree', 'impacket', 'impacket.examples', 'beroot', 'beRoot'
        ]
    }

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="beroot", description=self.__doc__)
        self.arg_parser.add_argument("-l", "--list", action="store_true", default=False, help="list all softwares installed (not run by default)")
        self.arg_parser.add_argument("-w", "--write", action="store_true", default=False, help="write output")
        self.arg_parser.add_argument("-c", "--cmd", action="store", default="whoami", help="cmd to execute for the webclient check (default: whoami)")

    def run(self, args):
        filepath = None
        if args.write:
            config = self.client.pupsrv.config or PupyConfig()
            folder = config.get_folder('beroot', {'%c': self.client.short_name()})
            filepath = os.path.join(folder, str(datetime.datetime.now()).replace(" ","_").replace(":","-")+"-beroot.txt")

        with redirected_stdio(self):
            for r in self.client.conn.modules["beRoot"].run(args.cmd, args.list, args.write):
                self.print_output(output=r, write=args.write, file=filepath)

        if args.write:
            self.success(filepath)

    def print_output(self, output, write=False, file=None):
        toPrint = True
        if 'NotPrint' in output:
            toPrint = False

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

        if toPrint:
            print st
        
        if write:
            f = open(file, 'a')
            f.write(st)
            f.close()
