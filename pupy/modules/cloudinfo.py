# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.utils.term import colorize
from pupylib.utils.rpyc_utils import obtain

from pygments import highlight, lexers, formatters
import json
import os

__class_name__="CloudInfo"

@config(cat="gather")
class CloudInfo(PupyModule):
    """ Retrieve EC2/DigitalOcean metadata """

    dependencies = [ 'cloudinfo' ]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="cloudinfo", description=self.__doc__)
        self.arg_parser.add_argument(
            '-log',
            help='Save output to file. You can use vars: '
            '%%h - host, %%m - mac, %%p - platform, %%u - user, %%a - ip address',
        )

    def run(self, args):
        cloud, metadata = self.client.conn.modules.cloudinfo.metadata()
        if not cloud:
            self.error('Unknown cloud or non-cloud environment')
            return

        self.success('Cloud: {}'.format(cloud))

        metadata = obtain(metadata)
        formatted_json = json.dumps(metadata, indent=1, sort_keys=True)

        if args.log:
            log = args.log.replace(
                '%m', self.client.desc['macaddr']
            ).replace(
                '%p', self.client.desc['platform']
            ).replace(
                '%a', self.client.desc['address']
            ).replace(
                '%h', self.client.desc['hostname'].replace(
                    '..', '__'
                ).replace(
                    '/', '_'
                )
            ).replace(
                '%u', self.client.desc['user'].replace(
                    '..', '__'
                ).replace(
                    '/', '_'
                )
            )

            dirname = os.path.dirname(log)

            if not os.path.exists(dirname):
                os.makedirs(dirname)

            with open(log, 'w') as logfile:
                logfile.write(formatted_json)

        self.stdout.write(
            highlight(
                unicode(formatted_json, 'UTF-8'),
                lexers.JsonLexer(),
                formatters.TerminalFormatter()
            )
        )
