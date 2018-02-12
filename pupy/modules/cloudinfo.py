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

    def run(self, args):
        cloudinfo = self.client.remote('cloudinfo', 'metadata')

        cloud, metadata = cloudinfo()

        if not cloud:
            self.error('Unknown cloud or non-cloud environment')
            return

        self.success('Cloud: {}'.format(cloud))

        formatted_json = json.dumps(metadata, indent=1, sort_keys=True)

        self.stdout.write(
            highlight(
                unicode(formatted_json, 'UTF-8'),
                lexers.JsonLexer(),
                formatters.TerminalFormatter()
            )
        )
