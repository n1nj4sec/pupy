# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.PupyOutput import Pygment

from pygments import lexers
import json

__class_name__="CloudInfo"

@config(cat="gather")
class CloudInfo(PupyModule):
    """ Retrieve EC2/DigitalOcean metadata """

    dependencies = [ 'cloudinfo' ]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="cloudinfo", description=cls.__doc__)

    def run(self, args):
        cloudinfo = self.client.remote('cloudinfo', 'metadata')

        cloud, metadata = cloudinfo()

        if not cloud:
            self.error('Unknown cloud or non-cloud environment')
            return

        self.success('Cloud: {}'.format(cloud))

        formatted_json = json.dumps(metadata, indent=1, sort_keys=True)

        self.log(
            Pygment(lexers.JsonLexer(), unicode(formatted_json, 'UTF-8'))
        )
