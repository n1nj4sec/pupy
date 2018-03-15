# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser

usage = 'Connect to the bind payload'
parser = PupyArgumentParser(prog='connect', description=usage)
parser.add_argument('args', help='Arguments to connect')

def do(server, handler, config, args):
    server.connect_on_client(args.args)
