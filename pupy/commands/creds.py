# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import (
    Color, Error, Success, Table,
    TruncateToTerm, NewLine, Line, MultiPart
)

from pupylib.utils.credentials import Credentials

usage = 'Credentials manager'
parser = PupyArgumentParser(prog='creds', description=usage)
parser.add_argument('-A', '--all', action='store_true', help='Search/Show info for all machines, not only active ones')
parser.add_argument('-k', '--key', help='Search in key in objects with key')
parser.add_argument('-s', '--sort', action='store_true', help='Search in key in objects with key')
parser.add_argument('--delete-db', action='store_true', help='Delete DB')
parser.add_argument('search', default='', nargs='?', help='Keyword to search')

def do(server, handler, config, modargs):
    try:
        credentials = Credentials(config=config)
    except Exception, e:
        handler.display(Error(e))
        return

    clients = server.get_clients_list()

    cids = None

    if modargs.delete_db:
        credentials.remove()
        handler.display(Success('DB deleted'))
        return

    if not modargs.all:
        cids = set([
            client.short_name() for client in clients
        ])
        cids.update([
            client.node() for client in clients
        ])

    categories = {}

    try:
        for item in credentials.display(search=modargs.search.decode('utf-8'), isSorted=modargs.sort):
            if item['category'] not in categories:
                categories[item['category']] = {
                    'credtype': item.get('credtype'),
                    'creds': []
                }

            category = categories[item['category']]
            category['creds'].append({
                k:v for k,v in item.iteritems() if k in ('cid', 'login', 'secret', 'resource')
            })

    except Exception, e:
        handler.display(Error(e))
        return

    if not categories:
        handler.display(Error('DB is empty'))
        return

    try:
        for category,info in categories.iteritems():
            if not info['creds']:
                continue

            credtype = info['credtype']

            columns = ['cid', 'login', 'secret', 'resource']
            caption = category

            if all(not x['resource'] for x in info['creds']):
                del columns[columns.index('resource')]

            cids = set(x['cid'] for x in info['creds'])
            if len(cids) == 1:
                del columns[columns.index('cid')]
                caption += ' (cid={})'.format(list(cids)[0])

            if credtype in ('plaintext', 'hash') or all(
                len(x['secret']) <= 64 for x in info['creds']):

                handler.display(TruncateToTerm(
                    Table(info['creds'], columns,
                          caption=Color(caption, 'yellow'))))
            else:
                caption = Line('{', Color(caption, 'yellow'), '}')
                handler.display(caption)
                parts = []
                for cred in info['creds']:
                    line = []
                    for column in columns:
                        if column == 'secret' or not cred[column]:
                            continue

                        line.append(Color(column+':', 'yellow'))
                        line.append(Color(cred[column], 'lightyellow'))

                    line.append(NewLine())
                    line.append(cred['secret'])
                    line.append(NewLine())
                    parts.append(Line(*line))

                handler.display(MultiPart(parts))

            handler.display(NewLine())
    except Exception, e:
        handler.display(Error(e))
        return
