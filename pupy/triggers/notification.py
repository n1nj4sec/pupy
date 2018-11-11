# -*- encoding: utf-8 -*-

IGNORED_EVENTS = (
    'start', 'exit', 'connect', 'disconnect', 'job completed'
)

import datetime

def execute(event_name, client, server, handler, config, **kwargs):
    if event_name in IGNORED_EVENTS:
        return

    client_id = ''
    if 'id' in kwargs:
        client_id = 'session={}'.format(kwargs['id'])
    elif 'node' in kwargs and kwargs['node']:
        if type(kwargs['node']) in (int, long):
            client_id = '{:012x}'.format(kwargs['node'])
        else:
            client_id = kwargs['node']

    if 'sid' in kwargs:
        if client_id:
            client_id += '/'

        if type(kwargs['sid']) in (int, long):
            client_id += 'sid:{:08x}'.format(kwargs['sid'])
        else:
            client_id += 'sid:'+kwargs['sid']

    if 'node' in kwargs:
        tags = str(config.tags(kwargs['node']))
        if tags:
            if client_id:
                client_id += '/'

            client_id += '{}'.format(tags)

    server.info('Event ({}): {} ({})'.format(
        datetime.datetime.now(), event_name, client_id))
