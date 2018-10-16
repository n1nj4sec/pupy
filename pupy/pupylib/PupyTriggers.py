# -*- coding: utf-8 -*-

__all__ = (
    'UnregisteredEventId',
    'SERVER', 'DNSCNC', 'CLIENT',
    'ON_CONNECT', 'ON_DISCONNECT',
    'ON_DNSCNC_SESSION', 'ON_DNSCNC_SESSION_LOST',
    'ON_START', 'ON_EXIT',
    'register_event_id',
    'unregister_event_id',
    'event'
)

import string

from .PupyConfig import Error, NoSectionError

from . import getLogger
logger = getLogger('triggers')

ALLOWED_CHARS = string.ascii_letters + string.digits + '_ '

SERVER = 0x80
DNSCNC = 0x40
CLIENT = 0x20

ON_CONNECT = CLIENT | 0
ON_DISCONNECT = CLIENT | 1
ON_DNSCNC_SESSION = DNSCNC | 0
ON_DNSCNC_SESSION_LOST = DNSCNC | 1
ON_START = SERVER | 0
ON_EXIT = SERVER | 1

EVENTS_ID_REGISTRY = {
    ON_START: 'start',
    ON_EXIT: 'exit',
    ON_CONNECT: 'connect',
    ON_DISCONNECT: 'disconnect',
    ON_DNSCNC_SESSION: 'dnscnc session',
    ON_DNSCNC_SESSION_LOST: 'dnscnc session lost'
}

class UnregisteredEventId(Exception):
    def __init__(self, eventid):
        super(UnregisteredEventId, self).__init__(self, eventid)
        self.eventid = eventid

    def __str__(self):
        return 'Unregistered Event ID %{:02x}'.format(self.eventid)

def register_event_id(eventid, name, scope=CLIENT):
    global EVENTS_ID_REGISTRY

    if eventid > 0x1F:
        raise ValueError('Invalid Event ID: should be less then 0x1F')
    elif scope not in (SERVER, CLIENT, DNSCNC):
        raise ValueError('Invalid scope, should be one of SERVER, CLIENT, DNSCNC')
    elif not all(x in ALLOWED_CHARS for x in name):
        raise ValueError('Only digits, letters, space and underscore allowed for event names')
    elif scope | eventid in EVENTS_ID_REGISTRY:
        raise ValueError('Event Id {:02x} already registered to {}'.format(
            scope | eventid, event_to_string(scope | eventid)))

    EVENTS_ID_REGISTRY[scope | eventid] = name

def unregister_event_id(eventid, scope=CLIENT):
    global EVENTS_ID_REGISTRY

    if scope | eventid not in EVENTS_ID_REGISTRY:
        raise UnregisteredEventId(scope | eventid)

    del EVENTS_ID_REGISTRY[scope | eventid]

def event_to_string(eventid):
    event_name = EVENTS_ID_REGISTRY.get(eventid, None)
    if event_name is None:
        raise UnregisteredEventId(eventid)

    return event_name

def event_to_config_section(eventid):
    event_name = event_to_string(eventid)
    return 'on_' + event_name.lower().replace(' ', '_')

def _event(eventid, client, server, handler, config, **kwargs):
    section = event_to_config_section(eventid)
    actions = config.items(section)
    event = event_to_string(eventid)

    for client_filter, action in actions:
        if client_filter.lower() in ('this', 'self', 'current', '@'):
            if eventid & CLIENT:
                client_filter = client.desc['id']
            elif eventid & DNSCNC:
                client_filter = '{:08x}'.format(client.spi)

        if action.startswith('include:'):
            _, included_section = action.split(':', 1)
            try:
                for nested in config.items(included_section):
                    actions.append(nested)
            except NoSectionError:
                pass

            continue

        elif action.startswith('python:'):
            _, trigger_name = action.split(':', 1)
            server.triggers.execute(
                trigger_name, event, client,
                server, handler, config, **kwargs)

            continue

        if kwargs:
            action = action.format(**kwargs)

        if eventid & DNSCNC:
            action = action.replace('%c', '{:08x}'.format(client.spi))

        elif eventid & CLIENT:
            action = action.replace('%c', '{:08x}'.format(client.desc['id']))

            node = client.desc['node']

            criterias = ['*', 'any']

            criterias.append(node)
            criterias.extend(list(config.tags(node)))

        if client_filter not in criterias and not client_filter.startswith(('*', 'any')) and \
          (not hasattr(server, 'get_clients') or client_filter not in server.get_clients(client_filter)):

            logger.info(
                'Incompatible event: eventid=%s criterias=%s client_filter=%s action=%s',
                event, criterias, client_filter, action)

            continue

        logger.info('Compatible event: eventid=%s criterias=%s client_filter=%s action=%s',
            event, criterias, client_filter, action)

        handler.inject(
            action, client_filter,
            'Action for event "{}" apply to <{}>: {}'.format(
                event, client_filter, action))


def event(eventid, client, server, handler, config, **kwargs):
    try:
        _event(eventid, client, server, handler, config)

    except NoSectionError:
        pass

    except Error, e:
        logger.error(e)

    except Exception, e:
        logger.exception(e)
