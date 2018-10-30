# -*- coding: utf-8 -*-

__all__ = (
    'UnregisteredEventId',
    'SERVER', 'DNSCNC', 'CLIENT',
    'ON_CONNECT', 'ON_DISCONNECT',
    'ON_DNSCNC_SESSION', 'ON_DNSCNC_SESSION_LOST',
    'ON_START', 'ON_EXIT',
    'ON_JOB_EXIT',
    'EventRegistrationException', 'UnregisteredEventId',
    'RegisteredEventId', 'RegistrationNotAllowed',
    'register_event_id',
    'unregister_event_id',
    'event',
    'SERVER', 'DNSCNC', 'CLIENT', 'CUSTOM'
)

import string

from .PupyConfig import Error, NoSectionError

from . import getLogger
logger = getLogger('triggers')

ALLOWED_CHARS = string.ascii_letters + string.digits + '_ '

SERVER = 0x80000000
DNSCNC = 0x40000000
CLIENT = 0x20000000
CUSTOM = 0x10000000

ON_CONNECT = CLIENT | 0
ON_DISCONNECT = CLIENT | 1
ON_JOB_EXIT = CLIENT | 2

ON_CLIENT_EXIT = CUSTOM | 0xFFFF
ON_CLIENT_CONNECTION_FAILED = CUSTOM | 0xFFFE

ON_DNSCNC_SESSION = DNSCNC | 0
ON_DNSCNC_SESSION_LOST = DNSCNC | 1
ON_DNSCNC_ONLINE_STATUS = DNSCNC | 2
ON_DNSCNC_EGRESS_PORTS = DNSCNC | 3
ON_DNSCNC_PSTORE = DNSCNC | 4
ON_DNSCNC_USER_ACTIVE = DNSCNC | 5
ON_DNSCNC_USER_INACTIVE = DNSCNC | 6
ON_DNSCNC_HIGH_RESOURCE_USAGE = DNSCNC | 7
ON_DNSCNC_USERS_INCREMENT = DNSCNC | 8
ON_DNSCNC_USERS_DECREMENT = DNSCNC | 9
ON_START = SERVER | 0
ON_EXIT = SERVER | 1


EVENTS_ID_REGISTRY = {
    ON_START: 'start',
    ON_EXIT: 'exit',
    ON_CONNECT: 'connect',
    ON_DISCONNECT: 'disconnect',
    ON_JOB_EXIT: 'job completed',
    ON_DNSCNC_SESSION: 'dnscnc session',
    ON_DNSCNC_SESSION_LOST: 'dnscnc session lost',
    ON_DNSCNC_ONLINE_STATUS: 'dnscnc online status',
    ON_DNSCNC_EGRESS_PORTS: 'dnscnc egress ports',
    ON_DNSCNC_PSTORE: 'dnscnc pstore',
    ON_DNSCNC_USER_ACTIVE: 'dnscnc user active',
    ON_DNSCNC_USER_INACTIVE: 'dnscnc user inactive',
    ON_DNSCNC_HIGH_RESOURCE_USAGE: 'dnscnc high resource usage',
    ON_DNSCNC_USERS_INCREMENT: 'dnscnc users increment',
    ON_DNSCNC_USERS_DECREMENT: 'dnscnc users decrement',

    ON_CLIENT_EXIT: 'client_exit',
    ON_CLIENT_CONNECTION_FAILED: 'dnscnc connection failed'
}

class EventRegistrationException(Exception):
    def __init__(self, eventid):
        super(EventRegistrationException, self).__init__(self, eventid)
        self.eventid = eventid

class UnregisteredEventId(EventRegistrationException):
    def __str__(self):
        return 'Unregistered Event ID %{:02x}'.format(self.eventid)

class RegisteredEventId(EventRegistrationException):
    def __str__(self):
        return 'Already registered Event ID %{:02x}'.format(self.eventid)

class RegistrationNotAllowed(EventRegistrationException):
    def __str__(self):
        return 'Registrations of global events are not allowed ' \
          '(Event ID %{:02x})'.format(self.eventid)

def register_event_id(eventid, name, scope=CLIENT):
    global EVENTS_ID_REGISTRY

    if not eventid & CUSTOM:
        raise RegistrationNotAllowed(eventid)

    if eventid > 0x1F000000:
        raise ValueError('Invalid Event ID: should be less then 0x1F')
    elif scope not in (SERVER, CLIENT, DNSCNC):
        raise ValueError('Invalid scope, should be one of SERVER, CLIENT, DNSCNC')
    elif not all(x in ALLOWED_CHARS for x in name):
        raise ValueError('Only digits, letters, space and underscore allowed for event names')
    elif scope | eventid in EVENTS_ID_REGISTRY:
        raise RegisteredEventId(eventid)

    EVENTS_ID_REGISTRY[eventid] = name

    return eventid

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

def _event(eventid, client, server, handler, triggers, config, **kwargs):

    actions = []

    try:
        section = event_to_config_section(eventid)
        actions.extend(config.items(section))
    except NoSectionError:
        pass

    try:
        actions.extend(config.items('on_any_event'))
    except NoSectionError:
        pass

    if not actions:
        return

    event = event_to_string(eventid)

    for client_filter, action in actions:
        if client_filter.lower() in ('this', 'self', 'current', '@'):
            if eventid & CLIENT:
                client_filter = client.desc['id']
            elif eventid & DNSCNC:
                if client:
                    client_filter = '{:08x}'.format(client.spi)
                elif 'node' in kwargs:
                    client_filter = '{:012x}'.format(kwargs['node'])

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
            if client:
                action = action.replace('%c', '{:08x}'.format(client.spi))
            elif 'node' in kwargs:
                action = action.replace('%c', '{:012x}'.format(kwargs['node']))

        elif eventid & CLIENT:
            action = action.replace('%c', '{:08x}'.format(client.desc['id']))

            node = client.desc['node']

            criterias = ['*', 'any']

            criterias.append(node)
            criterias.extend(list(config.tags(node)))

        if client_filter not in criterias and not client_filter.startswith(('*', 'any')) and \
          client_filter not in server.get_clients(client_filter):

            logger.info(
                'Incompatible event: eventid=%s criterias=%s client_filter=%s action=%s',
                event, criterias, client_filter, action)

            continue

        logger.info('Compatible event: eventid=%s criterias=%s client_filter=%s action=%s',
            event, criterias, client_filter, action)

        if handler:
            if client_filter.startswith(('*', 'any')):
                client_filter = '*'

            handler.inject(
                action, client_filter,
                'Action for event "{}" apply to <{}>: {}'.format(
                    event, client_filter, action))


def event(eventid, client, server, **kwargs):
    handler = server.handler
    config = server.config
    triggers = server.triggers

    try:
        _event(eventid, client, server, handler, triggers, config, **kwargs)

    except Error, e:
        logger.error(e)

    except Exception, e:
        logger.exception(e)
