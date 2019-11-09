# -*- coding: utf-8 -*-

import sys

from threading import Thread, Event

use_system_odbc = True

if sys.platform != 'win32':
    import os
    import tempfile
    import ctypes

    odbcinstini = tempfile.NamedTemporaryFile()
    os.environ['ODBCSYSINI'] = ''
    os.environ['ODBCINSTINI'] = odbcinstini.name

    registered = set()

    def register_driver(name, description, library):
        if name in registered:
            return False

        odbcinstini.write('\n'.join([
            '[{}]'.format(name),
            'Description={}'.format(description or 'None'),
            'Driver={}'.format(library),
            ''
        ]))
        odbcinstini.flush()
        registered.add(name)
        return True

else:
    def register_driver(name, library):
        raise NotImplementedError()


CONNECTIONS = {}

END = 0
HEADER = 1
DATA = 2
LOG = 3
ERROR = 4


def _get(alias):
    if alias is None and len(CONNECTIONS) > 0:
        alias = next(iter(CONNECTIONS))
        return alias, CONNECTIONS[alias]

    ctx = CONNECTIONS.get(alias, None)
    if not ctx:
        raise ValueError(
            'Alias {} is not registered, use "bind" first'.format(alias))

    return alias, ctx


def bind(alias, connstring, encoding=False):
    if alias in CONNECTIONS:
        raise ValueError('Alias already registered')

    import pyodbc

    ctx = pyodbc.connect(connstring)
    if encoding is True:
        ctx.setdecoding(pyodbc.SQL_WCHAR, encoding='utf-8')
    elif encoding:
        ctx.setdecoding(pyodbc.SQL_WCHAR, encoding=encoding)

    CONNECTIONS[alias] = connstring, ctx
    return alias


def unbind(alias):
    alias, (_, ctx) = _get(alias)
    ctx.close()
    del CONNECTIONS[alias]
    return alias


def _convval(value):
    if isinstance(value, (int, long, str, unicode)):
        return value

    return str(value)


def _sql_throw(cursor, on_data, completion, limit, portion):
    description = []
    buffer = []

    completed = False
    offset = 0

    on_data(LOG, 'Fetch started')

    for row_info in cursor.description:
        description.append(
            (row_info[0], row_info[1].__name__)
        )

    on_data(HEADER, tuple(description))

    while not completion.is_set() and (offset < limit):
        row = cursor.fetchone()

        if not row:
            if buffer:
                on_data(DATA, tuple(buffer))
                del buffer[:]

            completed = True
            cursor.close()
            on_data(END, None)
            break

        else:
            offset += 1
            buffer.append(
                tuple(
                    _convval(column) for column in row
                )
            )

        if len(buffer) >= portion:
            on_data(DATA, tuple(buffer))
            del buffer[:]

    if buffer:
        on_data(DATA, tuple(buffer))

    if not completed:
        try:
            cursor.cancel()
            on_data(LOG, 'Fetch cancelled')
        finally:
            try:
                cursor.close()
                on_data(LOG, 'Fetch completed')
            finally:
                on_data(END, None)



def _sql(cursor, on_data, completion, limit, portion=4096):
    try:
        _sql_throw(cursor, on_data, completion, limit, portion)
    except Exception as e:
        import traceback
        on_data(ERROR, '{}: {}'.format(e, traceback.format_exc()))


def tables(alias):
    _, (_, ctx) = _get(alias)
    cursor = ctx.cursor()

    catalogs = {}

    try:
        for table in cursor.tables():
            catalog = table[0]
            cur = None

            if catalog not in catalogs:
                catalogs[catalog] = []

            cur = catalogs[catalog]
            cur.append((
                '.'.join([table[1], table[2]]),
                table[3]
            ))
    finally:
        cursor.close()

    return catalogs


def describe(alias, table):
    _, (_, ctx) = _get(alias)
    cursor = ctx.cursor()

    try:
        cursor.execute('SELECT * FROM {} WHERE 1=0'.format(table))

        return tuple(
            (info[0], info[1].__name__) for info in cursor.description
        )

    finally:
        cursor.close()


def many(alias, query, limit, on_data):
    _, (_, ctx) = _get(alias)

    query = query.strip()
    cursor = ctx.cursor()
    cursor = cursor.execute(query)
    completion = Event()

    worker = Thread(
        target=_sql,
        args=(
            cursor, on_data, completion, limit
        ),
        name='SQL: ' + query
    )
    worker.daemon = True
    worker.start()

    def _completion():
        completion.set()
        cursor.cancel()

    return _completion


def one(alias, query):
    _, (_, ctx) = _get(alias)

    query = query.strip()
    cursor = ctx.cursor()
    try:
        return cursor.execute(query).fetchval()
    finally:
        cursor.close()


def bounded():
    return tuple(
        (alias, connstring) for alias, (
            connstring, _) in CONNECTIONS.iteritems()
    )


def drivers():
    try:
        import pyodbc
    except ImportError:
        return []

    return pyodbc.drivers()


def need_impl():
    try:
        import pyodbc
        return False
    except (ImportError, OSError):
        return True
