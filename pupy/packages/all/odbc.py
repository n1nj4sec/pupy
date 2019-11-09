# -*- coding: utf-8 -*-

import sys

from inspect import isfunction
from threading import Thread, Event

use_system_odbc = True

if sys.platform != 'win32':
    import os
    import tempfile

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


def as_cursor(cleanup=True):
    def _as_cursor_wrap_gen(func, cleanup):
        def _wrapper(alias, *args, **kwargs):
            from pyodbc import connect, OperationalError, SQL_WCHAR

            try:
                key, (connstr, encoding, ctx) = _get(alias)
                cursor = ctx.cursor()
                try:
                    return func(cursor, *args, **kwargs)
                except Exception:
                    if cleanup:
                        cursor.cancel()
                    raise
                finally:
                    if cleanup:
                        cursor.close()
            except OperationalError as e:
                if e.args[0] in ('08S01', '08003'):
                    try:
                        new_ctx = connect(connstr)

                        if encoding is True:
                            new_ctx.setdecoding(SQL_WCHAR, encoding='utf-8')
                        elif encoding:
                            new_ctx.setdecoding(SQL_WCHAR, encoding=encoding)

                        CONNECTIONS[key] = connstr, encoding, new_ctx
                        ctx.close()
                        cursor = new_ctx.cursor()
                        try:
                            return func(cursor, *args, **kwargs)
                        except Exception:
                            if cleanup:
                                cursor.close()
                            raise
                        finally:
                            if cleanup:
                                cursor.close()
                    except OperationalError:
                        pass

                _, _, ctx = CONNECTIONS[key]
                ctx.close()

                del CONNECTIONS[key]
                raise

        return _wrapper

    if isfunction(cleanup):
        return _as_cursor_wrap_gen(cleanup, True)

    def _wrap(func):
        return _as_cursor_wrap_gen(func, cleanup)

    return _wrap


def bind(alias, connstring, encoding=False):
    if alias in CONNECTIONS:
        raise ValueError('Alias already registered')

    import pyodbc

    ctx = pyodbc.connect(connstring)
    if encoding is True:
        ctx.setdecoding(pyodbc.SQL_WCHAR, encoding='utf-8')
    elif encoding:
        ctx.setdecoding(pyodbc.SQL_WCHAR, encoding=encoding)

    CONNECTIONS[alias] = connstring, encoding, ctx
    return alias


def unbind(alias):
    alias, (_, _, ctx) = _get(alias)
    try:
        ctx.close()
    finally:
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
    finally:
        cursor.cancel()
        cursor.close()


@as_cursor
def tables(cursor):
    catalogs = {}

    for table in cursor.tables():
        catalog = table[0]
        cur = None

        if catalog not in catalogs:
            catalogs[catalog] = []

        cur = catalogs[catalog]
        cur.append((
            '.'.join(
                part for part in [
                    table[1], table[2]
                ] if part),
            table[3]
        ))

    return catalogs


@as_cursor
def describe(cursor, table):
    cursor.execute('SELECT * FROM {} WHERE 1=0'.format(table))

    return tuple(
        (info[0], info[1].__name__) for info in cursor.description
    )


@as_cursor(cleanup=False)
def many(cursor, query, limit, on_data):

    query = query.strip()
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


@as_cursor
def one(cursor, query):
    query = query.strip()
    return cursor.execute(query).fetchval()


def bounded():
    return tuple(
        (alias, connstring) for alias, (
            connstring, _, _) in CONNECTIONS.iteritems()
    )


def drivers():
    try:
        import pyodbc
    except ImportError:
        return []

    return pyodbc.drivers()


def need_impl():
    try:
        __import__('pyodbc')
        return False
    except (ImportError, OSError):
        return True
