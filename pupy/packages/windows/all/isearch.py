# -*- encoding: utf-8 -*-

import adodbapi
import sys
import datetime

PROVIDER = 'provider=Search.CollatorDSO.1;EXTENDED?PROPERTIES="Application=Windows"'

def query(sql, limit):
    data = []
    error = None
    idx = 0
    cidx = 0

    encoding = sys.getfilesystemencoding()

    conn = adodbapi.connect(PROVIDER)

    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        for idx, record in enumerate(cursor):

            if idx >= limit:
                break

            line = []
            for cidx, column in enumerate(record):
                if type(column) == str:
                    column = column.decode(encoding)
                elif type(column) == datetime.datetime:
                    column = int((
                        column - datetime.datetime.utcfromtimestamp(0)
                    ).total_seconds())
                line.append(column)
            data.append(tuple(line))

    except adodbapi.apibase.DatabaseError, e:
        # ZOMG
        parts = e.message.split('\n')
        code = eval(parts[0])[1].decode(encoding)
        error = '\n'.join(parts[1:]) + '\n' + code

    finally:
        conn.close()

    return idx, cidx, data, error
