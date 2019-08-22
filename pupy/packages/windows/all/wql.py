# -*- encoding: utf-8 -*-

import wmi

def to_utf8(data):
    if isinstance(data, wmi._wmi_object):
        return to_utf8(data.id.split('!', 1)[1])

    elif type(data) != str:
        return data

    for encoding in ('utf-8', 'mbcs', 'utf-16le', 'latin1'):
        try:
            return data.decode(encoding)
        except UnicodeError:
            pass

    return data

def execute(query):
    try:
        client = wmi.WMI()
    except wmi.x_wmi_uninitialised_thread:
        import pythoncom
        pythoncom.CoInitialize()
        client = wmi.WMI()

    return client.query(query)

def execute_final(query):
    response = execute(query)

    columns = set()
    result = []

    for item in response:
        columns.update(item.properties.keys())

        result.append(
            tuple((to_utf8(column), to_utf8(getattr(item, column))) for column in item.properties)
        )

    _query = query.lower()
    try:
        idx_select = _query.index('select') + 7
        idx_from = _query.index('from')

        fields = to_utf8(query[idx_select:idx_from])
        if '*' not in fields:
            maybe_columns = tuple(x.strip() for x in fields.split(','))
            if all(column in columns for column in maybe_columns):
                columns = maybe_columns

    except ValueError:
        pass

    return tuple(columns), tuple(result)
