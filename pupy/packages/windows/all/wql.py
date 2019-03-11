# -*- encoding: utf-8 -*-

import wmi

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
    keys = set()
    result = []
    order = None

    for item in response:
        keys.update(item.keys)
        columns.update(item.properties.keys())

        result.append(
            tuple((column, getattr(item, column)) for column in item.properties)
        )

    _query = query.lower()
    try:
        idx_select = _query.index('select') + 7
        idx_from = _query.index('from')

        fields = query[idx_select:idx_from]
        if '*' not in fields:
            maybe_columns = tuple(x.strip() for x in fields.split(','))
            if all(column in columns for column in maybe_columns):
                columns = maybe_columns

    except ValueError:
        pass

    return tuple(keys), tuple(columns), tuple(result)
