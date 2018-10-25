# -*- coding: utf-8 -*-

import urllib2
import re
import json
import base64
import string

is_dict = re.compile(r'^(\d+)=([^/]+)$')

def get(path, version='latest', section='meta-data'):
    if path == '/':
        path = ''

    try:
        return urllib2.urlopen('http://169.254.169.254/{}/{}/{}'.format(
            version, section, path), timeout=2
        ).read()

    except:
        return None

def dir(path, version='latest', section='meta-data'):
    path = '/'.join([x for x in path.split('/') if x]) + '/'
    data = get(path, version, section)

    if data:
        return [x for x in data.split('\n') if x]
    else:
        return data

def list(path, version='latest', section='meta-data'):
    result = {}
    for item in dir(path, version, section):
        result[item] = get('/'.join(path, item))
    return result

def valueconv(x):
    try:
        return int(x)
    except:
        pass

    try:
        return float(x)
    except:
        pass

    try:
        return json.loads(x)
    except:
        pass

    try:
        for l in x:
            if l in string.letters:
                base64.b64decode(x)
                return x
    except:
        pass

    if x == 'none':
        return None
    elif x.endswith('\n'):
        return x
    elif '\n' in x:
        return [valueconv(z) for z in x.split('\n')]

    return x

def as_dict(path='', version='latest', section='meta-data'):
    result = {}
    dirs = dir(path, version, section)
    if not dirs:
        return None

    for item in dirs:
        if item.endswith('/'):
            records = as_dict(path+item, version, section)
            if records:
                result[item[:-1]] = records

        elif is_dict.match(item):
            idx, name = is_dict.match(item).groups()
            records = as_dict(path+idx+'/', version, section)
            if records:
                result[name] = records
        else:
            result[item] = valueconv(get(path+item, version, section))

    return result

def metadata():
    result = as_dict()
    if result:
        result = {
            'meta-data': result
        }

        user_data = get('', section='user-data')
        if user_data:
            try:
                result.update({
                    'user-data': dict(x.split('=', 1) for x in user_data.split(';'))
                })
            except:
                result.update({
                    'user-data': user_data
                })

        result.update({
            'dynamic': as_dict('/', section='dynamic')
        })
        return 'EC2', result

    result = as_dict('', 'metadata', 'v1')

    if result:
        return 'DO', result

    return None, None
