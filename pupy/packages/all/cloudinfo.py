# -*- coding: utf-8 -*-

import urllib2
import re
import json
import base64
import string

is_dict = re.compile(r'^(\d+)=([^/]+)$')


METADATA_SERVER = 'http://169.254.169.254'
METADATA_PROVIDER = None
METADATA_ROOT = None
METADATA_HEADERS = []
METADATA_PARAMS = ''


def _probe():
    global METADATA_ROOT
    global METADATA_PROVIDER
    global METADATA_HEADERS
    global METADATA_PARAMS

    if get('', 'latest/meta-data'):
        METADATA_PROVIDER = 'EC2'
        METADATA_ROOT = 'latest'

    elif get('', 'metadata/v1'):
        METADATA_PROVIDER = 'DO'
        METADATA_ROOT = 'metadata/v1'

    else:
        result = get('', 'metadata', [('Metadata', 'true')], 400)
        if not result:
            raise ValueError('Unknown metadata implementation')

        error = json.loads(result)
        version = error['newest-versions'][0]

        METADATA_PROVIDER = 'MS'
        METADATA_HEADERS = [('Metadata', 'true')]
        METADATA_ROOT = 'metadata/instance'
        METADATA_PARAMS = '?api-version={}&format=json'.format(version)

    return METADATA_PROVIDER, METADATA_ROOT, METADATA_HEADERS


def get(path, root=None, headers=None, code=200):
    opener = urllib2.build_opener()
    opener.addheaders = \
        METADATA_HEADERS if headers is None else headers

    path = '/'.join([x for x in path.split('/') if x])

    uri = '/'.join([
        METADATA_SERVER,
        METADATA_ROOT if root is None else root,
        path or ''
    ]) + METADATA_PARAMS

    try:
        response = opener.open(uri, timeout=2)
        if response.code != code:
            return None

    except urllib2.HTTPError as e:
        if e.code == code:
            return e.fp.read()
        else:
            return None

    return response.read()


def metadir(path):
    data = get(path)

    if data:
        return [x for x in data.split('\n') if x]
    else:
        return data


def isint(x):
    try:
        int(x)
        return True
    except:
        return False


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
        for letter in x:
            if letter in string.letters:
                base64.b64decode(x)
                return x
    except:
        pass

    if x is None or x == 'none':
        return None
    elif x.endswith('\n'):
        return x
    elif '\n' in x:
        return [valueconv(z) for z in x.split('\n')]

    return x


def as_dict(path=''):
    result = {}
    dirs = metadir(path)
    if not dirs:
        return None

    for item in dirs:
        if item.endswith('/'):
            records = as_dict('/'.join([path, item]))
            if records:
                result[item[:-1]] = records

        elif is_dict.match(item):
            idx, name = is_dict.match(item).groups()
            records = as_dict('/'.join([path, idx + '/']))
            if records:
                result[name] = records
        else:
            result[item] = valueconv(get('/'.join([path, item])))

    if isinstance(result, dict) and all(
            (isint(key) and int(key) < len(result)) for key in result):
        as_list = [None] * len(result)
        for key, value in result.iteritems():
            as_list[int(key)] = value

        result = as_list

    return result


def metadata():
    if METADATA_PROVIDER is None:
        try:
            _probe()
        except ValueError:
            return None

    if METADATA_PROVIDER == 'EC2':
        result = {
            'meta-data': as_dict('meta-data'),
            'dynamic': as_dict('dynamic'),
        }

        user_data = as_dict('user-data')
        if user_data:
            try:
                result['user-data'] = dict(
                    x.split('=', 1) for x in user_data.split(';')
                )
            except:
                result['user-data'] = user_data

    elif METADATA_PROVIDER == 'MS':
        result = json.loads(get(''))
    else:
        result = as_dict()

    return METADATA_PROVIDER, result
