from __future__ import unicode_literals
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os
import json
import codecs

from pupy.network.lib.convcompat import (
    ExtendedJsonEncoder, ExtendedJsonDecoder,
    as_unicode_string, as_unicode_string_deep
)

from io import BytesIO

from ..PupyConfig import PupyConfig
from ..PupyCredentials import Encryptor


class EncryptionError(Exception):
    pass


class Credentials(object):
    def __init__(self, client=None, config=None, password=None):
        self.config = config or PupyConfig()
        self.client = client
        self.db = os.path.join(
            self.config.get_folder('creds'),
            'creds.json'
        )

        if Encryptor.initialized() or password:
            self.encryptor = Encryptor.instance(
                password=password, config=self.config)
        else:
            self.encryptor = None

        if not os.path.exists(self.db):
            self._save_db({'creds': []})

    def _save_db(self, data):
        with open(self.db, 'w+') as db:
            if self.encryptor:
                jsondb = json.dumps(data, cls=ExtendedJsonEncoder, indent=4)
                self.encryptor.encrypt(BytesIO(jsondb), db)
            else:
                json.dump(data, db, cls=ExtendedJsonEncoder, indent=4)

    def _db_is_encrypted(self):
        with open(self.db) as db:
            content = db.read(8)
            return content == b'Salted__'

    def _load_db(self):
        if self._db_is_encrypted():
            with open(self.db, 'rb') as db:
                data = BytesIO()
                if self.encryptor:
                    self.encryptor.decrypt(db, data)
                else:
                    raise EncryptionError(
                        'Encrpyted credential storage: {}'.format(self.db)
                    )
                return json.loads(
                    data.getvalue(), cls=ExtendedJsonDecoder
                )
        else:
            with open(self.db, 'r') as db:
                return json.load(db, cls=ExtendedJsonDecoder)

    def add(self, data, cid=None):
        try:
            db = self._load_db()
        except ValueError:
            db = {'creds': []}

        if not cid:
            if not self.client:
                raise ValueError('Client ID (cid) required')

            cid = self.client.node()

        data = as_unicode_string_deep(list(data), fail=False)

        for d in data:
            for k in d:
                if not k.lower() == k:
                    d[k.lower()] = d[k]
                    del d[k]

            if 'credtype' not in d:
                if d.get('password'):
                    d['credtype'] = 'plaintext'
                elif d.get('hash'):
                    d['credtype'] = 'hash'
                elif d.get('key'):
                    d['credtype'] = 'key'
                else:
                    d['credtype'] = 'unknown'

            d['cid'] = cid

        db['creds'] = [
            dict(t) for t in frozenset([
                tuple(d.items()) for d in db['creds'] + data
            ])
        ]

        self._save_db(db)

    def display(self, search=None, is_sorted=False):
        search = as_unicode_string(search)

        data = self._load_db()

        if is_sorted:
            data = sorted(
                data['creds'],
                key=lambda d: d.get('cid', d.get('uid')),
                reverse=True
            )
        else:
            data = sorted(
                data['creds'],
                key=lambda d: d.get('credtype'), reverse=True
            )

        if not data:
            return

        for creds in data:
            creds = {k.lower(): v for k, v in creds.items()}

            c = {
                'category': creds['category'],
                'cid': creds.get('cid', creds.get('uid')),
                'credtype': creds.get('credtype'),
                'login': '',
                'secret': '',
                'resource': ''
            }

            if 'login' in creds:
                c['login'] = creds['login']
                if 'domain' in creds:
                    c['login'] = '%s\\%s' % (creds['domain'], c['login'])
            elif 'sid' in creds:
                c['login'] = 'SID: %s' % creds['sid']
            elif 'ssid' in creds:
                c['login'] = 'SSID: %s' % creds['ssid']
            elif 'user' in creds:
                c['login'] = creds['user']
            elif 'id' in creds:
                c['login'] = creds['id']
            elif 'label' in creds:
                c['login'] = creds['label']
            elif 'service' in creds:
                c['login'] = creds['service']
            elif 'defaultpassword' in creds:
                c['login'] = 'DefaultPassword'
            elif 'username' in creds:
                c['login'] = creds['username']

            if 'password' in creds:
                c['secret'] = creds['password']
            elif 'hash' in creds:
                c['secret'] = creds['hash']
            elif 'key' in creds:
                c['secret'] = creds['key']
            elif 'defaultpassword' in creds:
                c['secret'] = creds['defaultpassword']

            if 'url' in creds:
                c['resource'] = creds['url']
            elif 'host' in creds:
                c['resource'] = creds['host']
                if 'port' in creds:
                    c['resource'] += ':{}'.format(creds['port'])
            elif 'process' in creds:
                c['resource'] = creds['process']
            elif 'hub' in creds:
                c['resource'] = creds['hub']
            elif 'cmd' in creds:
                c['resource'] = creds['cmd']
            elif 'domain' in creds and 'file' in creds:
                c['resource'] = creds['domain']

            # check if in the research
            found = True

            if search:
                found = False
                for value in c.values():
                    if search.lower() in value.lower():
                        found = True
                        break

            # print only data with password and remove false positive
            if not found:
                continue

            yield c

    def remove(self):
        if os.path.exists(self.db):
            os.remove(self.db)
