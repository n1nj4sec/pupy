from __future__ import unicode_literals
import os
import json
from StringIO import StringIO

from ..PupyConfig import PupyConfig
from ..PupyCredentials import Encryptor

class Credentials(object):
    def __init__(self, client=None, config=None, password=None):
        self.config = config or PupyConfig()
        self.client = client
        self.db = os.path.join(
            self.config.get_folder('creds', {
                '%c': client or ''
            }), 'creds.json'
        )

        if Encryptor.initialized() or password:
            self.encryptor = Encryptor.instance(
                password=password, config=self.config)
        else:
            self.encryptor = None

        if not os.path.exists(self.db):
            self._save_db({'creds': []})

    def _save_db(self, data):
        jsondb = json.dumps(data, indent=4)
        with open(self.db, 'w+b') as db:
            if self.encryptor:
                self.encryptor.encrypt(StringIO(jsondb), db)
            else:
                db.write(jsondb)

            db.flush()

    def _load_db(self):
        try:
            with open(self.db) as db:
                content = db.read(8)
                db.seek(0)
                if content == ('Salted__'):
                    data = StringIO()
                    if self.encryptor:
                        self.encryptor.decrypt(db, data)
                    else:
                        raise EncryptionError(
                            'Encrpyted credential storage: {}'.format(self.db)
                        )
                    return json.loads(data.getvalue())
                else:
                    return json.load(db)
        except:
            return {'creds': []}

    def add(self, data):
        db = self._load_db()
        
        # add uid to sort creds by host
        for d in range(len(data)):
            data[d].update({'uid': self.client})
        
        db['creds'] = [
            dict(t) for t in frozenset([
                tuple(d.items()) for d in db['creds'] + data
            ])
        ]
        self._save_db(db)

    def display(self, search='all', isSorted=False):
        data = self._load_db()

        if isSorted:
            data = sorted(data['creds'], key=lambda d: d["uid"], reverse=True)
        else:
            data = sorted(data['creds'], key=lambda d: d["CredType"], reverse=True)

        if not data:
            print "The credential database is empty !"
            return

        if not isSorted:
            print "\nCredentials:\n"
            print "Category          Username                                Password                      URL/Hostname"
            print "--------          --------                                --------                      ------------"

        if search != 'all':
            dataToSearch = search
            found = False
        else:
            dataToSearch = None

        tmp_uid = ''
        for creds in data:
            found = False
            c = {'category': '', 'login': '', 'credtype': '', 'password': '', 'url': '', 'uid': ''}
            c['category'] = creds['Category']
            c['uid'] = creds['uid']
            more_info = []

            if 'Login' in creds:
                c['login'] = creds['Login']
                if 'Domain' in creds:
                    c['login'] = '%s\\%s' % (creds['Domain'], c['login'])
            else:
                if 'SSID' in creds:
                    c['login'] = 'SSID: %s' % creds['SSID']

            if 'Password' in creds:
                c['credtype'] = 'plaintext'
                c['password'] = creds['Password']

            if 'Hash' in creds:
                c['credtype'] = 'hash'
                c['password'] = creds['Hash']

            if 'URL' in creds:
                c['url'] = creds['URL']
            elif 'Host' in creds:
                c['url'] = creds['Host']

            if 'Port' in creds:
                more_info.append('port: %s' % creds['Port'])

            if 'SID' in creds:
                more_info.append('SID: %s' % creds['SID'])

            if 'Driver' in creds:
                more_info.append('Driver: %s' % creds['Driver'])

            if more_info:
                c['url'] += ' / ' + ' / '.join(more_info)

            # check if in the research
            if dataToSearch:
                for value in c:
                    if dataToSearch.lower() in c[value].lower():
                        found = True
                        break

            # print only data with password and remove false positive
            if c['password']:
                if (dataToSearch and found) or not dataToSearch:
                    if (tmp_uid != c['uid']) and isSorted:
                        tmp_uid = c['uid']
                        print '\nHost: %s' % c['uid']
                        print '-' * (len('Host') + len(c['uid']) + 2) + '\n'

                    print u"{}{}{}{}".format(
                           '{:<18}'.format(c['category']),
                           '{:<40}'.format(c['login']),
                           '{:<30}'.format(c['password']),
                           '{:<40}'.format(c['url']),
                    )

        print

    def flush(self):
        if os.path.exists(self.db):
            os.remove(self.db)
