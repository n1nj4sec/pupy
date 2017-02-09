from __future__ import unicode_literals
import os
import json

class Credentials(object):
    def __init__(self):
        ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "db"))
        dbName = 'creds.json'

        # check if the db exists
        self.db = ROOT + os.sep + dbName
        if not os.path.exists(ROOT):
            os.makedirs(ROOT)

        if not os.path.exists(self.db):
            f = open(self.db, "w")
            f.write('{"creds": []}')
            f.close()

    # check if dictionnary already exists in dictionnary_tab
    def checkIfExists(self, dictionnary, dictionnary_tab):
        for d in dictionnary_tab:
            shared_items = set(d.items()) & set(dictionnary.items())
            if len(shared_items) == len(d):
                return True
        return False

    def add(self, data):
        with open(self.db) as json_db:
            db = json.load(json_db)

        for d in data:
            if not self.checkIfExists(d, db['creds']):
                db['creds'].append(d)

        with open(self.db, 'w') as json_db: 
            json_db.write(json.dumps(db, indent=4))

    def display(self, search='all', isSorted=False):
        with open(self.db) as json_db:    
            data = json.load(json_db)
        
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
