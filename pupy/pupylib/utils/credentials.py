import os
import json

class Credentials():
    def __init__(self):
        ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__),"..", "..", "db"))
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
            json_db.write(json.dumps(db))

    def show(self):
        tool = ""
        with open(self.db) as json_db:    
            data = json.load(json_db)
        
        # List sorted by Tools
        data = sorted(data['creds'], key=lambda d: d["Tool"], reverse=True)
        for creds in data:
            if "Tool" in creds:
                if tool != creds["Tool"]:
                    print '\n---------- %s ---------- \n' % creds["Tool"]
                    tool = creds["Tool"]
                del creds["Tool"]
            
            if tool == 'Creddump':
                for cred in creds:
                    if creds[cred]:
                        print '%s' % creds[cred]
            else:
                for cred in creds:
                    if creds[cred]:
                        print '%s: %s' % (cred, creds[cred])
                print
        print

    def flush(self):
        if os.path.exists(self.db):
            os.remove(self.db)
