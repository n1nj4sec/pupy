import os
import getpass
import sys

if os.name == 'nt':
    import win32net
    import win32api

    def to_unicode(x):
        tx = type(x)
        if tx == str:
            return x.decode(sys.getfilesystemencoding())
        elif tx == unicode:
            return x
        else:
            return str(x)

    def users():
        result = []
        users, _, _ = win32net.NetUserEnum(None, 3)
        current = win32api.GetUserName()

        UF_ACCOUNT_DISABLE = 2
        UF_LOCKOUT = 16

        for user in users:
            if user['flags'] & (UF_ACCOUNT_DISABLE | UF_LOCKOUT):
                continue

            result.append({
                'name': to_unicode(user['name']),
                'groups': [
                    to_unicode(x) for x in win32net.NetUserGetLocalGroups(None, user['name'])
                ],
                'admin': user['priv'] == 2,
                'home': (
                    to_unicode(user['logon_server']) + u'\\' + to_unicode(user['home_dir'])
                ) if user['home_dir'] else u'default'
            })

        return {
            'current': current,
            'users': result
        }

else:
    import pwd
    import grp

    def users():
        try:
            shells = set(
                y.strip() for x in open('/etc/shells').readlines()
                if x.startswith('/') for y in x.split()
            )
        except:
            shells = ()

        current = getpass.getuser()
        groups = grp.getgrall()

        result = []

        for user in pwd.getpwall():
            if not user.pw_shell:
                continue
            elif shells:
                if user.pw_shell not in shells:
                    continue
            elif user.pw_shell.split('/')[-1] in ('nologin','false'):
                continue

            result.append({
                'name': user.pw_name,
                'groups': [
                    x.gr_name for x in groups if user.pw_name in x.gr_mem
                ],
                'admin': user.pw_uid == 0,
                'home': user.pw_dir
            })

        return {
            'current': current,
            'users': result
        }
