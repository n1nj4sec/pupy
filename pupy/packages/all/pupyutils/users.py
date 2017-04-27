import os
import getpass

if os.name == 'nt':
    import win32net
    import win32api

    def users():
        result = []
        users, _, _ = win32net.NetUserEnum(None, 1)
        current = win32api.GetUserName()

        UF_ACCOUNT_DISABLE = 2
        UF_LOCKOUT = 16

        for user in users:
            if user['flags'] & (UF_ACCOUNT_DISABLE | UF_LOCKOUT):
                continue

            result.append({
                'name': user['name'],
                'groups': win32net.NetUserGetLocalGroups(None, user['name']),
                'admin': user['priv'] == 2
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
                x.strip() for x in open('/etc/shells').readlines() if x.startswith('/')
            )
        except:
            shells = ()

        current = getpass.getuser()
        groups = grp.getgrall()

        result = []

        for user in pwd.getpwall():
            if shells and user.pw_shell not in shells:
                continue

            result.append({
                'name': user.pw_name,
                'groups': [
                    x.gr_name for x in groups if user.pw_name in x.gr_mem
                ],
                'admin': user.pw_uid == 0
            })

        return {
            'current': current,
            'users': result
        }
