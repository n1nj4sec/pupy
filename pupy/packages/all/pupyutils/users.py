from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import getpass

from io import open

from network.lib.convcompat import fs_as_unicode_string


if os.name == 'nt':
    import win32net
    import win32api

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
                'name': fs_as_unicode_string(user['name']),
                'groups': [
                    fs_as_unicode_string(x)
                    for x in win32net.NetUserGetLocalGroups(None, user['name'])
                ],
                'admin': user['priv'] == 2,
                'home': (
                    '\\'.join((
                        fs_as_unicode_string(user['logon_server']),
                        fs_as_unicode_string(user['home_dir'])
                    ))
                ) if user['home_dir'] else 'default'
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
                fs_as_unicode_string(
                    y.strip()
                ) for x in open('/etc/shells').readlines()
                if x.startswith('/') for y in x.split()
            )
        except:
            shells = ()

        current = fs_as_unicode_string(getpass.getuser())
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
                'name': fs_as_unicode_string(user.pw_name),
                'groups': [
                    fs_as_unicode_string(x.gr_name)
                    for x in groups if user.pw_name in x.gr_mem
                ],
                'admin': user.pw_uid == 0,
                'home': fs_as_unicode_string(user.pw_dir)
            })

        return {
            'current': current,
            'users': result
        }
