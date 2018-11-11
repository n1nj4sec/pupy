# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Color
from datetime import datetime, timedelta

import logging

__class_name__="WModule"

ADMINS = (r'NT AUTHORITY\SYSTEM', 'root')

@config(cat="admin")
class WModule(PupyModule):
    """ list terminal sessions """

    dependencies = ['pupyps']
    is_module=False

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="w", description=cls.__doc__)

    def run(self, args):
        try:
            users = self.client.remote('pupyps', 'users')

            data = users()
            tablein = []

            for user, hosts in reversed(sorted(data.iteritems())):
                for host, sessions in hosts.iteritems():
                    for session in sessions:
                        color = ""

                        if 'idle' in session:
                            idle = session['idle']
                            color = "cyan" if idle < 10*60 else (
                                "grey" if idle > 60*60*24 else ""
                            )

                        if 'dead' in session:
                            color = 'darkgrey'

                        object = {
                            'HOST': Color(host, color),
                            'USER': Color(
                                user,
                                "yellow" if user in ADMINS else (
                                    "green" if session.get('me') else color)
                            ),
                            'LOGIN': Color(
                                str(datetime.fromtimestamp(int(session['started']))), color
                            ),
                        }

                        if session.get('terminal'):
                            if session.get('name'):
                                what = '{} {}'.format(
                                    session['exe'] if session.get('exe') else ('{'+session.get('name')+'}'),
                                    ' '.join(session['cmdline'][1:] if session.get('cmdline') else '')
                                )
                            else:
                                what = ''

                            object.update({
                                'IDLE': Color(
                                    str(timedelta(seconds=session['idle'])), color
                                ) if session.get('idle') else '',
                                'PID': Color(str(session.get('pid', '')), color),
                                'WHAT': Color(what[:30]+'…' if len(what) > 30 else what, color)
                            })

                        tablein.append(object)

            self.table(tablein)

        except Exception, e:
            logging.exception(e)
