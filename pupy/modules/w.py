# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Color, Table
from datetime import datetime, timedelta

import logging

__class_name__="WModule"

ADMINS = (r'NT AUTHORITY\SYSTEM', 'root')


@config(cat="admin")
class WModule(PupyModule):
    """ list terminal sessions """

    dependencies = {
        'all': ['pupyps'],
        'windows': ['pupwinutils.security']
    }

    is_module=False

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="w", description=cls.__doc__)

    def run(self, args):
        if self.client.is_windows():
            EnumerateWTS = self.client.remote(
                'pupwinutils.security', 'EnumerateWTS')

            try:
                wts_sessions = EnumerateWTS()

                cols = ['#']

                sessions = wts_sessions.keys()

                records = []

                session_colors = {}

                state = {'#': 'State'}
                user = {'#': 'User'}
                client_info = {'#': 'Client'}
                client_res = {'#': 'Res'}
                time_info = {
                    k:{} for k in (
                        'LastInputTime', 'ConnectTime',
                        'DisconnectTime', 'LogonTime'
                    )
                }

                for session in sessions:
                    current = wts_sessions[session]['current']
                    session_state = wts_sessions[session]['state']
                    session_info = wts_sessions[session]['info']
                    session_client = wts_sessions[session]['client']

                    if current:
                        session = '<' + session + '>'

                    cols.append(session)

                    current_time = datetime.now()
                    disconnect_time = None
                    current_time = None
                    input_time = None

                    if session_info['CurrentTime']:
                        current_time = datetime.utcfromtimestamp(
                            session_info['CurrentTime'])

                    for time_info_record in time_info:
                        value = session_info[time_info_record]
                        if value:
                            value = datetime.utcfromtimestamp(value)
                            if time_info_record == 'DisconnectTime':
                                disconnect_time = value
                            elif time_info_record == 'LastInputTime':
                                input_time = value
                            elif time_info_record == 'CurrentTime':
                                current_time = value
                        else:
                            value = ''

                        time_info[time_info_record][session] = value

                    if session_state == 'Disconnected':
                        color = 'grey'
                    elif session_state == 'Listen':
                        color = 'cyan'
                    elif session_state == 'Active':
                        idle = None
                        if input_time:
                            idle = (current_time - input_time).total_seconds()

                        if idle is not None and idle < 10 * 60:
                            color = 'cyan'
                        elif disconnect_time > current_time:
                            color = 'lightgrey'

                    session_colors[session] = color

                    view_port = ''
                    if session_client['HRes'] and session_client['VRes']:
                        view_port = '{}x{}'.format(
                            session_client['HRes'], session_client['VRes'])

                    client_line = ''
                    if session_client['ClientName'] and session_client['ClientProductId']:
                        client_line = '{}\\{}@{} ({}/{} {}.{})'.format(
                            session_client['Domain'], session_client['UserName'],
                            session_client['ClientAddress'],
                            session_client['ClientName'], session_client['DeviceIdD'],
                            session_client['ClientProductId'], session_client['ClientBuildNumber']
                    )

                    client_info[session] = Color(client_line, color)
                    client_res[session] = Color(view_port, color)

                    state[session] = Color(session_state, color)

                    username = session_info['UserName']
                    domain = session_info['Domain']
                    if username:
                        if domain:
                            username = domain + '\\' + username

                    user[session] = Color(username, color)

                records.append(state)
                records.append(user)
                for time_info_type in time_info:
                    record = {'#': time_info_type}
                    record.update({
                        session:Color(
                            str(time_info[time_info_type][session]).rsplit('.')[0]
                            if time_info[time_info_type][session] else '',
                            session_colors[session]
                        ) for session in cols[1:]
                    })
                    records.append(record)
                records.append(client_info)
                records.append(client_res)

                self.log(Table(records, cols))
                return

            except Exception:
                pass

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
                                'WHAT': Color(what[:30]+'...' if len(what) > 30 else what, color)
                            })

                        tablein.append(object)

            self.table(tablein)

        except Exception, e:
            logging.exception(e)
