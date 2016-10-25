# -*- coding: utf-8 -*-

import dbus

def notification(text, title='', timeout=5, app='System', icon='', actions='', hint=''):
    idnum = 0

    bus = dbus.SessionBus()
    notif = bus.get_object(
        'org.freedesktop.Notifications',
        '/org/freedesktop/Notifications'
    )
    notify = dbus.Interface(notif, 'org.freedesktop.Notifications')
    notify.Notify(
        app, idnum, icon, title, text, actions, hint, timeout*1000
    )
