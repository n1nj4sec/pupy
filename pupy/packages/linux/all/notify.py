# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import dbus

def notification(text, title='', timeout=5, app='System', icon='', actions='', hint=''):
    idnum = 0
    title = title or ''

    bus = dbus.SessionBus()
    notif = bus.get_object(
        'org.freedesktop.Notifications',
        '/org/freedesktop/Notifications'
    )
    notify = dbus.Interface(notif, 'org.freedesktop.Notifications')
    notify.Notify(
        app, idnum, icon, title, text, actions, hint, timeout*1000
    )
