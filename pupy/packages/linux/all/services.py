# -*- encoding: utf-8 -*-

import dbus
import os

def get_services_systemd():
    sys_bus = dbus.SystemBus()
    systemd = sys_bus.get_object('org.freedesktop.systemd1', '/org/freedesktop/systemd1')

    list_units = systemd.get_dbus_method('ListUnits', 'org.freedesktop.systemd1.Manager')

    objects = []

    for unit, description, loaded, active, status, _, sd_object, _, _, _ in list_units():
        if not unit.endswith('.service'):
            continue

        unit_object = sys_bus.get_object('org.freedesktop.systemd1', sd_object)
        service_iface = dbus.Interface(unit_object, 'org.freedesktop.DBus.Properties')
        properties = service_iface.GetAll('org.freedesktop.systemd1.Service')

        exec_start = properties.get('ExecStart')

        binpath = ''

        if not len(exec_start):
            continue

        exec_start = exec_start[-1]

        argv0, argv = exec_start[0], exec_start[1]
        binpath = None

        argv0 = unicode(argv0)
        argv = [unicode(x) for x in argv]

        if os.path.basename(argv0) == os.path.basename(argv[0]):
            binpath = argv0
        else:
            binpath = '{}| {}'.format(argv0, argv[0])

        if len(argv) > 1:
            binpath += ' ' + ' '.join([x if ' ' not in x else repr(x) for x in argv[1:]])

        objects.append({
            'name': unicode(unit),
            'display_name': unicode(description),
            'status': unicode(status),
            'pid': int(properties.get('MainPID')) or None,
            'binpath': unicode(binpath),
            'username': unicode(properties.get('User'))
        })

    return objects

if __name__ == '__main__':
    for x in get_services_systemd():
        print x
