#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import subprocess

def shell_exec(client, cmdline, shell=None, env=None, encoding=None):
    """ cmdline can be either a list of arguments or a string """

    check_output = client.remote('subprocess', 'check_output')

    res = ''

    try:
        if client.is_android():
            if shell is None:
                shell="/system/bin/sh"
        if shell is None:
            res = check_output(
                cmdline,
                stderr = subprocess.STDOUT,
                stdin = subprocess.PIPE,
                shell = True,
                universal_newlines = True,
                env=env
            )
        else:
            if client.is_windows():
                command=[shell, '/c', cmdline]
            else:
                command=[shell, '-c', cmdline]

            res = check_output(
                command,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                universal_newlines=True,
                env=env
            )

    except Exception as e:
        if hasattr(e, 'output') and e.output:
            res = e.output
        else:
            res = str(e)

    if encoding:
        try:
            res = res.decode(encoding)
        except Exception:
            pass

    return res
