#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import subprocess

def shell_exec(client, cmdline, shell=None):
    """ cmdline can be either a list of arguments or a string """
    if type(cmdline) is not list:
        cmdline=cmdline.split()
    res=""
    try:
        if client.is_android():
            if shell is None:
                shell="/system/bin/sh"
        if shell is None:
            res=client.conn.modules.subprocess.check_output(cmdline, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell=True, universal_newlines=True)
        else:
            if client.is_windows():
                command=[shell, '/c'] + cmdline
            else:
                command=[shell, '-c'] + cmdline
            res=client.conn.modules.subprocess.check_output(command, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, universal_newlines=True)
    except Exception as e:
        if hasattr(e,'output') and e.output:
            res=e.output
        else:
            res=str(e)
        
    if client.is_windows():
        try:
            res=res.decode('cp437')
        except Exception:
            pass
    return res

