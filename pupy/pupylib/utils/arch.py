# -*- coding: utf-8 -*-

import platform
import sys


def make_os_arch(os_arch):
    substitute = {
        'x86_64': 'amd64',
        'i386': 'x86',
        'i686': 'x86',
        'i486': 'x86',
        'armv7l': 'armhf'
    }

    return substitute.get(os_arch, os_arch)


def make_template_arch(os_arch):
    substitute = {
        'x86_64': 'x64',
        'amd64': 'x64',
        'i386': 'x86',
        'i686': 'x86',
        'i486': 'x86',
        'armv7l': 'armhf'
    }

    return substitute.get(os_arch, os_arch)


def make_proc_arch(os_arch, proc_arch):
    os_arch = make_os_arch(os_arch)

    os_arch_to_platform = {
        'amd64': 'intel',
        'x86': 'intel',
        'i86pc': 'sun-intel',
        'armhf': 'armhf',
        'aarch64': 'arm',
    }

    os_platform_to_arch = {
        'intel': {
            '32bit': 'x86',
            '64bit': 'amd64'
        },
        'sun-intel': {
            # Yes.. Just one arch supported
            # The script is for amd64
            '32bit': 'i86pc',
            '64bit': 'i86pc'
        },
        'armhf': {
            '32bit': 'armhf',
            '64bit': 'armhf'
        },
        'arm': {
            '32bit': 'arm',
            '64bit': 'aarch64'
        }
    }

    if os_arch in os_arch_to_platform:
        return os_platform_to_arch[
            os_arch_to_platform[os_arch]
        ][proc_arch]
    else:
        return proc_arch


def is_native(os_arch, proc_arch, pyver):
    target_pymaj, target_pymin = pyver[:2]
    local_pymaj, local_pymin = sys.version_info[:2]

    target_arch = make_proc_arch(os_arch, proc_arch)
    local_arch = platform.machine()

    return all(target == local for target, local in zip([
        target_pymaj, target_pymin, target_arch
    ], [
        local_pymaj, local_pymin, local_arch
    ]))

def same_as_local_arch(os_arch, proc_arch):
    target_arch = make_proc_arch(os_arch, proc_arch)
    local_arch = make_os_arch(platform.machine())
    local_os = sys.platform.lower()
    if local_os=="win32":
        local_os="windows"
    return all(target == local for target, local in zip([
        target_arch, os_arch
    ], [
        local_arch, local_os
    ]))
