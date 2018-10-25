#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

__all__ = [
  'ScriptletArgumentError', 'Scriptlet',
  'ScriptletsPacker', 'load_scriptlets'
]

from pupylib import getLogger
from pupylib.payloads  import dependencies
from pupylib.PupyCompile import Compiler

from collections import OrderedDict

from ast import (
    parse,
    TryExcept, FunctionDef,
    Num, Name, Str, Expr, Assign, If,
    Load, Param, NodeTransformer
)
from os import path, listdir

ROOT = path.abspath(path.join(path.dirname(__file__), '..', 'packages'))

logger = getLogger('scriptlets')

WRAPPING_TEMPLATE = '''
def __{scriptlet}_closure__():
    try:
       {scriptlet}_logger = logger.getChild("{scriptlet}")
       {scriptlet}_logger.debug('Start...')

       # SCRIPTLET BODY GOES HERE
       'PLACEHOLDER'

       {scriptlet}_main(logger={scriptlet}_logger, pupy=pupy)
       {scriptlet}_logger.debug('Done')

    except Exception, e:
        {scriptlet}_logger.exception(e)

__{scriptlet}_closure__()
del __{scriptlet}_closure__
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
        'description', 'dependencies', 'compatibility',
        'arguments', 'name', 'ast'
    )

    def __init__(self, name, description, dependencies, compatibility, arguments, ast):
        self.description = description
        self.dependencies = dependencies
        self.arguments = arguments
        self.name = name
        self.ast = ast
        self.compatibility = compatibility


def select_body_by_os(item, target_os):
    assert(type(item) == If)

    if not (type(item.test) == Str and item.test.s.startswith('__os:') and \
            item.test.s.endswith('__')):
        raise ValueError(
            'Invalid OS selection statement, should be "__os:target-os__"')

    required_os = item.test.s[5:-2]
    if required_os == target_os:
        return item.body
    elif len(item.orelse) == 1 and type(item.orelse[0]) == If:
        return select_body_by_os(item.orelse[0], target_os)
    elif not item.orelse:
        raise ValueError('Else statement should not be empty')

    return item.orelse

def str_to_int(value):
    if value.startswith('0x'):
        value = int(value, 16)
    elif value.startswith('0b'):
        value = int(value, 2)
    elif value.startswith('0o'):
        value = int(value, 8)
    else:
        value = int(value)

    return value

class ScriptletsPacker(object):
    def __init__(self, os=None, arch=None):
        self.scriptlets = OrderedDict()
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
                scriptlet=scriptlet.name)

            # Select part with proper OS if any
            # Should be top-level if statement if string test

            while True:
                os_selection_idx = None

                for idx, item in enumerate(scriptlet.ast.body):
                    if not (type(item) == If and type(item.test) == Str and \
                      item.test.s.startswith('__os:') and item.test.s.endswith('__')):
                        continue

                    os_selection_idx = idx
                    break

                if os_selection_idx is None:
                    break

                new_body = select_body_by_os(
                    scriptlet.ast.body[os_selection_idx],
                    self.os
                )

                scriptlet.ast.body = \
                  scriptlet.ast.body[:os_selection_idx] + \
                  new_body + scriptlet.ast.body[os_selection_idx+1:]

            # Bind args
            # There should be top level function main

            main_found = False
            shadow_kwargs = {'logger', 'pupy'}

            for item in scriptlet.ast.body:
                if not (type(item) == FunctionDef and item.name == 'main'):
                    continue

                main_found = True
                lineno = 0
                col_offset = 0

                item.name = scriptlet.name + '_main'
                for idx, (arg, value) in enumerate(zip(item.args.args, item.args.defaults)):
                    lineno = value.lineno
                    col_offset = value.col_offset
                    vtype = type(value)

                    if arg.id in shadow_kwargs:
                        shadow_kwargs.remove(arg.id)
                    elif arg.id in kwargs:
                        default = kwargs[arg.id]
                        if vtype == Num:
                            if type(default) not in (int, long):
                                default = str_to_int(default)

                            value.n = default
                        elif vtype == Str:
                            if type(default) not in (str, unicode):
                                default = str(default)
                            value.s = default
                        elif vtype == Name:
                            if value.id in ('True', 'False'):
                                if default.lower() in ('true', 'yes', 'on', '1'):
                                    value.id = 'True'
                                elif default.lower() in ('false', 'no', 'off', '0'):
                                    value.id = 'False'
                                else:
                                    raise ValueError('Expect True/False value for {}'.format(arg.id))
                            else:
                                new_value = None
                                try:
                                    new_value = Num(str_to_int(default))
                                except ValueError:
                                    new_value = Str(default)

                                new_value.lineno = value.lineno
                                new_value.col_offset = value.col_offset

                                item.args.defaults[idx] = new_value


                    elif vtype == Str and value.s.startswith('__global:') and value.s.endswith('__'):
                        global_name = value.s[9:-2]
                        global_ref = Name(global_name, Load())
                        global_ref.lineno = value.lineno
                        global_ref.col_offset = value.col_offset
                        item.args.defaults[idx] = global_ref

                for idx, shadow_kwarg in enumerate(shadow_kwargs):
                    shadow_name = Name(shadow_kwarg, Param())
                    shadow_name.lineno = lineno
                    shadow_name.col_offset = col_offset + (idx*16)
                    item.args.args.append(shadow_name)

                    shadow_value = Name('None', Load())
                    shadow_value.lineno = lineno
                    shadow_value.col_offset = col_offset + (idx*16)+7
                    item.args.defaults.append(shadow_value)

                break

            if not main_found:
                raise ValueError(
                    'Scriptlet {} - Invalid source code. '
                    '"def main():" not found'.format(
                        scriptlet.name))

            placeholder_idx = None

            # Wrap in try/except, and other things
            template_ast = parse(template)
            for item in template_ast.body:
                if not(type(item) == FunctionDef and \
                       item.name == '__{}_closure__'.format(scriptlet.name)):
                    continue

                assert(len(item.body) == 1 and type(item.body[0]) == TryExcept)

                closure = item.body[0]

                for idx, payload in enumerate(closure.body):
                    if type(payload) is not Expr:
                        continue

                    if type(payload.value) is Str and payload.value.s == 'PLACEHOLDER':
                        placeholder_idx = idx
                        break

                assert(placeholder_idx is not None)

                closure.body = closure.body[:placeholder_idx] + scriptlet.ast.body + \
                  closure.body[placeholder_idx+1:]

                break

            if placeholder_idx is None:
                raise ValueError('Template placeholder not found. Fill the bug report')

            compiler.add_ast(template_ast)

        return compiler.compile('sbundle', raw=True)

def parse_scriptlet(filedir, filename):
    filepath = path.join(filedir, filename)
    filecontent = None

    name, _ = path.splitext(filename)

    with open(filepath) as content:
        filecontent = content.read()

    fileast = None
    fileast = parse(filecontent)

    docstrings = []

    # Search/evaluate/delete.
    # 1. docstring
    # 2. dependencies
    # 3. arguments
    # 4. compatibility

    meta = parse('')

    to_delete = []

    for item in fileast.body:
        if type(item) == Expr and type(item.value) == Str:
            # docstring found
            docstrings.append(item.value.s)
        elif type(item) == Assign and all(
            type(x) == Name and x.id.startswith('__') and \
            x.id.endswith('__') and x.id for x in item.targets
        ):
            # metadata found
            meta.body.append(item)
        else:
            continue

        to_delete.append(item)

    for item in to_delete:
        idx = fileast.body.index(item)
        del fileast.body[idx]

    metadata = compile(meta, 'metadata-'+filename, 'exec')
    metadict = {}
    exec (metadata, metadict)
    del metadict['__builtins__']

    docstring = '\n'.join(
        x.strip() for x in docstrings
    )

    return Scriptlet(
        name,
        docstring,
        metadict.get('__dependencies__', []),
        metadict.get('__compatibility__', None),
        metadict.get('__arguments__', {}),
        fileast
    )

def iterate_scriptlet_files():
    visited = set()

    default_dir = path.dirname(__file__)

    for filedir in (default_dir, 'scriptlets'):
        if not path.isdir(filedir):
            continue

        filedir = path.abspath(filedir)
        if filedir in visited:
            continue

        visited.add(filedir)

        for filename in listdir(filedir):
            if not filename.endswith('.py') or filename.startswith('_'):
                continue

            yield filedir, filename

def load_scriptlets(target_os, target_arch):

    scriptlets = {}

    for dirname, filename in iterate_scriptlet_files():
        try:
            scriptlet = parse_scriptlet(dirname, filename)
            if scriptlet.compatibility and target_os != 'any' and target_os not in scriptlet.compatibility:
                logger.info('Scriptlet {} is incompatible with {}'.format(
                    scriptlet.name, target_os))
                continue

            scriptlets[scriptlet.name] = scriptlet

        except SyntaxError, e:
            logger.error('SyntaxError (scriptlet=%s:%d:+%d):\nline: %s\nError: %s',
                         filename, e.lineno, e.offset, e.text.strip(), e.msg)

        except IOError, e:
            logger.debug(e)
        except Exception, e:
            logger.exception(e)

    return scriptlets
