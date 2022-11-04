from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = ('PythonCompleter',)

import re
import inspect

try:
    import keyword
except ImportError:
    keyword = None

from pupy.network.lib.convcompat import as_native_string


class PythonCompleter(object):
    __slots__ = (
        'local_ns', 'global_ns', 'matches'
    )

    def __init__(self, local_ns=None, global_ns=None):
        if local_ns is not None:
            self.local_ns = local_ns
        else:
            self.local_ns = {}

        if global_ns is not None:
            self.global_ns = global_ns
        else:
            self.global_ns = globals()

        self.matches = ()

    def complete(self, text, state):
        text = as_native_string(text)

        if state == 0:
            if '.' in text:
                self.matches = tuple(self.attr_matches(text))
            else:
                self.matches = tuple(self.var_matches(text))

        try:
            return self.matches[state]

        except IndexError:
            return None

    def var_matches(self, text):
        m = re.match(r'\s*(\w+)', text)

        if not m:
            return []

        text = m.group(1)

        words = [
            x for x in self.local_ns if x.startswith(text)
        ]

        if keyword is not None:
            words.extend(
                x for x in keyword.kwlist if x.startswith(text)
            )

        if '__builtins__' in words:
            words.remove('__builtins__')

        return words

    def attr_matches(self, text):
        '''
        Compute matches when text contains a dot.

        Assuming the text is of the form NAME.NAME....[NAME], and is
        evaluatable in self.namespace, it will be evaluated and its attributes
        (as revealed by dir()) are used as possible completions.  (For class
        instances, class members are also considered.)

        WARNING: this can still invoke arbitrary C code, if an object
        with a __getattr__ hook is evaluated.
        '''

        bsw = "[a-zA-Z0-9_\\(\\)\\[\\]\"']"

        m = re.match(r'(\w+(\.\w+)*)\.(\w*)'.replace(r'\w', bsw), text)
        if not m:
            return []

        expr, attr = m.group(1, 3)

        chain = expr.split('.')
        thisobject = None

        while chain:
            thisobject_name = chain.pop(0)
            if thisobject_name is None:
                break

            if thisobject is None:
                thisobject = self.local_ns.get(thisobject_name)
                if thisobject is None:
                    return []
            else:
                try:
                    thisobject = object.__getattribute__(
                        thisobject, thisobject_name
                    )
                except AttributeError:
                    return []

        if thisobject is None:
            return []

        words = [
            name for name, value in inspect.getmembers(thisobject)
        ]

        matches = []

        n = len(attr)

        for word in words:
            if attr and word[:n] != attr:
                continue

            value = object.__getattribute__(thisobject, word)

            try:
                object.__getattribute__(value, '__call__')
                word += '('
            except AttributeError:
                pass

            matches.append(expr + '.' + word)

        return matches


def get_class_members(klass):
    ret = dir(klass)

    if hasattr(klass, '__bases__'):
        for base in klass.__bases__:
            ret.extend(get_class_members(base))

    return ret
