"""
A library of various helpers functions and classes
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys
import logging
import inspect


class MissingModule(object):
    __slots__ = ["__name"]

    def __init__(self, name):
        self.__name = name

    def __getattr__(self, name):
        if name.startswith("__"): # issue 71
            raise AttributeError("module %r not found" % (self.__name,))
        raise ImportError("module %r not found" % (self.__name,))

    def __bool__(self):
        return False

    __nonzero__ = __bool__


def safe_import(name):
    try:
        mod = __import__(name, None, None, "*")
    except ImportError:
        mod = MissingModule(name)
    except Exception:
        # issue 72: IronPython on Mono
        if sys.platform == "cli" and name == "signal": #os.name == "posix":
            mod = MissingModule(name)
        else:
            raise

    return mod


def setup_logger(quiet = False, logfile = None):
    opts = {}
    if quiet:
        opts['level'] = logging.ERROR
    else:
        opts['level'] = logging.DEBUG
    if logfile:
        opts['filename'] = logfile
    logging.basicConfig(**opts)


def get_methods(obj_attrs, obj):
    """introspects the given (local) object, returning a list of all of its
    methods (going up the MRO).

    :param obj: any local (not proxy) python object

    :returns: a list of ``(method name, docstring)`` tuples of all the methods
              of the given object
    """
    methods = {}
    attrs = {}

    if isinstance(obj, type):
        # don't forget the darn metaclass
        mros = list(reversed(type(obj).__mro__)) + list(reversed(obj.__mro__))
    else:
        mros = reversed(type(obj).__mro__)
    for basecls in mros:
        attrs.update(basecls.__dict__)

    for name, attr in attrs.items():
        if name not in obj_attrs and hasattr(attr, "__call__"):
            methods[name] = inspect.getdoc(attr)

    return methods.items()
