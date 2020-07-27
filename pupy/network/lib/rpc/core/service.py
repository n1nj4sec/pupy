"""
Services are the heart of RPyC: each side of the connection exposes
a *service*, which define the capabilities available to the other side.

Note that the services by both parties need not be symmetric, e.g., one
side may exposed *service A*, while the other may expose *service B*.
As long as the two can interoperate, you're good to go.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

# Wrong conversions
# from __future__ import unicode_literals

from network.lib.compat import execute, is_py3k


class Service(object):
    """The service base-class. Derive from this class to implement custom RPyC
    services:

    * The name of the class implementing the ``Foo`` service should match the
      pattern ``FooService`` (suffixed by the word 'Service') ::

          class FooService(Service):
              pass

          FooService.get_service_name() # 'FOO'
          FooService.get_service_aliases() # ['FOO']

    * To supply a different name or aliases, use the ``ALIASES`` class attribute ::

          class Foobar(Service):
              ALIASES = ["foo", "bar", "lalaland"]

          Foobar.get_service_name() # 'FOO'
          Foobar.get_service_aliases() # ['FOO', 'BAR', 'LALALAND']

    * Override :func:`on_connect` to perform custom initialization

    * Override :func:`on_disconnect` to perform custom finalization

    * To add exposed methods or attributes, simply define them normally,
      but prefix their name by ``exposed_``, e.g. ::

          class FooService(Service):
              def exposed_add(self, x, y):
                  return x + y

    * All other names (not prefixed by ``exposed_``) are local (not accessible
      to the other party)

    .. note::
       You can override ``_rpyc_getattr``, ``_rpyc_setattr`` and ``_rpyc_delattr``
       to change attribute lookup -- but beware of possible **security implications!**
    """
    __slots__ = ["_conn"]
    ALIASES = ()

    def __init__(self, conn):
        self._conn = conn

    def on_connect(self):
        """called when the connection is established"""
        pass

    def on_disconnect(self):
        """called when the connection had already terminated for cleanup
        (must not perform any IO on the connection)"""
        pass

    # Using default defined in 'protocol.Connection._access_attr' for:
    # def _rpyc_getattr(self, name):

    def _rpyc_delattr(self, name):
        raise AttributeError("access denied")

    def _rpyc_setattr(self, name, value):
        raise AttributeError("access denied")

    @classmethod
    def get_service_aliases(cls):
        """returns a list of the aliases of this service"""
        if cls.ALIASES:
            return tuple(str(n).upper() for n in cls.ALIASES)
        name = cls.__name__.upper()
        if name.endswith("SERVICE"):
            name = name[:-7]
        return (name,)

    @classmethod
    def get_service_name(cls):
        """returns the canonical name of the service (which is its first
        alias)"""
        return cls.get_service_aliases()[0]

    exposed_get_service_aliases = get_service_aliases
    exposed_get_service_name = get_service_name


class ModuleNamespace(object):
    """used by the :class:`SlaveService` to implement the magical
    'module namespace'"""

    __slots__ = (
        "__getmodule", "__cache", "__weakref__"
    )

    def __init__(self, getmodule):
        self.__getmodule = getmodule
        self.__cache = {}

    def __contains__(self, name):
        try:
            self[name]
        except ImportError:
            return False
        else:
            return True

    def __getitem__(self, name):
        if isinstance(name, (tuple, list)):
            name = '.'.join(name)

        if name not in self.__cache:
            self.__cache[name] = self.__getmodule(name)

        return self.__cache[name]

    def __getattr__(self, name):
        return self[name]
