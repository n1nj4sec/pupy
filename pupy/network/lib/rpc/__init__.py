"""
::

         #####    #####             ####
        ##   ##  ##   ##           ##             ####
        ##  ##   ##  ##           ##                 #
        #####    #####   ##   ##  ##               ##
        ##  ##   ##       ## ##   ##                 #
        ##   ##  ##        ###    ##              ###
        ##   ##  ##        ##      #####
     -------------------- ## ------------------------------------------
                         ##

Remote Python Call (RPyC)
Licensed under the MIT license (see `LICENSE` file)

A transparent, symmetric and light-weight RPC and distributed computing
library for python.

Usage::

    >>> import rpyc
    >>> c = network.lib.rpc.connect_by_service("SERVICENAME")
    >>> print c.root.some_function(1, 2, 3)

Classic-style usage::

    >>> import rpyc
    >>> # `hostname` is assumed to be running a slave-service server
    >>> c = network.lib.rpc.classic.connect("hostname")
    >>> print c.execute("x = 5")
    None
    >>> print c.eval("x + 2")
    7
    >>> print c.modules.os.listdir(".")       #doctest: +ELLIPSIS
    [...]
    >>> print c.modules["xml.dom.minidom"].parseString("<a/>")   #doctest: +ELLIPSIS
    <xml.dom.minidom.Document instance at ...>
    >>> f = c.builtin.open("foobar.txt", "rb")     #doctest: +SKIP
    >>> print f.read(100)     #doctest: +SKIP
    ...

"""
from network.lib.rpc.core import (Channel,
    Connection, Service, BaseNetref, AsyncResult, GenericException,
    AsyncResultTimeout, VoidService, SlaveService)
from network.lib.rpc.utils.helpers import nowait, timed, buffiter, BgServingThread, restricted
from network.lib.rpc.utils import classic
from network.lib.rpc.version import version as __version__

__author__ = "Tomer Filiba (tomerfiliba@gmail.com)"

