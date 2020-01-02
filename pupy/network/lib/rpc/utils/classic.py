from __future__ import with_statement
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys
import os
import inspect

from io import open

from network.lib.compat import pickle, execute, is_py3k
from network.lib.rpc.core.service import ModuleNamespace
from contextlib import contextmanager

#===============================================================================
# remoting utilities
#===============================================================================


def upload(conn, localpath, remotepath, filter = None, ignore_invalid = False, chunk_size = 16000):
    """uploads a file or a directory to the given remote path

    :param localpath: the local file or directory
    :param remotepath: the remote path
    :param filter: a predicate that accepts the filename and determines whether
                   it should be uploaded; None means any file
    :param chunk_size: the IO chunk size
    """
    if os.path.isdir(localpath):
        upload_dir(conn, localpath, remotepath, filter, chunk_size)
    elif os.path.isfile(localpath):
        upload_file(conn, localpath, remotepath, chunk_size)
    else:
        if not ignore_invalid:
            raise ValueError("cannot upload %r" % (localpath,))


def upload_file(conn, localpath, remotepath, chunk_size = 16000):
    lf = open(localpath, "rb")
    rf = conn.builtin.open(remotepath, "wb")
    while True:
        buf = lf.read(chunk_size)
        if not buf:
            break
        rf.write(buf)
    lf.close()
    rf.close()


def upload_dir(conn, localpath, remotepath, filter = None, chunk_size = 16000):
    if not conn.modules.os.path.isdir(remotepath):
        conn.modules.os.makedirs(remotepath)
    for fn in os.listdir(localpath):
        if not filter or filter(fn):
            lfn = os.path.join(localpath, fn)
            rfn = conn.modules.os.path.join(remotepath, fn)
            upload(conn, lfn, rfn, filter = filter, ignore_invalid = True, chunk_size = chunk_size)


def download(conn, remotepath, localpath, filter = None, ignore_invalid = False, chunk_size = 16000):
    """
    download a file or a directory to the given remote path

    :param localpath: the local file or directory
    :param remotepath: the remote path
    :param filter: a predicate that accepts the filename and determines whether
                   it should be downloaded; None means any file
    :param chunk_size: the IO chunk size
    """
    if conn.modules.os.path.isdir(remotepath):
        download_dir(conn, remotepath, localpath, filter)
    elif conn.modules.os.path.isfile(remotepath):
        download_file(conn, remotepath, localpath, chunk_size)
    else:
        if not ignore_invalid:
            raise ValueError("cannot download %r" % (remotepath,))


def download_file(conn, remotepath, localpath, chunk_size = 16000):
    rf = conn.builtin.open(remotepath, "rb")
    lf = open(localpath, "wb")
    while True:
        buf = rf.read(chunk_size)
        if not buf:
            break
        lf.write(buf)
    lf.close()
    rf.close()


def download_dir(conn, remotepath, localpath, filter = None, chunk_size = 16000):
    if not os.path.isdir(localpath):
        os.makedirs(localpath)
    for fn in conn.modules.os.listdir(remotepath):
        if not filter or filter(fn):
            rfn = conn.modules.os.path.join(remotepath, fn)
            lfn = os.path.join(localpath, fn)
            download(conn, rfn, lfn, filter = filter, ignore_invalid = True)


def upload_package(conn, module, remotepath = None, chunk_size = 16000):
    """
    uploads a module or a package to the remote party

    :param conn: the RPyC connection to use
    :param module: the local module/package object to upload
    :param remotepath: the remote path (if ``None``, will default to the
                       remote system's python library (as reported by
                       ``distutils``)
    :param chunk_size: the IO chunk size

    .. note:: ``upload_module`` is just an alias to ``upload_package``

    example::

       import foo.bar
       ...
       network.lib.rpc.classic.upload_package(conn, foo.bar)

    """
    if remotepath is None:
        site = conn.modules["distutils.sysconfig"].get_python_lib()
        remotepath = conn.modules.os.path.join(site, module.__name__)
    localpath = os.path.dirname(os.path.abspath(inspect.getsourcefile(module)))
    upload(conn, localpath, remotepath, chunk_size = chunk_size)

upload_module = upload_package


def obtain(proxy):
    """obtains (copies) a remote object from a proxy object. the object is
    ``pickled`` on the remote side and ``unpickled`` locally, thus moved
    **by value**. changes made to the local object will not reflect remotely.

    :param proxy: an RPyC proxy object

    .. note:: the remote object to must be ``pickle``-able

    :returns: a copy of the remote object
    """
    return pickle.loads(pickle.dumps(proxy))


def deliver(conn, localobj):
    """delivers (recreates) a local object on the other party. the object is
    ``pickled`` locally and ``unpickled`` on the remote side, thus moved
    **by value**. changes made to the remote object will not reflect locally.

    :param conn: the RPyC connection
    :param localobj: the local object to deliver

    .. note:: the object must be ``picklable``

    :returns: a proxy to the remote object
    """
    return conn.modules["network.lib.compat"].pickle.loads(pickle.dumps(localobj))


@contextmanager
def redirected_stdio(conn):
    r"""
    Redirects the other party's ``stdin``, ``stdout`` and ``stderr`` to
    those of the local party, so remote IO will occur locally.

    Example usage::

        with redirected_stdio(conn):
            conn.modules.sys.stdout.write("hello\n")   # will be printed locally

    """
    orig_stdin = conn.modules.sys.stdin
    orig_stdout = conn.modules.sys.stdout
    orig_stderr = conn.modules.sys.stderr
    try:
        conn.modules.sys.stdin = sys.stdin
        conn.modules.sys.stdout = sys.stdout
        conn.modules.sys.stderr = sys.stderr
        yield
    finally:
        conn.modules.sys.stdin = orig_stdin
        conn.modules.sys.stdout = orig_stdout
        conn.modules.sys.stderr = orig_stderr


def pm(conn):
    """same as ``pdb.pm()`` but on a remote exception

    :param conn: the RPyC connection
    """
    #pdb.post_mortem(conn.root.getconn()._last_traceback)
    with redirected_stdio(conn):
        conn.modules.pdb.post_mortem(conn.root.getconn()._last_traceback)


def interact(conn, namespace = None):
    """remote interactive interpreter

    :param conn: the RPyC connection
    :param namespace: the namespace to use (a ``dict``)
    """
    if namespace is None:
        namespace = {}
    namespace["conn"] = conn
    with redirected_stdio(conn):
        conn.execute("""def _rinteract(ns):
            import code
            code.interact(local = dict(ns))""")
        conn.namespace["_rinteract"](namespace)


class MockClassicConnection(object):
    """Mock classic RPyC connection object. Useful when you want the same code to run remotely or locally.

    """
    def __init__(self):
        self._conn = None
        self.namespace = {}
        self.modules = ModuleNamespace(self.getmodule)

        if is_py3k:
            self.builtin = self.modules.builtins
        else:
            self.builtin = self.modules.__builtin__

        self.builtins = self.builtin

    def execute(self, text):
        execute(text, self.namespace)

    def eval(self, text):
        return eval(text, self.namespace)

    def getmodule(self, name):
        return __import__(name, None, None, "*")

    def getconn(self):
        return None

def teleport_function(conn, func):
    """
    "Teleports" a function (including nested functions/closures) over the RPyC connection.
    The function is passed in bytecode form and reconstructed on the other side.

    The function cannot have non-brinable defaults (e.g., ``def f(x, y=[8]):``,
    since a ``list`` isn't brinable), or make use of non-builtin globals (like modules).
    You can overcome the second restriction by moving the necessary imports into the
    function body, e.g. ::

        def f(x, y):
            import os
            return (os.getpid() + y) * x

    :param conn: the RPyC connection
    :param func: the function object to be delivered to the other party
    """
    from network.lib.rpc.utils.teleportation import export_function
    exported = export_function(func)
    return conn.modules["network.lib.rpc.utils.teleportation"].import_function(exported)
