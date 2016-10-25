# SecretStorage module for Python
# Access passwords using the SecretService DBus API
# Author: Dmitry Shachnev, 2013
# License: BSD

"""This file provides quick access to all SecretStorage API. Please
refer to documentation of individual modules for API details.

It also provides some functions for compatibility with older
SecretStorage releases. Those functions are not recommended for use
in new software."""

import dbus
from secretstorage.util import int_from_bytes, int_to_bytes
from secretstorage.collection import Collection, create_collection, \
 get_all_collections, get_default_collection, get_any_collection, \
 get_collection_by_alias, search_items
from secretstorage.item import Item
from secretstorage.defines import DBUS_NOT_SUPPORTED, DBUS_EXEC_FAILED, \
 DBUS_NO_REPLY, DBUS_ACCESS_DENIED
from secretstorage.exceptions import SecretStorageException, \
 SecretServiceNotAvailableException, LockedException, \
 ItemNotFoundException

__version_tuple__ = (2, 3, 1)
__version__ = '.'.join(map(str, __version_tuple__))

def dbus_init(main_loop=True, use_qt_loop=False):
	"""Returns new SessionBus_. If `main_loop` is :const:`True` and no
	D-Bus main loop is registered yet, registers a default main loop
	(PyQt5 main loop if `use_qt_loop` is :const:`True`, otherwise GLib
	main loop).

	.. _SessionBus: https://www.freedesktop.org/wiki/IntroductionToDBus/#buses

	.. note::
	   Qt uses GLib main loops on UNIX-like systems by default, so one
	   will rarely need to set `use_qt_loop` to :const:`True`.
	"""
	if main_loop and not dbus.get_default_main_loop():
		if use_qt_loop:
			from dbus.mainloop.pyqt5 import DBusQtMainLoop
			DBusQtMainLoop(set_as_default=True)
		else:
			from dbus.mainloop.glib import DBusGMainLoop
			DBusGMainLoop(set_as_default=True)
	try:
		return dbus.SessionBus()
	except dbus.exceptions.DBusException as e:
		if e.get_dbus_name() in (DBUS_NOT_SUPPORTED,
		DBUS_EXEC_FAILED, DBUS_NO_REPLY, DBUS_ACCESS_DENIED):
			raise SecretServiceNotAvailableException(
				e.get_dbus_message())
		raise
