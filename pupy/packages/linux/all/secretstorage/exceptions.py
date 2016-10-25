# SecretStorage module for Python
# Access passwords using the SecretService DBus API
# Author: Dmitry Shachnev, 2012
# License: BSD

"""All secretstorage functions may raise various exceptions when
something goes wrong. All exceptions derive from base
:exc:`SecretStorageException` class."""

class SecretStorageException(Exception):
	"""All exceptions derive from this class."""

class SecretServiceNotAvailableException(SecretStorageException):
	"""Raised by :class:`~secretstorage.item.Item` or
	:class:`~secretstorage.collection.Collection` constructors, or by
	other functions in the :mod:`secretstorage.collection` module, when
	the Secret Service API is not available."""

class LockedException(SecretStorageException):
	"""Raised when an action cannot be performed because the collection
	is locked. Use :meth:`~secretstorage.collection.Collection.is_locked`
	to check if the collection is locked, and
	:meth:`~secretstorage.collection.Collection.unlock` to unlock it.
	"""

class ItemNotFoundException(SecretStorageException):
	"""Raised when an item does not exist or has been deleted. Example of
	handling:

	>>> import secretstorage
	>>> bus = secretstorage.dbus_init()
	>>> item_path = '/not/existing/path'
	>>> try:
	...     item = secretstorage.Item(bus, item_path)
	... except secretstorage.ItemNotFoundException:
	...     print('Item not found!')
	... 
	Item not found!

	Also, :func:`~secretstorage.collection.create_collection` may raise
	this exception when a prompt was dismissed during creating the
	collection.
	"""
