# SecretStorage module for Python
# Access passwords using the SecretService DBus API
# Author: Dmitry Shachnev, 2013
# License: BSD

"""SecretStorage item contains a *secret*, some *attributes* and a
*label* visible to user. Editing all these properties and reading the
secret is possible only when the :doc:`collection <collection>` storing
the item is unlocked. The collection can be unlocked using collection's
:meth:`~secretstorage.collection.Collection.unlock` method."""

import dbus
from secretstorage.defines import SS_PREFIX
from secretstorage.exceptions import LockedException
from secretstorage.util import InterfaceWrapper, bus_get_object, \
 open_session, format_secret, to_unicode, unlock_objects
from Crypto import Cipher

ITEM_IFACE = SS_PREFIX + 'Item'

class Item(object):
	"""Represents a secret item."""

	def __init__(self, bus, item_path, session=None):
		self.item_path = item_path
		item_obj = bus_get_object(bus, item_path)
		self.session = session
		self.bus = bus
		self.item_iface = InterfaceWrapper(item_obj, ITEM_IFACE)
		self.item_props_iface = InterfaceWrapper(item_obj,
			dbus.PROPERTIES_IFACE)
		self.item_props_iface.Get(ITEM_IFACE, 'Label', signature='ss')

	def __eq__(self, other):
		return self.item_path == other.item_path

	def is_locked(self):
		"""Returns :const:`True` if item is locked, otherwise
		:const:`False`."""
		return bool(self.item_props_iface.Get(ITEM_IFACE, 'Locked',
			signature='ss'))

	def ensure_not_locked(self):
		"""If collection is locked, raises
		:exc:`~secretstorage.exceptions.LockedException`."""
		if self.is_locked():
			raise LockedException('Item is locked!')

	def unlock(self, callback=None):
		"""Requests unlocking the item. Usually, this will mean that the
		whole collection containing this item will be unlocked.

		If `callback` is specified, calls it when unlocking is complete
		(see :func:`~secretstorage.util.exec_prompt` description for
		details). Otherwise, uses the loop from GLib API and returns a
		boolean representing whether the operation was dismissed.

		.. versionadded:: 2.1.2"""
		return unlock_objects(self.bus, [self.item_path], callback)

	def get_attributes(self):
		"""Returns item attributes (dictionary)."""
		attrs = self.item_props_iface.Get(ITEM_IFACE, 'Attributes',
			signature='ss')
		return {to_unicode(key): to_unicode(value)
			for key, value in attrs.items()}

	def set_attributes(self, attributes):
		"""Sets item attributes to `attributes` (dictionary)."""
		self.item_props_iface.Set(ITEM_IFACE, 'Attributes', attributes,
			signature='ssv')

	def get_label(self):
		"""Returns item label (unicode string)."""
		label = self.item_props_iface.Get(ITEM_IFACE, 'Label',
			signature='ss')
		return to_unicode(label)

	def set_label(self, label):
		"""Sets item label to `label`."""
		self.ensure_not_locked()
		self.item_props_iface.Set(ITEM_IFACE, 'Label', label,
			signature='ssv')

	def delete(self):
		"""Deletes the item."""
		self.ensure_not_locked()
		return self.item_iface.Delete(signature='')

	def get_secret(self):
		"""Returns item secret (bytestring)."""
		self.ensure_not_locked()
		if not self.session:
			self.session = open_session(self.bus)
		secret = self.item_iface.GetSecret(self.session.object_path,
			signature='o')
		if not self.session.encrypted:
			return bytes(bytearray(secret[2]))
		aes_iv = bytes(bytearray(secret[1]))
		aes = Cipher.AES.new(self.session.aes_key, Cipher.AES.MODE_CBC, aes_iv)
		encrypted_secret = bytes(bytearray(secret[2]))
		padded_secret = aes.decrypt(encrypted_secret)
		padded_secret = bytearray(padded_secret)
		return bytes(padded_secret[:-padded_secret[-1]])

	def get_secret_content_type(self):
		"""Returns content type of item secret (string)."""
		self.ensure_not_locked()
		if not self.session:
			self.session = open_session(self.bus)
		secret = self.item_iface.GetSecret(self.session.object_path,
			signature='o')
		return str(secret[3])

	def set_secret(self, secret, content_type='text/plain'):
		"""Sets item secret to `secret`. If `content_type` is given,
		also sets the content type of the secret (``text/plain`` by
		default)."""
		self.ensure_not_locked()
		if not self.session:
			self.session = open_session(self.bus)
		secret = format_secret(self.session, secret, content_type)
		self.item_iface.SetSecret(secret, signature='(oayays)')

	def get_created(self):
		"""Returns UNIX timestamp (integer) representing the time
		when the item was created.

		.. versionadded:: 1.1"""
		return int(self.item_props_iface.Get(ITEM_IFACE, 'Created',
			signature='ss'))

	def get_modified(self):
		"""Returns UNIX timestamp (integer) representing the time
		when the item was last modified."""
		return int(self.item_props_iface.Get(ITEM_IFACE, 'Modified',
			signature='ss'))

	def to_tuple(self):
		"""Returns (*attributes*, *secret*) tuple representing the
		item."""
		self.ensure_not_locked()
		return self.get_attributes(), self.get_secret()
