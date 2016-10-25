# SecretStorage module for Python
# Access passwords using the SecretService DBus API
# Author: Dmitry Shachnev, 2013
# License: BSD

"""Collection is a place where secret items are stored. Normally, only
the default collection should be used, but this module allows to use any
registered collection. Use :func:`get_default_collection` to get the
default collection (and create it, if necessary).

Collections are usually automatically unlocked when user logs in, but
collections can also be locked and unlocked using
:meth:`Collection.lock` and :meth:`Collection.unlock` methods (unlocking
requires showing the unlocking prompt to user and can be synchronous or
asynchronous). Creating new items and editing existing ones is possible
only in unlocked collection."""

import dbus
from secretstorage.defines import SS_PREFIX, SS_PATH
from secretstorage.exceptions import LockedException, ItemNotFoundException
from secretstorage.item import Item
from secretstorage.util import bus_get_object, InterfaceWrapper, \
 exec_prompt_glib, format_secret, open_session, to_unicode, unlock_objects

COLLECTION_IFACE = SS_PREFIX + 'Collection'
SERVICE_IFACE    = SS_PREFIX + 'Service'
DEFAULT_COLLECTION = '/org/freedesktop/secrets/aliases/default'
SESSION_COLLECTION = '/org/freedesktop/secrets/collection/session'

class Collection(object):
	"""Represents a collection."""

	def __init__(self, bus, collection_path=DEFAULT_COLLECTION, session=None):
		collection_obj = bus_get_object(bus, collection_path)
		self.bus = bus
		self.session = session
		self.collection_path = collection_path
		self.collection_iface = InterfaceWrapper(collection_obj,
			COLLECTION_IFACE)
		self.collection_props_iface = InterfaceWrapper(collection_obj,
			dbus.PROPERTIES_IFACE)
		self.collection_props_iface.Get(COLLECTION_IFACE, 'Label',
			signature='ss')

	def is_locked(self):
		"""Returns :const:`True` if item is locked, otherwise
		:const:`False`."""
		return bool(self.collection_props_iface.Get(
			COLLECTION_IFACE, 'Locked', signature='ss'))

	def ensure_not_locked(self):
		"""If collection is locked, raises
		:exc:`~secretstorage.exceptions.LockedException`."""
		if self.is_locked():
			raise LockedException('Collection is locked!')

	def unlock(self, callback=None):
		"""Requests unlocking the collection. If `callback` is specified,
		calls it when unlocking is complete (see
		:func:`~secretstorage.util.exec_prompt` description for details).
		Otherwise, uses loop from GLib API and returns a boolean
		representing whether the operation was dismissed."""
		return unlock_objects(self.bus, [self.collection_path], callback)

	def lock(self):
		"""Locks the collection."""
		service_obj = bus_get_object(self.bus, SS_PATH)
		service_iface = InterfaceWrapper(service_obj, SERVICE_IFACE)
		service_iface.Lock([self.collection_path], signature='ao')

	def delete(self):
		"""Deletes the collection and all items inside it."""
		self.ensure_not_locked()
		self.collection_iface.Delete(signature='')

	def get_all_items(self):
		"""Returns a generator of all items in the collection."""
		for item_path in self.collection_props_iface.Get(
		COLLECTION_IFACE, 'Items', signature='ss'):
			yield Item(self.bus, item_path, self.session)

	def search_items(self, attributes):
		"""Returns a generator of items with the given attributes.
		`attributes` should be a dictionary."""
		result = self.collection_iface.SearchItems(attributes,
			signature='a{ss}')
		for item_path in result:
			yield Item(self.bus, item_path, self.session)

	def get_label(self):
		"""Returns the collection label."""
		label = self.collection_props_iface.Get(COLLECTION_IFACE,
			'Label', signature='ss')
		return to_unicode(label)

	def set_label(self, label):
		"""Sets collection label to `label`."""
		self.ensure_not_locked()
		self.collection_props_iface.Set(COLLECTION_IFACE, 'Label',
			label, signature='ssv')

	def create_item(self, label, attributes, secret, replace=False,
	content_type='text/plain'):
		"""Creates a new :class:`~secretstorage.item.Item` with given
		`label` (unicode string), `attributes` (dictionary) and `secret`
		(bytestring). If `replace` is :const:`True`, replaces the existing
		item with the same attributes. If `content_type` is given, also
		sets the content type of the secret (``text/plain`` by default).
		Returns the created item."""
		self.ensure_not_locked()
		if not self.session:
			self.session = open_session(self.bus)
		secret = format_secret(self.session, secret, content_type)
		attributes = dbus.Dictionary(attributes, signature='ss')
		properties = {
			SS_PREFIX+'Item.Label': label,
			SS_PREFIX+'Item.Attributes': attributes
		}
		new_item, prompt = self.collection_iface.CreateItem(properties,
			secret, replace, signature='a{sv}(oayays)b')
		return Item(self.bus, new_item, self.session)

def create_collection(bus, label, alias='', session=None):
	"""Creates a new :class:`Collection` with the given `label` and `alias`
	and returns it. This action requires prompting. If prompt is dismissed,
	raises :exc:`~secretstorage.exceptions.ItemNotFoundException`. This is
	synchronous function, uses loop from GLib API."""
	if not session:
		session = open_session(bus)
	properties = {SS_PREFIX+'Collection.Label': label}
	service_obj = bus_get_object(bus, SS_PATH)
	service_iface = dbus.Interface(service_obj, SERVICE_IFACE)
	collection_path, prompt = service_iface.CreateCollection(properties,
		alias, signature='a{sv}s')
	if len(collection_path) > 1:
		return Collection(bus, collection_path, session=session)
	dismissed, unlocked = exec_prompt_glib(bus, prompt)
	if dismissed:
		raise ItemNotFoundException('Prompt dismissed.')
	return Collection(bus, unlocked, session=session)

def get_all_collections(bus):
	"""Returns a generator of all available collections."""
	service_obj = bus_get_object(bus, SS_PATH)
	service_props_iface = dbus.Interface(service_obj,
		dbus.PROPERTIES_IFACE)
	for collection_path in service_props_iface.Get(SERVICE_IFACE,
	'Collections', signature='ss'):
		yield Collection(bus, collection_path)

def get_default_collection(bus, session=None):
	"""Returns the default collection. If it doesn't exist,
	creates it."""
	try:
		return Collection(bus)
	except ItemNotFoundException:
		return create_collection(bus, 'Default',
		'default', session)

def get_any_collection(bus):
	"""Returns any collection, in the following order of preference:

	- The default collection;
	- The "session" collection (usually temporary);
	- The first collection in the collections list."""
	try:
		return Collection(bus)
	except ItemNotFoundException:
		pass
	try:
		# GNOME Keyring provides session collection where items
		# are stored in process memory.
		return Collection(bus, SESSION_COLLECTION)
	except ItemNotFoundException:
		pass
	collections = list(get_all_collections(bus))
	if collections:
		return collections[0]
	else:
		raise ItemNotFoundException('No collections found.')

def get_collection_by_alias(bus, alias):
	"""Returns the collection with the given `alias`. If there is no
	such collection, raises
	:exc:`~secretstorage.exceptions.ItemNotFoundException`."""
	service_obj = bus_get_object(bus, SS_PATH)
	service_iface = dbus.Interface(service_obj, SERVICE_IFACE)
	collection_path = service_iface.ReadAlias(alias, signature='s')
	if len(collection_path) <= 1:
		raise ItemNotFoundException('No collection with such alias.')
	return Collection(bus, collection_path)

def search_items(bus, attributes):
	"""Returns a generator of items in all collections with the given
	attributes. `attributes` should be a dictionary."""
	service_obj = bus_get_object(bus, SS_PATH)
	service_iface = dbus.Interface(service_obj, SERVICE_IFACE)
	locked, unlocked = service_iface.SearchItems(attributes,
		signature='a{ss}')
	for item_path in locked + unlocked:
		yield Item(bus, item_path)
