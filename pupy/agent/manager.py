# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = ('Task', 'Manager')

from threading import Thread, Event

import pupy.agent
import sys

if sys.version_info.major > 2:
    basestring = str


class Task(Thread):

    __slots__ = (
        '_pstore', '_stopped', '_manager', '_dirty', '_event_id'
    )

    stopped = None
    results_type = list
    event_id = None

    def __init__(self, manager, *args, **kwargs):
        Thread.__init__(self)

        self._event_id = kwargs.pop('event_id', self.event_id)

        self.daemon = True
        self._pstore = manager.pstore
        self._stopped = Event()

        if not self._pstore[self]:
            self._pstore[self] = self.results_type()

        self._manager = manager
        self._dirty = False

        pupy.agent.dprint('Create task {}', self.__class__.__name__)

    @property
    def name(self):
        return type(self).__name__

    @property
    def results(self):
        results = self._pstore[self]
        self._pstore[self] = self.results_type()
        self._dirty = False

        if isinstance(results, list):
            results = tuple(results)

        return results

    @property
    def dirty(self):
        return self._dirty

    def append(self, result):
        if issubclass(self.results_type, basestring):
            self._pstore[self] += result
        elif self.results_type == list:
            self._pstore[self].append(result)
        elif self.results_type == set:
            self._pstore[self].add(result)
        elif self.results_type == dict:
            self._pstore[self][result[0]] = result[1]
        else:
            raise TypeError(
                'Unknown results type: {}'.format(self.results_type)
            )

        fire_event = False

        if not self._dirty:
            fire_event = True

        self._dirty = True

        try:
            if fire_event and self._event_id is not None:
                self.broadcast_event(self._event_id)
        except:
            pupy.agent.remote_error('Task (append) error: {}', self.name)

    def broadcast_event(self, eventid, *args, **kwargs):
        pupy.agent.broadcast_event(eventid, *args, **kwargs)

    def stop(self):
        pupy.agent.dprint('Stopping task {}', self.__class__.__name__)

        if self._stopped and self.active:
            self._stopped.set()

    def run(self):
        pupy.agent.dprint('Task {} started', self.__class__.__name__)

        try:
            self.task()
        except:
            pupy.agent.remote_error('Task (run) error: {}', self.name)
        finally:
            pupy.agent.dprint('Task {} completed', self.__class__.__name__)

            if self._stopped:
                self._stopped.set()

    @property
    def active(self):
        if self._stopped is None:
            return False

        try:
            return not self._stopped.is_set()

        except:
            pupy.agent.remote_error('Task (active) error: {}', self.name)
            return False

    def event(self, event):
        pass


class Manager(object):
    TERMINATE = 0
    PAUSE = 1
    SESSION = 2

    __slots__ = ('tasks', 'pstore')

    def __init__(self, pstore):
        self.tasks = {}
        self.pstore = pstore

    def get(self, klass):
        name = klass.__name__
        return self.tasks.get(name)

    def create(self, klass, *args, **kwargs):
        name = klass.__name__
        if name not in self.tasks:
            try:
                task = klass(self, *args, **kwargs)
                task.start()
                self.tasks[name] = task
                return task

            except:
                pupy.agent.remote_error('Manager (create): {}', name)

    def stop(self, klass, force=False):
        name = klass.__name__
        if name in self.tasks:
            try:
                self.tasks[name].stop()
                del self.tasks[name]
            except:
                pupy.agent.remote_error('Manager (stop): {}', name)
                if force:
                    del self.tasks[name]

    def active(self, klass):
        name = klass.__name__
        if name in self.tasks:
            if not self.tasks[name].stopped:
                # Failed somewhere in the middle
                del self.tasks[name]
                return False

            return self.tasks[name].stopped.is_set()
        else:
            return False

    @property
    def dirty(self):
        return any(x.dirty for x in self.tasks.values())

    @property
    def status(self):
        return {
            name:{
                'active': task.active,
                'results': task.dirty,
            } for name,task in self.tasks.items()
        }

    def event(self, event):
        for task in self.tasks.values():
            try:
                task.event(event)
            except:
                pupy.agent.remote_error('Manager (event): {} evt={}', task.name, event)

        if event == self.TERMINATE:
            for task in self.tasks.values():
                try:
                    task.stop()
                except:
                    pupy.agent.remote_error(
                        'Manager (terminate): {} evt={}', task.name, event)

            self.pstore.store()
