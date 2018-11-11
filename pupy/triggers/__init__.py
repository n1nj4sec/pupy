# -*- coding: utf-8 -*-

__all__ = ('Triggers')

import os
import imp

class Triggers(object):
    SUFFIXES = tuple([
        suffix for suffix, _, rtype in imp.get_suffixes() \
        if rtype == imp.PY_SOURCE
    ])

    def __init__(self):
        self._triggers = {}
        self._triggers_stats = {}
        self._folders_stats = {}
        self._refresh()

    def _refresh(self):
        triggers_paths = [
            os.path.dirname(__file__), 'triggers'
        ]

        triggers = {}
        dups = set()

        for path in triggers_paths:
            path = os.path.abspath(path)
            if path in dups:
                continue

            dups.add(path)

            try:
                path_st_mtime = os.stat(path).st_mtime
            except OSError:
                continue

            if self._folders_stats.get(path, None) == path_st_mtime:
                continue

            self._folders_stats[path] = path_st_mtime

            triggers.update({
                '.'.join(x.rsplit('.', 1)[:-1]):os.path.join(path, x) \
                for x in os.listdir(path) if x.endswith(self.SUFFIXES) and \
                not x.startswith('__init__')
            })

        for trigger, source in triggers.iteritems():
            try:
                current_stat = os.stat(source)
            except OSError:
                continue

            if trigger not in self._triggers or self._triggers_stats[trigger] != current_stat.st_mtime:
                try:
                    self._triggers[trigger] = imp.load_source(trigger, source)
                    self._triggers_stats[trigger] = current_stat.st_mtime
                except IOError:
                    pass

    def execute(self, trigger_name, event_name, client, server, handler, config, **kwargs):
        self._refresh()
        trigger = self._triggers.get(trigger_name, None)
        if trigger_name is None:
            return

        trigger.execute(event_name, client, server, handler, config, **kwargs)
