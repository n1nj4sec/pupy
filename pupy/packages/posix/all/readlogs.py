# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
__all__ = [
  'get_last_events'
]

import os

from readlogs_generic import GenericLogReader

def get_last_events(count=10, includes=[], excludes=[], eventid=None):
    events = {}
    for d in ['/var/log', '/var/adm']:
        if os.path.isdir(d):
            events.update(
                GenericLogReader(d).get_last_events(count, includes, excludes))

    return events
