# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
def execute(event_name, client, server, handler, config, **kwargs):
    server.info(
        'Event: {}, client={}, server={}, handler={}, config={}, kwargs={}'.format(
            event_name, client, server, handler, config, kwargs))
