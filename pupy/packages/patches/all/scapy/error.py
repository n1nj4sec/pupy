## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

## PATCHED

"""
Logging subsystem and basic exception class.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

#############################
##### Logging subsystem #####
#############################

class Scapy_Exception(Exception):
    pass

import logging
from logging import NullHandler

log_scapy = logging.getLogger("scapy")
log_scapy.addHandler(NullHandler())

log_runtime = logging.getLogger("scapy.runtime")          # logs at runtime
log_runtime.addFilter(NullHandler())

log_interactive = logging.getLogger("scapy.interactive")  # logs in interactive functions
log_loading = logging.getLogger("scapy.loading")          # logs when loading Scapy

def warning(*args, **kwargs):
    # Do nothing
    pass
