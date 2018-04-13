## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

## PATCHED

"""
Logging subsystem and basic exception class.
"""

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
