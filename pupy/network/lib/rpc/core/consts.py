"""
Constants used by the protocol
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

# messages
MSG_REQUEST      = 1
MSG_REPLY        = 2
MSG_EXCEPTION    = 3

# boxing
LABEL_VALUE      = 1
LABEL_TUPLE      = 2
LABEL_LOCAL_REF  = 3
LABEL_REMOTE_REF = 4

LABEL_V1_SET     = 5
LABEL_V1_DICT    = 6
LABEL_V1_NAMED_TUPLE = 7
LABEL_V1_LIST    = 8

# action handlers
HANDLE_PING        = 1
HANDLE_CLOSE       = 2
HANDLE_GETROOT     = 3
HANDLE_GETATTR     = 4
HANDLE_DELATTR     = 5
HANDLE_SETATTR     = 6
HANDLE_CALL        = 7
HANDLE_CALLATTR    = 8
HANDLE_REPR        = 9
HANDLE_STR         = 10
HANDLE_CMP         = 11
HANDLE_HASH        = 12
HANDLE_DIR         = 13
HANDLE_PICKLE      = 14
HANDLE_DEL         = 15
HANDLE_INSPECT     = 16
HANDLE_BUFFITER    = 17
HANDLE_OLDSLICING  = 18
HANDLE_MAX         = 19

# optimized exceptions
EXC_STOP_ITERATION = 1
