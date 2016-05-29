#!/usr/bin/env python

# This file is part of creddump.
#
# creddump is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# creddump is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with creddump.  If not, see <http://www.gnu.org/licenses/>.

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu
"""


import sys
from framework.win32.domcachedump import dump_file_hashes
def showUsage():
    print "usage: %s <system hive> <security hive> <Vista/7>" % sys.argv[0]
    print "\nExample (Windows Vista/7):"
    print "%s /path/to/System32/config/SYSTEM /path/to/System32/config/SECURITY true" % sys.argv[0]
    print "\nExample (Windows XP):"
    print "%s /path/to/System32/SYSTEM /path/to/System32/config/SECURITY false" % sys.argv[0]

if len(sys.argv) < 4:
    showUsage()
    sys.exit(1)

if sys.argv[3] not in ["true", "false"]:
    showUsage()
    sys.exit(1)

vista = True if sys.argv[3] == "true" else False

dump_file_hashes(sys.argv[1], sys.argv[2], sys.argv[3])
