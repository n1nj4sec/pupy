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
from framework.win32.hashdump import dump_file_hashes

if len(sys.argv) < 3:
    print "usage: %s <system hive> <SAM hive>" % sys.argv[0]
    sys.exit(1)

dump_file_hashes(sys.argv[1], sys.argv[2])
