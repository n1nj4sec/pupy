# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import ctypes

__class_name__="Drives"

@config(compat="windows", category="admin")
class Drives(PupyModule):
    """ List valid drives in the system """
   	
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="drives", description=self.__doc__)

    def run(self, args):
		blen = self.client.conn.modules['ctypes'].c_uint(128)
		rv = self.client.conn.modules['ctypes'].c_uint()
		bufs = self.client.conn.modules['ctypes'].create_string_buffer(128)
		rv = self.client.conn.modules['ctypes'].windll.kernel32.GetLogicalDriveStringsA(blen, bufs)
		if rv == 0:
		    self.log('Error retrieving logical drives')
		drives = bufs.raw.split('\0')
		for drive in drives:
			if drive:
				self.log('- %s' % drive)
			else:
				break
