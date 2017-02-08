import subprocess
import string
import random
import os

def screenshot():
	randname=''.join([random.choice(string.ascii_lowercase) for i in range(0,random.randint(6,12))])
	screenpath = '/tmp/{name}.png'.format(name=randname)

	path_to_bin = '/usr/sbin/screencapture'
	cmd = '{pathToBin} -x -C {screen_path}'.format(pathToBin=path_to_bin, screen_path=screenpath)

	if os.path.exists(path_to_bin):
		process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		# wait the end of the command
		process.communicate()
		if os.path.exists(screenpath):
			return True, screenpath
		else:
			return False, 'screenshot failed'
	else:
		return False, 'binary %s not found' % path_to_bin