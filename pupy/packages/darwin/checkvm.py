import subprocess
import os

def checkvm():
	# check existing dir
	dirs = [
		'~/Library/Logs/VMWare',
		'~/Library/Logs/VMWare Fusion/'
	]

	for d in dirs:
		if os.path.isdir(os.path.expanduser(d)):
			return 'VMWare'

	p = subprocess.Popen('system_profiler', stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
	output, err = p.communicate()
	if output:
		if 'VMWare' in output:
			return 'VMWare'
		elif 'VirtualBox' in output:
			return 'VirtualBox'

	return None