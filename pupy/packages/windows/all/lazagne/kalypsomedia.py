import os, re, base64
import ConfigParser

class Kalypsomedia():
	# xorstring(s, k)
	# xors the two strings
	def xorstring(self, s, k):
		return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s,k))
		
	def run(self):
		creds = []
		key = 'lwSDFSG34WE8znDSmvtwGSDF438nvtzVnt4IUv89'
		
		if 'APPDATA' in os.environ:
			inifile = os.environ['APPDATA'] + '\\Kalypso Media\\Launcher\\launcher.ini'
		else:
			return
		
		# The actual user details are stored in *.userdata files
		if not os.path.exists(inifile):
			return
		
		config = ConfigParser.ConfigParser()
		config.read(inifile)
		values = {}
		
		values['Login'] = config.get('styx user','login')
		
		# get the encoded password
		cookedpw = base64.b64decode(config.get('styx user','password'));
		values['Password'] = self.xorstring(cookedpw, key)
		values['Category'] = 'KalypsoMedia'

		creds.append(values)
		
		return creds

					
				
