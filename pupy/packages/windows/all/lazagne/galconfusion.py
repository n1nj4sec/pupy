import os
from _winreg import HKEY_CURRENT_USER, OpenKey, QueryValueEx

class Galconfusion():
	
	def run(self):
		creds = []
		
		# Find the location of steam - to make it easier we're going to use a try block
		# 'cos I'm lazy
		try:
			with OpenKey(HKEY_CURRENT_USER, 'Software\Valve\Steam') as key:
				results=QueryValueEx(key, 'SteamPath')
		except:
			return
		
		if not results:
			return
			
		steampath=results[0]
		userdata = steampath + '\\userdata'
		
		# Check that we have a userdata directory
		if not os.path.exists(userdata):
			return
		
		# Now look for Galcon Fusion in every user
		files = os.listdir(userdata)
		
		for file in files:
			filepath = userdata + '\\' + file + '\\44200\\remote\\galcon.cfg'
			if not os.path.exists(filepath):
				continue
			
			# If we're here we should have a Galcon Fusion file
			with open(filepath, mode='rb') as cfgfile: 
				# We've found a config file, now extract the creds
				data = cfgfile.read()
				values = {}
				
				values['Login'] = data[4:0x23]
				values['Password'] = data[0x24:0x43]
				values['Category'] = 'Galconfusion'
				creds.append(values)
		
		return creds
					
				
