import xml.etree.cElementTree as ET
import os, win32crypt
import binascii
import tempfile, socket
from ctypes import *

class Wifi():
	
	# used when launched with a system account 
	def run(self):
		# need to be admin privilege, to find passwords
		if not windll.Shell32.IsUserAnAdmin():
			return
		else:
			directory = ''
			if 'ALLUSERSPROFILE' in os.environ:
				directory = os.environ['ALLUSERSPROFILE'] + os.sep + 'Microsoft\Wlansvc\Profiles\Interfaces'
			# for windows Vista or higher
			if os.path.exists(directory):
				passwordFound = False
				rep = []
				pwdFound = []
				for repository in os.listdir(directory):
					if os.path.isdir(directory + os.sep + repository):
						
						rep = directory + os.sep + repository
						for file in os.listdir(rep):
							values = {}
							if os.path.isfile(rep + os.sep + file):
								f = rep + os.sep + file
								tree = ET.ElementTree(file=f)
								root = tree.getroot()
								xmlns =  root.tag.split("}")[0] + '}'
								
								iterate = False
								for elem in tree.iter():
									if elem.tag.endswith('SSID'):
										for w in elem:
											if w.tag == xmlns + 'name':
												values['SSID'] = w.text
									
									if elem.tag.endswith('authentication'):
										values['Authentication'] = elem.text
										
									if elem.tag.endswith('protected'):
										values['Protected'] = elem.text
									
									if elem.tag.endswith('keyMaterial'):
										key = elem.text
										try:
											binary_string = binascii.unhexlify(key)
											password = win32crypt.CryptUnprotectData(binary_string, None, None, None, 0)[1]
											values['Password'] = password
											values["Category"] = "Wifi"
											passwordFound = True
										except:
											values['INFO'] = '[!] Password not found.'
								
								# store credentials
								if len(values) != 0:
									pwdFound.append(values)	
				return pwdFound
				
			
		
	
	
	