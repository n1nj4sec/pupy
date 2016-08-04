import sqlite3
import win32crypt
import sys, os, platform, base64
import xml.etree.cElementTree as ET

class Cyberduck():

	# find the user.config file containing passwords
	def get_path(self):
		if 'APPDATA' in os.environ:
			directory = os.environ['APPDATA'] + '\Cyberduck'
			
			if os.path.exists(directory):
				for dir in os.listdir(directory):
					if dir.startswith('Cyberduck'):
						for d in os.listdir(directory + os.sep + dir):
							path = directory + os.sep + dir + os.sep + d + os.sep + 'user.config'
							if os.path.exists(path):
								return path
				
				return 'User_profil_not_found'
			else:
				return 'CYBERDUCK_NOT_EXISTS'
		else:
			return 'APPDATA_NOT_FOUND'
			
	# parse the xml file
	def parse_xml(self, xml_file):
		tree = ET.ElementTree(file=xml_file)
		
		pwdFound = []
		for elem in tree.iter():
			values = {}
			try:
				if elem.attrib['name'].startswith('ftp') or elem.attrib['name'].startswith('ftps') or elem.attrib['name'].startswith('sftp') or elem.attrib['name'].startswith('http') or elem.attrib['name'].startswith('https'):
					values['URL'] = elem.attrib['name']
					encrypted_password = base64.b64decode(elem.attrib['value'])
					password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
					values['Password'] = password
					values['Category'] = "Cyberduck"
					pwdFound.append(values)
			except Exception,e:
				pass
		return pwdFound
		
	# main function
	def run(self):
		path = self.get_path()
		if path == 'CYBERDUCK_NOT_EXISTS' or path == 'User_profil_not_found' or path == 'APPDATA_NOT_FOUND':
			return
		else:
			self.parse_xml(path)
			