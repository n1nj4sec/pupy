import xml.etree.cElementTree as ET
import win32con, win32api
import os

class Puttycm():
		
	def run(self):
		try:
			database_path = self.get_default_database()
		except Exception,e:
			return
		
		if os.path.exists(database_path):
			self.parse_xml(database_path)

	def get_default_database(self):
		accessRead = win32con.KEY_READ | win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE
		key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, 'Software\\ACS\\PuTTY Connection Manager', 0, accessRead)
		thisName = str(win32api.RegQueryValueEx(key, 'DefaultDatabase')[0])
		if thisName :
			return thisName
		else:
			return ' '
	
	def parse_xml(self, database_path):
		xml_file = os.path.expanduser(database_path)
		tree = ET.ElementTree(file=xml_file)
		root = tree.getroot()
		
		pwdFound = []
		for connection in root.iter('connection'):
			children = connection.getchildren()
			values = {}
			for child in children:
				for c in child:
					find = False
					
					if str(c.tag) == 'name':
						find = True
					if str(c.tag) == 'protocol':
						find = True
					elif str(c.tag) == 'host':
						find = True
					elif str(c.tag) == 'port':
						find = True
					elif str(c.tag) == 'description':
						find = True
					elif str(c.tag) == 'login':
						find = True
					elif str(c.tag) == 'password':
						find = True
					
					if find:
						values["Category"] = "PuttyCM"
						values[str(c.tag)] = str(c.text)
			
			# password found 
			if len(values) != 0:
				pwdFound.append(values)
		
		return pwdFound
		