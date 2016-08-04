import xml.etree.cElementTree as ET
import os

class Squirrel():
	
	def get_path(self):
		path = ''
		if 'HOMEPATH' in os.environ:
			path = os.environ['HOMEPATH'] + os.sep + '.squirrel-sql'
		else:
			return 'var_Env_Not_Found'
		
		if os.path.exists(path):
			return path
		else:
			return 'Not_Found'
		
	
	def parse_xml(self, xml_file):
		tree = ET.ElementTree(file=xml_file)
		pwdFound = []
		for elem in tree.iter('Bean'):
			values = {}
			for e in elem:
				if e.tag == 'name':
					values['name'] = e.text
				
				elif e.tag == 'url':
					values['url'] = e.text
				
				elif e.tag == 'userName':
					values['userName'] = e.text
				
				elif e.tag == 'password':
					values['password'] = e.text
					values['Category'] = "squirrel"
			
			if len(values):
				pwdFound.append(values)
			
		return pwdFound
		
	# Main function
	def run(self):
		
		path = self.get_path()
		if path == 'Not_Found' or path == 'var_Env_Not_Found':
			return
		else:
			path += os.sep + 'SQLAliases23.xml'
			if os.path.exists(path):
				return self.parse_xml(path)
			