# import xml.etree.cElementTree as ET
import xml.etree.cElementTree as ET
import os

class Pidgin():

	def run(self):
		
		if 'APPDATA' in os.environ:
			directory = os.environ['APPDATA'] + '\.purple'
			path = os.path.join(directory, 'accounts.xml')
		else:
			return
		
		if os.path.exists(path):
			tree = ET.ElementTree(file=path)
			
			root = tree.getroot()
			accounts = root.getchildren()
			pwdFound = []
			for a in accounts:
				values = {}
				aa = a.getchildren()
				noPass = True

				for tag in aa:
					cpt = 0
					if tag.tag == 'name':
						cpt = 1
						values['Login'] = tag.text
					
					if tag.tag == 'password':
						values['Password'] = tag.text
						values['Category'] = 'Pidgin'
						noPass = False
					
				if noPass == False:
					pwdFound.append(values)

			return pwdFound
			
