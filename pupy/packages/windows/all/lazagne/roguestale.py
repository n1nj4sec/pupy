import xml.etree.cElementTree as ET
import os, re

class Roguestale():
	
	def run(self):
		creds = []
		
		if 'USERPROFILE' in os.environ:
			directory = os.environ['USERPROFILE'] + '\\Documents\\Rogue\'s Tale\\users'
		else:
			return
		
		# The actual user details are stored in *.userdata files
		if not os.path.exists(directory):
			return
		
		files = os.listdir(directory)
		
		for file in files:
			if re.match('.*\.userdata',file):
				# We've found a user file, now extract the hash and username
				values = {}
				
				xmlfile = directory + '\\' + file
				tree=ET.ElementTree(file=xmlfile)
				root=tree.getroot()
				
				# Double check to make sure that the file is valid
				if root.tag != 'user':
					continue
				
				# Now save it to credentials
				values['Login'] = root.attrib['username']
				values['Hash'] = root.attrib['password']
				values["Category"] = "Rogue's Tale"
				creds.append(values)
		
		return creds
					
				
