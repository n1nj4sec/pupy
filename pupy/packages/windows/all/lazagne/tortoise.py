import sqlite3, win32crypt
import sys, os, platform, base64

class Tortoise():

	def run(self):

		file_path = ''
		if 'APPDATA' in os.environ:
			file_path = os.environ.get('APPDATA') + '\\Subversion\\auth\\svn.simple'
		else:
			return
		
		values = {}
		pwdFound = []
		if os.path.exists(file_path):
			for root, dirs, files in os.walk(file_path + os.sep):
				for name_file in files:
					values = {}
					f = open(file_path + os.sep + name_file, 'r')
					
					url = ''
					username = ''
					result = ''
					
					i = 0
					# password
					for line in f:
						if i == -1:
							result = line.replace('\n', '')
							break
						if line.startswith('password'):
							i = -3
						i+=1
					
					i = 0
					# url
					for line in f:
						if i == -1:
							url = line.replace('\n', '')
							break
						if line.startswith('svn:realmstring'):
							i = -3
						i+=1

					i = 0
					# username
					for line in f:
						if i == -1:
							username = line.replace('\n', '')
							break
						if line.startswith('username'):
							i = -3
						i+=1
					
					# unccrypt the password
					if result:
						
						try:
							password = win32crypt.CryptUnprotectData(base64.b64decode(result), None, None, None, 0)[1]
						except:
							password = ''
						
						if password:
							values['Category'] = "tortoise"
							values['URL'] = url
							values['Username'] = username
							values['Password'] = password
							
							pwdFound.append(values)
			
			return pwdFound
	
