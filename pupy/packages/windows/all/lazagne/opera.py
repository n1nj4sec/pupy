import sys, struct, hashlib, binascii, re, os
from Crypto.Cipher import DES3
from ConfigParser import RawConfigParser
import sqlite3, win32crypt

class Opera():
	def __init__(self):
		self.CIPHERED_FILE = ''
	
	def run(self):
		# retrieve opera folder
		path = self.get_path()
		
		if path == 'env_variable_error' or not path:
			return
		
		passwords = ''
		# old versions
		if self.CIPHERED_FILE == 'wand.dat':
			# check the use of master password 
			if not os.path.exists(path + os.sep + 'operaprefs.ini'):
				return
			
			passwords = self.decipher_old_version(path)
			if passwords:
				return self.parse_results(passwords)
		# new versions
		else:
			return self.decipher_new_version(path)
	
	def get_path(self):	
		if 'APPDATA' in os.environ:
			# version less than 10
			if os.path.exists(os.environ['APPDATA'] + '\Opera\Opera\profile'):
				self.CIPHERED_FILE = 'wand.dat'
				return os.environ['APPDATA'] + '\Opera\Opera\profile'
			
			# version more than 10
			if os.path.exists(os.environ['APPDATA'] + '\Opera\Opera'):
				self.CIPHERED_FILE = 'wand.dat'
				return os.environ['APPDATA'] + '\Opera\Opera'
			
			# new versions
			elif os.path.exists(os.environ['APPDATA'] + '\Opera Software\Opera Stable'):
				self.CIPHERED_FILE = 'Login Data'
				return os.environ['APPDATA'] + '\Opera Software\Opera Stable'
		
			else:
				return None
		else: 
			return 'env_variable_error'
	
	def decipher_old_version(self, path):
		salt = '837DFC0F8EB3E86973AFFF'
		
		# retrieve wand.dat file
		if not os.path.exists(path + os.sep + 'wand.dat'):
			return 
		
		# read wand.dat
		f = open(path + os.sep + 'wand.dat', 'rb') 
		file =  f.read()
		fileSize = len(file)
		
		passwords = []
		offset = 0
		while offset < fileSize:

			offset = file.find('\x08', offset) + 1
			if offset == 0:
				break

			tmp_blockLength = offset - 8
			tmp_datalen = offset + 8
			
			blockLength = struct.unpack('!i', file[tmp_blockLength : tmp_blockLength + 4])[0]
			datalen = struct.unpack('!i', file[tmp_datalen : tmp_datalen + 4])[0]
			
			binary_salt = binascii.unhexlify(salt)
			desKey = file[offset: offset + 8]
			tmp = binary_salt + desKey
			
			md5hash1 = hashlib.md5(tmp).digest()
			md5hash2 = hashlib.md5(md5hash1 + tmp).digest() 

			key = md5hash1 + md5hash2[0:8]
			iv = md5hash2[8:]
			
			data = file[offset + 8 + 4: offset + 8 + 4 + datalen]

			des3dec = DES3.new(key, DES3.MODE_CBC, iv)
			try:
				plaintext = des3dec.decrypt(data)
				plaintext = re.sub(r'[^\x20-\x7e]', '', plaintext)
				passwords.append(plaintext)
			except Exception,e:
				pass
			
			offset += 8 + 4 + datalen
		return passwords
		
	def decipher_new_version(self, path):
		database_path = path + os.sep + 'Login Data'
		if os.path.exists(database_path):
			
			# Connect to the Database
			conn = sqlite3.connect(database_path)
			cursor = conn.cursor()
			
			# Get the results
			try:
				cursor.execute('SELECT action_url, username_value, password_value FROM logins')
			except Exception,e:
				return 
			
			pwdFound = []
			for result in cursor.fetchall():
				values = {}
				
				# Decrypt the Password
				password = win32crypt.CryptUnprotectData(result[2], None, None, None, 0)[1]
				if password:
					values['Category'] = "Opera"
					values['Website'] = result[0]
					values['Username'] = result[1]
					values['Password'] = password
					pwdFound.append(values)

		return pwdFound
		
	def masterPasswordUsed(self, path):
		
		# the init file is not well defined so lines have to be removed before to parse it
		cp = RawConfigParser()
		f = open(path + os.sep + 'operaprefs.ini', 'rb')
		
		f.readline() # discard first line
		while 1:
			try:
				cp.readfp(f)
				break
			except Exception,e:
				f.readline() # discard first line
		try:
			master_pass = cp.get('Security Prefs','Use Paranoid Mailpassword')
			return master_pass
		except Exception,e:
			return False
			
		
	def parse_results(self, passwords):
		
		cpt = 0
		values = {}
		pwdFound = []
		for password in passwords:
			
			# date (begin of the sensitive data)
			match=re.search(r'(\d+-\d+-\d+)', password)
			if match:
				values = {}
				cpt = 0
				tmp_cpt = 0
			
			# after finding 2 urls
			if cpt == 2:
				tmp_cpt += 1
				if tmp_cpt == 2:
					values['User'] = password
					values['Category'] = "Opera"
				elif tmp_cpt == 4:
					values['Password'] = password
				
			# url
			match=re.search(r'^http', password)
			if match:
				cpt +=1
				if cpt == 1:
					tmp_url = password
				elif cpt == 2:
					values['URL'] = tmp_url
			pwdFound.append(values)
		
		return pwdFound

