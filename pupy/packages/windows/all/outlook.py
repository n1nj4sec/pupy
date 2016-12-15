# -*- coding: UTF8 -*-
#Author: @bobsecq
#Contributor(s):

import os, logging, sys, time
from collections import OrderedDict
import win32com
import win32com.client
import glob, re

class outlook():
	'''
	'''
	
	OL_SAVE_AS_TYPE={'olTXT': 0,'olRTF':1,'olTemplate': 2,'olMSG': 3,'olDoc':4,'olHTML':5,'olVCard': 6,'olVCal':7,'olICal': 8}
	OL_DEFAULT_FOLDERS = {'olFolderDeletedItems':3,'olFolderDrafts':16,'olFolderInbox':6,'olFolderJunk':23,'olFolderSentMail':5}
	OL_ACCOUNT_TYPES = {4:'olEas',0:'olExchange',3:'olHttp',1:'olImap',5:'olOtherAccount',2:'olPop3'}
	OL_EXCHANGE_CONNECTION_MODE = {100:'olOffline',500:'olOnline',200:'olDisconnected',300:'olConnectedHeaders',400:'olConnected',0:'olNoExchange'}
	
	def __init__(self, folderIndex=None, folderId=None, sleepTime=3, msgSaveType='olMSG'):
		'''
		'''
		self.outlook = None
		self.mapi = None
		self.foldersAndSubFolders = None
		self.folderId = folderId
		self.folderIndex = folderIndex
		self.msgSaveType = msgSaveType
		self.inbox = None
		self.constants = None
		self.sleepTime = sleepTime
		self.remoteTempFolder = os.path.expandvars("%TEMP%")
				
	def outlookIsInstalled(self):
		'''
		returns True if Outlook is installed
		otherwise returns False
		'''
		try:
			win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
			return True
		except Exception,e:
			return False
		
				
	def connect(self):
		'''
		Returns True if no error
		Otherise returns False
		'''
		try:
			self.outlook = win32com.client.Dispatch("Outlook.Application")
			#self.outlook = win32com.client.gencache.EnsureDispatch("Outlook.Application")
			self.mapi = self.outlook.GetNamespace("MAPI")
			if self.folderId == None : self.setDefaultFolder(folderIndex=self.folderIndex)
			else : self.setFolderFromId(folderId=self.folderId)
			return True
		except Exception,e:
			return False
		
	def getInformation(self):
		'''
		Returns Dictionnary
		'''
		info = OrderedDict()
		try:
			info['CurrentProfileName']=self.mapi.CurrentProfileName
		except Exception,e:
				logging.debug("Impossible to get CurrentProfileName configuration: {0}".format(e))
				info['CurrentProfileName']=""
		#info['CurrentUserAddress']=repr(self.mapi.CurrentUser) #Needs to be authenticiated to remote mail server. Otherwise, infinite timeout
		try:
			info['SessionType']=self.outlook.Session.Type
		except Exception,e:
			logging.debug("Impossible to get SessionType configuration: {0}".format(e))
			info['SessionType']=""
		for i, anAccount in enumerate(self.outlook.Session.Accounts):
			try:
				info['Account{0}-DisplayName'.format(i)]=anAccount.DisplayName
			except Exception,e:
				logging.debug("Impossible to get DisplayName configuration: {0}".format(e))
				info['Account{0}-DisplayName'.format(i)]=""
			try:
				info['Account{0}-SmtpAddress'.format(i)]=anAccount.SmtpAddress
			except Exception,e:
				logging.debug("Impossible to get SmtpAddress configuration: {0}".format(e))
				info['Account{0}-SmtpAddress'.format(i)]=""
			try: 
				info['Account{0}-AutoDiscoverXml'.format(i)]=anAccount.AutoDiscoverXml
			except Exception,e:
				logging.debug("Impossible to get AutoDiscoverXml configuration: {0}".format(e))
				info['Account{0}-AutoDiscoverXml'.format(i)]=""
			try: 
				info['Account{0}-AccountType'.format(i)]=self.OL_ACCOUNT_TYPES[anAccount.AccountType]
			except Exception,e:
				logging.debug("Impossible to get AccountType configuration: {0}".format(e))
				info['Account{0}-AccountType'.format(i)]=""
			#info['Account{0}-UserName'.format(i)]=anAccount.UserName #Needs to be authenticiated to remote mail server. Otherwise, infinite timeout
		try:
			info['ExchangeMailboxServerName']=self.mapi.ExchangeMailboxServerName #Returns a String value that represents the name of the Exchange server that hosts the primary Exchange account mailbox.
		except Exception,e:
				logging.debug("Impossible to get ExchangeMailboxServerName configuration: {0}".format(e))
				info['ExchangeMailboxServerName'.format(i)]=""
		try:
			info['ExchangeMailboxServerVersion']=self.mapi.ExchangeMailboxServerVersion #Returns a String value that represents the full version number of the Exchange server that hosts the primary Exchange account mailbox.
		except Exception,e:
				logging.debug("Impossible to get ExchangeMailboxServerVersion configuration: {0}".format(e))
				info['ExchangeMailboxServerVersion'.format(i)]=""
		try:
			info['Offline']=self.mapi.Offline #Returns a Boolean indicating True if Outlook is offline (not connected to an Exchange server), and False if online (connected to an Exchange server)
		except Exception,e:
				logging.debug("Impossible to get Offline configuration: {0}".format(e))
				info['Offline'.format(i)]=""
		try:
			info['ExchangeConnectionMode']=self.OL_EXCHANGE_CONNECTION_MODE[self.mapi.ExchangeConnectionMode]
			self.mapi.SendAndReceive(True)
		except Exception,e:
				logging.debug("Impossible to get ExchangeConnectionMode configuration: {0}".format(e))
				info['ExchangeConnectionMode']=None
		return info
		
		
	def __getOlDefaultFoldersNameFromIndex__(self, folderIndex):
		'''
		Return None if folderIndex not found in OlDefaultFolders
		Otherwise returns Name of the folder
		'''
		found = False
		for k in self.OL_DEFAULT_FOLDERS:
			if self.OL_DEFAULT_FOLDERS[k] == folderIndex:
				return k
		return ""
	
	def setDefaultFolder(self, folderIndex=None):
		'''
		See https://msdn.microsoft.com/fr-fr/library/office/ff861868.aspx for folderIndex
		Return True if done
		Otherwise returns False
		'''
		if folderIndex == None: 
			folderIndex = self.OL_DEFAULT_FOLDERS['olFolderInbox']
		folderName = self.__getOlDefaultFoldersNameFromIndex__(folderIndex)
		if folderName == None:
			logging.warning('Impossible to move the default folder to {0}. This folder index is not in {1}'.format(folderIndex, self.OL_DEFAULT_FOLDERS))
			return False
		else:
			logging.debug("Moving outlook default folder to {0}".format(folderName))
			self.inbox = self.mapi.GetDefaultFolder(folderIndex)
			return True
	
	def setFolderFromId(self, folderId):
		'''
		See https://msdn.microsoft.com/fr-fr/library/office/ff861868.aspx for folderIndex
		Return True if done
		Otherwise returns False
		'''
		if folderId == None: 
			logging.error("Impossible to set Outlook folder to None")
			return False
		else:
			logging.debug("Moving outlook default folder to {0}".format(folderId))
			self.inbox = self.mapi.GetFolderFromID(folderId)
			return True
		
	def getEmails(self):
		'''
		Returns a list which contains all mailitems
		'''
		emails = []
		logging.debug("Getting {0} emails...".format(self.getNbOfEmails()))
		for anEmail in self.inbox.Items:
			emails.append(anEmail)
		return emails
		
	def getAMailFile(self, mailItem):
		'''
		return pathToAMailFileOnTarget, nameOftheMailFile
		'''
		ctime, subjectCleaned, receivedTime, path, filename = str(time.time()).replace('.',''), "Unknown", "Unknown", "", ""
		try:
			subjectCleaned = ''.join(l for l in mailItem.Subject.encode('ascii','ignore') if l.isalnum())
			receivedTime = str(mailItem.ReceivedTime).replace('/','').replace('\\','').replace(':','-').replace(' ','_')
		except Exception,e:
			logging.warning("Impossible to encode email subject or receivedTime:{0}".format(repr(e)))
		filename = "{0}_{1}_{2}.{3}".format(receivedTime, ctime, subjectCleaned[:100], 'msg')
		path = os.path.join(self.remoteTempFolder,filename)
		logging.debug('Saving temporarily the email on the remote path {0}'.format(path))
		mailItem.SaveAs(path, outlook.OL_SAVE_AS_TYPE[self.msgSaveType])
		try:
			os.rename(path, path) #test if the file is not opened by another process
		except OSError as e:
			time.sleep(self.sleepTime)
		return path, filename
		
		
	def deleteTempMailFile(self,path):
		'''
		'''
		try:
			os.remove(path)
		except OSError as e:
			time.sleep(self.sleepTime)
			os.remove(path)
			
	"""
	def getAllSubjects(self):
		'''
		'''
		subjects = []
		logging.debug("Getting subjects of {0} emails...".format(self.getNbOfEmails()))
		for anEmail in self.inbox.Items:
			subjects.append(anEmail.Subject)
		return subjects
	"""
	
	def getNbOfEmails(self):
		'''
		'''
		#nc = self.inbox.Count
		nb = len(self.inbox.Items)
		logging.debug("Getting number of emails... {0} emails".format(nb))
		return nb
		
	def getAllFolders(self):
		'''
		'''
		folders = {}
		for inx, folder in enumerate(list(self.mapi.Folders)):
			logging.debug("New folder: {0}({1})".format(folder.Name.encode('utf-8'), folder.EntryID))
			folders[folder.Name] = {}
			if "Dossiers publics" not in folder.Name and "Public folders" not in folder.Name: #Bug in my version of outlook when getting emails in public folder
				for inx,subfolder in enumerate(list(folder.Folders)):
					logging.debug("{0}->{1} ({2})".format(inx, subfolder.Name.encode('utf-8'), subfolder.EntryID))
					folders[folder.Name][subfolder.Name]=subfolder.EntryID
		return folders
	
	
	def getPathToOSTFiles(self):
		'''
		According to https://support.office.com/en-us/article/Locating-the-Outlook-data-files-0996ece3-57c6-49bc-977b-0d1892e2aacc
		'''
		paths = []
		DEFAULT_LOCATIONS_OST = ["<drive>:\Users\<username>\AppData\Local\Microsoft\Outlook",
		"<drive>:\Documents and Settings\<username>\Local Settings\Application Data\Microsoft\Outlook"
		]
		systemDrive = os.getenv("SystemDrive")
		login = os.getenv("username")
		for aLocationOST in DEFAULT_LOCATIONS_OST :
			completeLocationOST = aLocationOST.replace("<drive>",systemDrive[:-1]).replace("<username>",login)
			regex = os.path.join(completeLocationOST,"*.ost")
			logging.debug('Searching OST file in {0}'.format(regex))
			files = glob.glob(regex)
			for aFile in files:
				ostFileFound = os.path.join(completeLocationOST,aFile)
				logging.info('OST file found in {0}'.format(ostFileFound))
				paths.append([os.path.basename(aFile), ostFileFound])
		return paths
		
	
	def searchStringsInEmails(self, strings, separator=','):
		'''
		Returns emails when aString in subject or body
		'''
		emails= []
		stringsSplited = strings.split(separator)
		for aString in stringsSplited:
			results = self.searchAStringInEmails(aString)
			emails = emails + results
		return emails
	
	def searchAStringInEmails(self, aString):
		'''
		Returns emails when aString in subject or body
		'''
		body, subject, emails = "", "", []
		logging.debug("Searching {1} over {0} emails...".format(self.getNbOfEmails(), aString))
		for anEmail in self.inbox.Items:
			outEmail = {'body':anEmail.Body, 'subject':anEmail.Subject}
			if bool(re.search(aString, anEmail.Subject))==True:
				emails.append(outEmail)
			elif bool(re.search(aString, anEmail.Body))==True:
				emails.append(outEmail)
		return emails
