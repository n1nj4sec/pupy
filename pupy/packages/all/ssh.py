import os
import re
import paramiko
import socket

class SSH():
	def __init__(self, _user, _ssh_private_key_path, _password, _file_to_parse, _ip, _port, _verbose=False, _command=''):
		self.user = _user
		self.ssh_private_key_path = os.path.expanduser(_ssh_private_key_path) # <path to private key>
		self.password = _password

		self.connection_by_key = False # if private key
		if self.ssh_private_key_path:
			self.connection_by_key = True

		self.file_to_parse = os.path.expanduser(_file_to_parse) # path to 'known_hosts' file
		self.ip = _ip
                self.port = _port
		self.verbose = _verbose
		self.command = _command

	def check_existing_files(self):
		if self.ssh_private_key_path and not os.path.exists(self.ssh_private_key_path):
			return False, 'The file does not exist on the remote host: %s' % self.ssh_private_key_path

		if not self.ip and not os.path.exists(self.file_to_parse):
			return False, 'The file does not exist on the remote host: %s' % self.file_to_parse

		return True, ''

	def execute_command_using_password(self, client):
		stdout_data = []
		stderr_data = []
		session = client.open_channel(kind='session')
		session.exec_command(self.command)
		nbytes = 4096
		while True:
		    if session.recv_ready():
		        stdout_data.append(session.recv(nbytes))
		    if session.recv_stderr_ready():
		        stderr_data.append(session.recv_stderr(nbytes))
		    if session.exit_status_ready():
		        break

		# print 'exit status: ', session.recv_exit_status()
		output = ''.join(stdout_data)
		output += ''.join(stderr_data)
		session.close()
		return output

	def execute_command_using_key(self, client):
		stdin , stdout, stderr = client.exec_command(self.command)
		output = stdout.read()
		output += stderr.read()
		return output

	def sshConnect(self, hostname):
		
		output = ''
		# Connection using private key
		if self.connection_by_key:
			k = paramiko.RSAKey.from_private_key_file(self.ssh_private_key_path)
			ssh  = paramiko.SSHClient() # will create the object
			ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # no known_hosts error
			ssh.connect(hostname, username=self.user, pkey = k) # no passwd needed
			if self.command:
				output = self.execute_command_using_key(ssh)
		
		# Connection using plain text passowrd
		else:
			ssh = paramiko.Transport((hostname, self.port))
			ssh.connect(username=self.user, password=self.password)
			plaintext_password = True
			if self.command:
				output = self.execute_command_using_password(ssh)

		ssh.close()

		return output

	def checkOpenPort(self, ip, port):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(3)
		result = sock.connect_ex((ip, port))
		sock.shutdown(2)
		if result == 0:
			return True
		else:
			return False

	def parseip(self):
		file = open(self.file_to_parse, "r")
		ips = []
		for text in file.readlines():
			text = text.rstrip()
			regex = re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})',text)
			if regex:
				if regex[0] and regex[0] not in ips:
					ips.append(regex[0].replace('\n',''))

		file.close()
		if self.verbose:
			print '[!] File parsed, %d IP found. ' % len(ips)
		return ips

	def ssh_client(self):
		check_files = self.check_existing_files()
		if not check_files[0]:
			return check_files[0], check_files[1]  # BOOL / ERROR

		try:
			if not self.ip:
				ips = self.parseip()
				if not ips:
					return False, 'no ip found parsing the file'
			else:
				ips = [self.ip]

			if self.verbose:
				print '[!] Checking connections, please wait.'
			
			ip_ok = []
			for ip in ips:
				try:
					if self.checkOpenPort(ip, self.port):
						output = self.sshConnect(ip)
						if self.verbose:
							print '[+] Successful connection : %s' % ip
						ip_ok.append([ip, output])
					else:
						if self.verbose:
							print '[-] Port seems to be closed : %s' % ip
				except Exception, e:
					if 'encrypted' in str(e[0]):
						return False, str(e[0])
					if self.verbose:
						print '[!] ' + str(e)
			if ip_ok:
				result = 'List of successful connection\n'
				for ip in ip_ok:
					result += '- %s\n' % str(ip[0])
					if self.command:
						result += '%s\n' % str(ip[1])
				return True, result
			else:
				return False, 'No successful connection found.'

		except IOError, (errno, strerror):
			return False, 'I/O Error(%s) : %s\n' % (str(errno), str(strerror))
