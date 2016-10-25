import platform
import subprocess
import os
# inspired from the checkvm.rb from the metasploit framework

def execute_command(dic):
	vm = ''
	output = subprocess.check_output(dic[0].split(' '))
	if output:
		vm = check_result(dic, output)
	return vm

def read_file(dic):
	try:
		vm = ''
		content = open(dic[0]).read()
		if content:
			vm = check_result(dic, content)
			return vm
	except:
		return

def check_result(dic, output):
	for vms_artifacts in dic[1]:
		for vms_artifact in vms_artifacts.split(','):
			if vms_artifact.strip() in output:
				return dic[1][vms_artifacts]

# Check DMi Info
def check_dmi():
	dic = [
			'/usr/sbin/dmidecode', 
			{
				'microsoft corporation': 'MS Hyper-V', 
				'vmware': 'VMware', 
				'virtualbox': 'VirtualBox', 
				'qemu': 'Qemu/KVM', 
				'domu': 'Xen'
			}
		]
	return execute_command(dic)

# Check Modules
def check_modules():
	dic = [
		'/sbin/lsmod', 
		{
			'vboxsf, vboxguest': 'VirtualBox', 
			'vmw_ballon, vmxnet': 'VMware',  
			'xen-vbd, xen-vnif': 'Xen', 
			'virtio_pci, virtio_net': 'Qemu/KVM', 
			'hv_vmbus, hv_blkvsc, hv_netvsc, hv_utils, hv_storvsc': 'MS Hyper-V'
		}
	]
	return execute_command(dic)

# Check SCSI Driver
def scsi_driver():
	dic = [
		'/proc/scsi/scsi', 
		{
			'vmware': 'VMware',
			'vbox': 'VirtualBox'
		}
	]
	return read_file(dic)

# Check IDE Devices
def check_ide_devices():
	dic = [
		'/proc/ide/hd*/model', 
		{
			'vmware': 'VMware',
			'vbox': 'VirtualBox', 
			'qemu': 'Qemu/KVM', 
			'virtual [vc]d': 'Hyper-V/Virtual PC'
		}
	]
	return read_file(dic)

# Check using lspci
def check_lspci():
	distro = platform.linux_distribution()[0].lower()
	if distro in ['oracle', 'centos', 'suse', 'redhat', 'mandrake', 'slackware', 'fedora']:
		cmd = '/sbin/lspci'
	elif distro in ['debian', 'ubuntu']:
		cmd = '/usr/bin/lspci'
	else:
		cmd = 'lspci'

	dic = [
			cmd, 
			{
				'vmware': 'VMware',
				'virtualbox': 'VirtualBox', 
			}
		]
	return execute_command(dic)

# Check using lscpu
def check_lscpu():
	dic = [
		'lscpu', 
		{
			'Xen': 'Xen',
			'KVM': 'KVM', 
			'Microsoft': 'MS Hyper-V'
		}
	]
	return execute_command(dic)

# Check dmesg Output
def check_dmesg_output():
	dic = [
		'dmesg', 
		{
			'vboxbios, vboxcput, vboxfacp, vboxxsdt, vbox cd-rom, vbox harddisk': 'VirtualBox',
			'vmware virtual ide, vmware pvscsi, vmware virtual platform': 'VMware', 
			'xen_mem, xen-vbd': 'Xen', 
			'qemu virtual cpu version': 'Qemu/KVM', 
		}
	]
	return execute_command(dic)

def checkvm():
	functions = [
		check_modules(), 
		scsi_driver(), 
		check_ide_devices(), 
		check_lspci(), 
		check_lscpu(), 
		check_dmesg_output()
	]
	if os.geteuid() == 0:
		functions.append(check_dmi())

	vm = ''
	for function in functions: 
		vm = function
		if vm:
			break
	return vm
