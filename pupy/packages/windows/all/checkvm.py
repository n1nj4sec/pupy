import _winreg
import psutil

HKEY_LOCAL_MACHINE = -2147483646
KEY_READ           = 131097

class Check_VM():
    def __init__(self):
        self.process_list = []

    def get_process_list(self):
        if not self.process_list:
            for p in psutil.process_iter():
                self.process_list.append(p.name())

        return self.process_list

    def check_existing_key(self, k, key):
        try:
            hkey = _winreg.OpenKey(k, key, 0, KEY_READ)
            return hkey
        except:
            return False

    # Hyper-V
    def check_hyper_V(self):

        keys = [
            'SOFTWARE\\Microsoft\\Hyper-V',
            'SOFTWARE\\Microsoft\\VirtualMachine',
            'HARDWARE\\ACPI\\FADT\\vrtual',
            'HARDWARE\\ACPI\\RSDT\\vrtual',
            'SYSTEM\\ControlSet001\\Services\\vmicheartbeat',
            'SYSTEM\\ControlSet001\\Services\\vmicvss',
            'SYSTEM\\ControlSet001\\Services\\vmicshutdown',
            'SYSTEM\\ControlSet001\\Services\\vmiexchange',
        ]
        for key in keys:
            h = self.check_existing_key(HKEY_LOCAL_MACHINE, key)
            if h:
                _winreg.CloseKey(h)
                return True

        h = self.check_existing_key(HKEY_LOCAL_MACHINE, 'HARDWARE\\DESCRIPTION\\System')
        if h:
            string = str(_winreg.QueryValueEx(h, 'SystemBiosVersion')[0])
            if 'vrtual' in string:
                return True

        return False

    # VMWARE
    def check_VMWare(self):

        keys = [
            'SYSTEM\\ControlSet001\\Services\\vmdebug',
            'SYSTEM\\ControlSet001\\Services\\vmmouse',
            'SYSTEM\\ControlSet001\\Services\\VMTools',
            'SYSTEM\\ControlSet001\\Services\\VMMEMCTL',
        ]
        for key in keys:
            h = self.check_existing_key(HKEY_LOCAL_MACHINE, key)
            if h:
                _winreg.CloseKey(h)
                return True

        h = self.check_existing_key(HKEY_LOCAL_MACHINE, 'HARDWARE\\DESCRIPTION\\System\\BIOS')
        if h:
            string = str(_winreg.QueryValueEx(h, 'SystemManufacturer')[0])
            if 'vmware' in string:
                return True

        plist = self.get_process_list()
        if 'vmwareuser.exe' in plist or 'vmwaretray.exe' in plist or 'vmtoolsd.exe' in plist:
            return True

    # Virtual PC
    def check_Virtual_PC(self):
        plist = self.get_process_list()
        if 'vmusrvc.exe' in plist or 'vmsrvc.exe' in plist or 'vmwareuser.exe' in plist or 'vmwaretray.exe' in plist:
            return True

        keys = [
            'SYSTEM\\ControlSet001\\Services\\vpc-s3',
            'SYSTEM\\ControlSet001\\Services\\vpcuhub',
            'SYSTEM\\ControlSet001\\Services\\msvmmouf'
        ]
        for key in keys:
            h = self.check_existing_key(HKEY_LOCAL_MACHINE, key)
            if h:
                _winreg.CloseKey(h)
                return True

    # Virtual Box
    def check_Virtual_Box(self):
        plist = self.get_process_list()
        if 'vboxservice.exe' in plist or 'vboxtray.exe' in plist:
            return True

        keys = [
            'HARDWARE\\ACPI\\FADT\\vbox_',
            'HARDWARE\\ACPI\\RSDT\\vbox_',
            'SYSTEM\\ControlSet001\\Services\\VBoxMouse',
            'SYSTEM\\ControlSet001\\Services\\VBoxGuest',
            'SYSTEM\\ControlSet001\\Services\\VBoxService',
            'SYSTEM\\ControlSet001\\Services\\VBoxSF',
        ]
        for key in keys:
            h = self.check_existing_key(HKEY_LOCAL_MACHINE, key)
            if h:
                _winreg.CloseKey(h)
                return True

        h = self.check_existing_key(HKEY_LOCAL_MACHINE, 'HARDWARE\\DESCRIPTION\\System')
        if h:
            string = str(_winreg.QueryValueEx(h, 'SystemBiosVersion')[0])
            if 'vbox' in string:
                return True

    # Xen
    def check_xen(self):
        plist = self.get_process_list()
        if 'xenservice.exe' in plist:
            return True

        keys = [
            'HARDWARE\\ACPI\\FADT\\xen',
            'HARDWARE\\ACPI\\DSDT\\xen',
            'HARDWARE\\ACPI\\RSDT\\xen',
            'SYSTEM\\ControlSet001\\Services\\xenevtchn',
            'SYSTEM\\ControlSet001\\Services\\xennet',
            'SYSTEM\\ControlSet001\\Services\\xennet6',
            'SYSTEM\\ControlSet001\\Services\\xensvc',
            'SYSTEM\\ControlSet001\\Services\\xenvdb',
        ]
        for key in keys:
            h = self.check_existing_key(HKEY_LOCAL_MACHINE, key)
            if h:
                _winreg.CloseKey(h)
                return True

    # QEMU
    def check_qemu(self):
        h = self.check_existing_key(HKEY_LOCAL_MACHINE, 'HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0')
        if h:
            string = str(_winreg.QueryValueEx(h, 'ProcessorNameString')[0])
            if 'vmware' in string:
                return True

    def run(self):
        vm = []
        if self.check_hyper_V():
            vm.append('This is a Hyper-V machine.')

        if self.check_VMWare():
            vm.append('This is a VMWare machine.')

        if self.check_Virtual_PC():
            vm.append('This is a Virtual PC.')

        if self.check_Virtual_Box():
            vm.append('This is a Virtual Box.')

        if self.check_xen():
            vm.append('This is a Xen Machine.')

        if self.check_qemu():
            vm.append('This is a Qemu machine.')

        return vm
