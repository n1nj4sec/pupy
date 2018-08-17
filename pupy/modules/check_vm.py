# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__="CheckVM"

@config(category="gather", compatibilities=['windows', 'linux', 'darwin'])
class CheckVM(PupyModule):
    """ check if running on Virtual Machine """

    dependencies = ['checkvm']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="CheckVM", description=cls.__doc__)

    def run(self, args):
        if self.client.is_windows():
            check_vm = self.client.remote('checkvm')
            vms = check_vm.Check_VM().run()
            if vms:
                for vm in vms:
                    self.success(vm)
            else:
                self.error('No Virtual Machine found')

        elif self.client.is_linux():
            checkvm = self.client.remote('checkvm', 'checkvm', False)
            vm = checkvm()
            if vm:
                self.success('This appears to be a %s virtual machine' % vm)
            else:
                self.success('This does not appear to be a virtual machine')

        elif self.client.is_darwin():
            checkvm = self.client.remote('checkvm', 'checkvm', False)
            self.info('Be patient, could take a while')
            vm = checkvm()
            if vm:
                self.success('This appears to be a %s virtual machine' % vm)
            else:
                self.success('This does not appear to be a virtual machine')
