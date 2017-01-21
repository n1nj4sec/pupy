# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__="GetInfo"

@config(cat="gather")
class GetInfo(PupyModule):
    """ get some informations about one or multiple clients """
    dependencies = {
        'all': [ ],
        'windows': [ "pupwinutils.security" ],
    }

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(
            prog='get_info',
            description=self.__doc__
        )

    def run(self, args):
        commonKeys = [
            "hostname", "user", "release", "version",
            "os_arch", "proc_arch", "pid", "exec_path",
            "address", "macaddr"
        ]
        pupyKeys = [ "transport", "launcher", "launcher_args" ]
        windKeys = [ "uac_lvl","intgty_lvl" ]
        linuxKeys = [ "daemonize" ]
        macKeys = []

        infos = []

        for k in commonKeys:
            infos.append((k,self.client.desc[k]))

        if self.client.is_windows():
            self.client.load_package("psutil")
            self.client.load_package("pupwinutils.security")
            for k in windKeys:
                infos.append((k,self.client.desc[k]))

            security = self.client.conn.modules["pupwinutils.security"]
            currentUserIsLocalAdmin = security.can_get_admin_access()

            value = '?'
            if currentUserIsLocalAdmin == True:
                value = 'Yes'
            elif currentUserIsLocalAdmin == False:
                value = 'No'

            infos.append(('local_adm', value))

        elif self.client.is_linux():
            for k in linuxKeys:
                infos.append((k,self.client.desc[k]))

        elif self.client.is_darwin():
            for k in macKeys:
                infos.append((k,self.client.desc[k]))
        
        elif self.client.is_android():
            self.client.load_package("pupydroid.utils")
            wifiConnected = self.client.conn.modules["pupydroid.utils"].isWiFiConnected()
            if wifiConnected == True:
                androidCtionType = {'info':"WiFi", 'fast':True}
            else:
                androidCtionType = self.client.conn.modules["pupydroid.utils"].getMobileNetworkType()
            infos.append(('ction_type', "{0} (fast:{1})".format(androidCtionType['info'], androidCtionType['fast'])))
            androidID = self.client.conn.modules["pupydroid.utils"].getAndroidID()
            infos.append(("android_id",androidID))
            wifiEnabled = self.client.conn.modules["pupydroid.utils"].isWiFiEnabled()
            infos.append(("wifi_enabled",wifiEnabled))
            infoBuild = self.client.conn.modules["pupydroid.utils"].getInfoBuild()
            infos.append(("device_name",infoBuild['deviceName']))
            infos.append(("manufacturer",infoBuild['manufacturer']))
            #infos.append(("model",infoBuild['model']))
            #infos.append(("product",infoBuild['product']))
            infos.append(("bootloader_version",infoBuild['bootloaderVersion']))
            infos.append(("radio_version",infoBuild['radioVersion']))
            infos.append(("release",infoBuild['release']))
            battery = self.client.conn.modules["pupydroid.utils"].getBatteryStats()
            infos.append(("battery_%",battery['percentage']))
            infos.append(("is_charging",battery['isCharging']))
            simState = self.client.conn.modules["pupydroid.utils"].getSimState()
            infos.append(("sim_state",simState))
            deviceId = self.client.conn.modules["pupydroid.utils"].getDeviceId()
            infos.append(("device_id",deviceId))
            #Needs API level 23. When this API will be used, these 2 following line should be uncommented
            #simInfo = self.client.conn.modules["pupydroid.utils"].getSimInfo() 
            #infos.append(("sim_count",simInfo))
            if ("absent" not in simState) and ("unknown" not in simState):
                phoneNb = self.client.conn.modules["pupydroid.utils"].getPhoneNumber()
                infos.append(("phone_nb",phoneNb))
                simCountryIso = self.client.conn.modules["pupydroid.utils"].getSimCountryIso()
                infos.append(("sim_country",simCountryIso))
                networkCountryIso = self.client.conn.modules["pupydroid.utils"].getNetworkCountryIso()
                infos.append(("network_country",networkCountryIso))
                networkOperatorName = self.client.conn.modules["pupydroid.utils"].getNetworkOperatorName()
                infos.append(("network_operator",networkOperatorName))
                isNetworkRoaming = self.client.conn.modules["pupydroid.utils"].isNetworkRoaming()
                infos.append(("is_roaming",isNetworkRoaming))
            else:
                #Print N/A when not applicable. These following lines can be removed from info if needed
                infos.append(("phone_nb","N/A"))
                infos.append(("sim_country","N/A"))
                infos.append(("network_country","N/A"))
                infos.append(("network_operator","N/A"))
                infos.append(("device_id","N/A"))

        for k in pupyKeys:
            infos.append((k,self.client.desc[k]))

        infos.append(('platform', '{}/{}'.format(
            self.client.platform, self.client.arch or '?'
        )))
        
        #For remplacing None or "" value by "?"
        infoTemp = []
        for i, (key, value) in enumerate(infos):
            if value == None or value == "":
                value = "?"
            infoTemp.append((key, value))
        infos = infoTemp

        info_fmt = '{{:<{}}}: {{}}'.format(max([len(pair[0]) for pair in infos]) + 1)

        infos = [
            info_fmt.format(info[0], info[1]) for info in infos
        ]

        max_data_size = max([len(info) for info in infos])
        delim = '-'*max_data_size

        infos = '\n'.join([delim] + infos + [delim, ''])

        self.rawlog(infos)
