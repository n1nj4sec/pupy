# -*- coding: utf-8 -*-
import sys
import uuid

def get_hw_uuid():
    zero_uuid = uuid.UUID('00000000-0000-0000-0000-000000000000')

    if 'win' in sys.platform:
        try:
            import win32com

            strComputer = "."
            objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            objSWbemServices = objWMIService.ConnectServer(strComputer, "root\\cimv2")
            colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_ComputerSystemProduct")
            for objItem in colItems:
                if objItem.UUID != None:
                    return 'wmi', objItem.UUID
        except:
            pass

        try:
            import subprocess
            return 'wmic', subprocess.check_output('wmic csproduct get uuid').strip().split('\n')[-1]
        except:
            pass

    elif 'linux' in sys.platform:
        machine_uuid = None
        try:
            with open('/sys/devices/virtual/dmi/id/product_uuid') as product_uuid:
                return 'dmi', uuid.UUID(product_uuid.read().strip())
        except IOError:
            pass

        try:
            with open('/etc/machine-id') as machine_id:
                return 'machine-id', machine_id.read().strip()
        except IOError:
            pass

        try:
            with open('/var/lib/dbus/machine-id') as machine_id:
                return 'machine-id', machine_id.read().strip()
        except IOError:
            pass

    return 'zero', zero_uuid
