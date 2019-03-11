# -*- encoding: utf-8 -*-

import wmi

def execute(query):
    try:
        client = wmi.WMI()
    except wmi.x_wmi_uninitialised_thread:
        import pythoncom
        pythoncom.CoInitialize()
        client = wmi.WMI()

    return tuple(client.query(query))
