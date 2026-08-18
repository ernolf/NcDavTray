# Fetches the release archive and lays it out where it can be started from. The
# folder has one fixed name and is emptied before use, so an attempt that broke
# off leaves one copy behind rather than one per try.
# What comes back is the path of the unpacked script, and '' whenever anything
# about the package failed to hold up.
function Save-UpdatePackage {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Url, [int64]$Size = 0, [int]$TimeoutMs = 120000 )
	$dir = Join-Path $env:TEMP ("{0}_update" -f $AppName)
	try {
		if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
		New-Item -ItemType Directory -Path $dir -Force | Out-Null
	} catch { return '' }
	$zip = Join-Path $dir 'package.zip'
	try {
		$req = New-HttpGetRequest $Url $TimeoutMs 'application/octet-stream'
		$resp = $req.GetResponse()
		try {
			$out = [System.IO.File]::Create($zip)
			try { $resp.GetResponseStream().CopyTo($out) } finally { $out.Close() }
		} finally { try { $resp.Close() } catch {} }
	} catch { return '' }
	# A download that stopped early is a perfectly valid file of the wrong length,
	# and the release says how long the right one is.
	if ($Size -gt 0) { try { if ((Get-Item -LiteralPath $zip).Length -ne $Size) { return '' } } catch { return '' } }
	try {
		Add-Type -AssemblyName System.IO.Compression.FileSystem
		[System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $dir)
	} catch { return '' }
	$ps1 = Join-Path (Join-Path $dir $AppName) $ScriptFile
	if (-not (Test-Path -LiteralPath $ps1 -PathType Leaf)) { return '' }
	# The tag says what the release is called, the script says what it is. Only the
	# second one is about to be installed, so it is the one that has to be newer --
	# a release named wrongly would otherwise install a copy older than this one.
	$got = $null
	try {
		$m = [regex]::Match((Get-Content -Raw -LiteralPath $ps1), '(?m)^\s*\$Version\s*=\s*''([^'']+)''')
		if ($m.Success) { $got = [version]$m.Groups[1].Value }
	} catch { return '' }
	if (-not $got) { return '' }
	try { if ($got -le [version]$Version) { return '' } } catch { return '' }
	# Handing over is an agreement between two copies, and -Action Update is the half
	# the downloaded one has to keep. It exists from 2.0.0 on; anything older would
	# refuse the parameter after this copy has already stepped aside, leaving nothing
	# running and nothing installed.
	if ($got -lt [version]'2.0.0') { return '' }
	return $ps1
}
