# --- Broker: elevate once, apply registry values under HKLM and restart WebClient ---
function Invoke-WebClientWriteBroker {
	param([hashtable]$ValuesToSet)
	# Basic sanity check
	if (-not $ValuesToSet -or $ValuesToSet.Count -eq 0) { return $false }
	# Write JSON payload for the elevated helper
	$tmpJson = [System.IO.Path]::GetTempFileName().Replace('.tmp', '.json')
	($ValuesToSet | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $tmpJson -Encoding UTF8
	# Log file for debugging (persists across runs)
	$tmpLog = Join-Path $env:TEMP 'NcDavTray-WebClientBroker.log'
	$broker = @"
param([string]`$JsonPath, [string]`$LogPath)
`$ErrorActionPreference = 'Stop'
function Write-Log([string]`$m) { try { Add-Content -LiteralPath `$LogPath -Value ("[{0}] {1}" -f (Get-Date -Format 's'), `$m) } catch {} }
try {
	Write-Log 'Broker started'
	if (-not (Test-Path -LiteralPath `$JsonPath)) { Write-Log ("JSON not found: {0}" -f `$JsonPath); exit 2 }
	`$raw = ''
	try { `$raw = Get-Content -Raw -LiteralPath `$JsonPath; Write-Log ("JSON raw: {0}" -f `$raw) } catch { Write-Log ("Error reading JSON: {0}" -f `$_.Exception.Message); exit 2 }
	`$data = `$null
	# Use fully qualified cmdlet name to avoid alias/shadowing issues
	try { `$data = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject `$raw } catch { Write-Log ("ConvertFrom-Json failed: {0}" -f `$_.Exception.Message); exit 2 }
	if (`$data -eq `$null) { Write-Log 'ConvertFrom-Json returned `$null'; exit 2 }
	# Dump JSON property names for debugging
	try { `$names = @(); foreach (`$p in `$data.PSObject.Properties) { `$names += `$p.Name }; Write-Log ("JSON props: {0}" -f ([string]::Join(', ', `$names))) } catch { Write-Log 'Warning: could not enumerate JSON properties' }
	`$keyReg = '$($RegWebClient -replace ':', '')'
	`$keyPs = '$RegWebClient'
	if (-not (Test-Path `$keyPs)) { Write-Log ("Create key: {0}" -f `$keyPs); New-Item -Path `$keyPs -Force | Out-Null }
	function Set-DWord([string]`$name, [object]`$valRaw) {
		`$val = 0
		try {
			if (`$valRaw -is [string]) { if ([string]::IsNullOrWhiteSpace(`$valRaw)) { `$val = 0 } else { `$val = [decimal]`$valRaw } } else { `$val = [decimal]`$valRaw }
		} catch { Write-Log ("Set-DWord {0}: parse error for value '{1}', forcing 0" -f `$name, `$valRaw); `$val = 0 }
		if (`$val -lt 0) { `$val = 0 }
		`$max = [decimal][uint32]::MaxValue
		if (`$val -gt `$max) { `$val = `$max }
		`$ival = [uint32][math]::Floor(`$val)
		Write-Log ("Set {0} = {1}" -f `$name, `$ival)
		& reg.exe ADD "`$keyReg" /v "`$name" /t REG_DWORD /d "`$ival" /f | Out-Null
	}
	`$startupType = `$null
	if (`$data.PSObject.Properties.Name -contains 'BasicAuthLevel') { `$bal = [long]`$data.BasicAuthLevel; if (`$bal -lt 0) { `$bal = 0 }; if (`$bal -gt 2) { `$bal = 2 }; Set-DWord 'BasicAuthLevel' `$bal }
	if (`$data.PSObject.Properties.Name -contains 'FileAttributesLimitInBytes') { Set-DWord 'FileAttributesLimitInBytes' `$data.FileAttributesLimitInBytes }
	if (`$data.PSObject.Properties.Name -contains 'FileSizeLimitInBytes') { Set-DWord 'FileSizeLimitInBytes' `$data.FileSizeLimitInBytes }
	if (`$data.PSObject.Properties.Name -contains 'LocalServerTimeoutInSec') { Set-DWord 'LocalServerTimeoutInSec' `$data.LocalServerTimeoutInSec }
	if (`$data.PSObject.Properties.Name -contains 'InternetServerTimeoutInSec') { Set-DWord 'InternetServerTimeoutInSec' `$data.InternetServerTimeoutInSec }
	if (`$data.PSObject.Properties.Name -contains 'SendReceiveTimeoutInSec') { Set-DWord 'SendReceiveTimeoutInSec' `$data.SendReceiveTimeoutInSec }
	if (`$data.PSObject.Properties.Name -contains 'ServerNotFoundCacheLifeTimeInSec') { Set-DWord 'ServerNotFoundCacheLifeTimeInSec' `$data.ServerNotFoundCacheLifeTimeInSec }
	# Optional: change startup type (Automatic / Manual / Disabled)
	if (`$data.PSObject.Properties.Name -contains 'StartupType') {
		try {
			`$startupType = [string]`$data.StartupType
			if ([string]::IsNullOrWhiteSpace(`$startupType)) { `$startupType = `$null }
		} catch {
			Write-Log ("StartupType parse failed: {0}" -f `$_.Exception.Message)
			`$startupType = `$null
		}
		if (`$startupType) {
			try {
				Write-Log ("Set start type: {0}" -f `$startupType)
				Set-Service -Name WebClient -StartupType `$startupType -ErrorAction Stop
			} catch { Write-Log ("Failed to set start type: {0}" -f `$_.Exception.Message) }
		}
	}
	try {
		Write-Log 'Restart WebClient service'
		Stop-Service WebClient -ErrorAction SilentlyContinue | Out-Null
		if (-not `$startupType -or (`$startupType -ne 'Disabled')) { Start-Service WebClient -ErrorAction SilentlyContinue | Out-Null }
	} catch { Write-Log ("Service restart error: {0}" -f `$_.Exception.Message) }
	Write-Log 'Broker success'; exit 0
}
catch { Write-Log ("Broker error: {0}" -f `$_.Exception.Message); exit 1 }
"@
	# Persist broker script
	$ps1 = [System.IO.Path]::GetTempFileName().Replace('.tmp', '.ps1')
	$broker | Set-Content -LiteralPath $ps1 -Encoding UTF8
	# Use 64-bit PowerShell when available
	$pwsh = Join-Path $env:WINDIR 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
	if (-not (Test-Path $pwsh)) { $pwsh = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe' }
	$psi = New-Object System.Diagnostics.ProcessStartInfo
	$psi.FileName = $pwsh
	$psi.Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ps1`" -JsonPath `"$tmpJson`" -LogPath `"$tmpLog`""
	$psi.Verb = 'runas'
	$psi.UseShellExecute = $true
	$psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
	$psi.CreateNoWindow = $true
	$ok = $false
	try { $p = [System.Diagnostics.Process]::Start($psi); if ($p) { $p.WaitForExit(); if ($p.ExitCode -eq 0) { $ok = $true } } } catch { $ok = $false }
	Remove-Item -LiteralPath $ps1, $tmpJson -Force -ErrorAction SilentlyContinue
	return $ok
}
