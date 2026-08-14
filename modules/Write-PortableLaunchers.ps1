# Helper: write VBS/CMD/README into $Destination. The SPDX header of the script
# goes into the launchers as well, so no file of the package is left unlicensed.
function Write-PortableLaunchers {
	[CmdletBinding()] param( [Parameter(Mandatory = $true)][string]$Destination, [Parameter(Mandatory = $true)][string]$ScriptName, [Parameter(Mandatory = $true)][string]$SpdxFrom )
	# Extract SPDX lines from the .ps1 header (first 80 lines is plenty)
	$spdx = @()
	try {
		$head = Get-Content -LiteralPath $SpdxFrom -First 80 -ErrorAction Stop
		$spdx = $head | Where-Object { $_ -match '^\s*#\s*SPDX-' } | ForEach-Object { ($_ -replace '^\s*#\s*', '').Trim() }
	} catch {}
	# --- VBS launcher ---
	$vbsHeader = $spdx | ForEach-Object { "' " + $_ }
	$vbsBody = @(
		"Option Explicit", "", "Dim fso, shell, here, ps1, cmd", "Set fso = CreateObject(""Scripting.FileSystemObject"")",
		"Set shell = CreateObject(""WScript.Shell"")", "", "here = fso.GetParentFolderName(WScript.ScriptFullName)", ("ps1 = fso.BuildPath(here, ""{0}"")" -f $ScriptName), "",
		# Use Chr(34) to avoid crazy quote-escaping; equivalent to double double-quotes:
		'cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File " & Chr(34) & ps1 & Chr(34)', "shell.Run cmd, 0, False"
	)
	$vbsPath = Join-Path $Destination ('{0}.vbs' -f $AppNameShort)
	# IMPORTANT: do not concatenate arrays with + then -join; use a single flat array
	@($vbsHeader; ""; $vbsBody) -join "`r`n" | Set-Content -Path $vbsPath -Encoding ASCII
	# --- CMD starter (calls the VBS via relative path) ---
	$cmdHeader = $spdx | ForEach-Object { ":: " + $_ }
	$cmdBody = @( "@echo off", ("wscript.exe ""%~dp0{0}.vbs""" -f $AppNameShort) )
	$cmdPath = Join-Path $Destination ("Start {0}.cmd" -f $AppName)
	@($cmdHeader; ""; $cmdBody) -join "`r`n" | Set-Content -Path $cmdPath -Encoding ASCII
	# --- README_FIRST.txt (short variant) ---
	$readme = @"
$AppName (portable)

Start the app by double-clicking: "Start $AppName.cmd"

Much and good luck,
ernolf
"@
	Set-Content -Path (Join-Path $Destination 'README_FIRST.txt') -Value $readme -Encoding UTF8
}