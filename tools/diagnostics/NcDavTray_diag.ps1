# NcDavTray - WebDAV / WebClient diagnostics
# Read-only: collects environment info to debug "mapping failed" issues.
# No password and no share token ever reaches the report; host and user names do
# unless the anonymized profile is chosen at the prompt.

# SPDX-FileCopyrightText: 2025 [ernolf] Raphael Gradenwitz <raphael.gradenwitz@googlemail.com>
# SPDX-License-Identifier: GPL-3.0-or-later


$AppName      = 'NcDavTray'
$AppNameShort = 'NDT' 
$HereDir      = Split-Path -Parent $PSCommandPath
$ScriptFile   = ("{0}.ps1" -f $AppNameShort)
$InstallDir   = Join-Path $env:LOCALAPPDATA $AppName
$InstallBin   = Join-Path $InstallDir $ScriptFile
$PortJson     = ("{0}_config.json" -f $AppNameShort)
# What a portable copy up to 1.2.2 wrote instead: one account, no mount list.
$LegacyJson   = ("{0}_portable.json" -f $AppName)
$SecretPath   = ("{0}_secret.dat" -f $AppNameShort)
$RegBase      = ("HKCU:\Software\{0}" -f $AppName)
$RegAccounts  = Join-Path $RegBase 'Accounts'
$RegMounts    = Join-Path $RegBase 'Mounts'
$RegMP2       = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2'
$RegWebClient = 'HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters'
# Shared state, keyed on the application name and therefore in the same place as
# an installed copy: a portable copy keeps it here too, because processes and
# their PIDs live per user session, not per folder.
$StateDir      = $InstallDir
$CacheStateDir = Join-Path $StateDir 'CacheAgent'
$InstanceList  = Join-Path (Join-Path $StateDir 'Instances') 'instances.json'
# The redirector's cache, in the profile of the LOCAL SERVICE account
$CacheRoot     = Join-Path $env:WINDIR 'ServiceProfiles\LocalService\AppData\Local\Temp\TfsStore\Tfs_DAV'

$ErrorActionPreference = 'SilentlyContinue'
try {
    [System.Threading.Thread]::CurrentThread.CurrentCulture   = 'en-US'
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'
} catch {}

$script:Configs       = @()
$script:KnownHosts    = @() # Nextcloud servers
$script:KnownDrives   = @()
$script:KnownWinUsers = @()
$script:KnownNcUsers  = @()
$script:KnownWinHosts = @()
$script:KnownLabels   = @()
# Folder names inside the user's cloud are as personal as the label, and the path
# to a mount runs through the report in three spellings. What the report needs of
# it is its shape, not its names.
$script:KnownSubPaths = @()
$script:SegNumbers    = @{}
# A share token is not a name but a key: it grants access to the share on its own.
# It is masked in every report, anonymized or not, which is why it is kept apart
# from the lists above.
$script:KnownTokens   = @()

if ($env:USERNAME)     { $script:KnownWinUsers += $env:USERNAME }
if ($env:COMPUTERNAME) { $script:KnownWinHosts += $env:COMPUTERNAME }
if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) {
	$script:KnownWinHosts += $env:USERDOMAIN
}

$script:Anonymize = $false

Write-Host ""
Write-Host "NcDavTray diagnostics" -ForegroundColor Cyan

$profile = Read-Host @"
Select diagnostics profile:
  1 = Local diagnostics (no anonymization by default)
  2 = Public issue / GitHub (automatic anonymization)
Profile [1/2]
"@

if ($profile -eq '2') {
	$script:Anonymize = $true
} else {
	$anonAnswer = Read-Host @"
Anonymize hostnames, user names and labels in the report? [y/N]
You should anonymize the output if you want to use this diagnostics file in a GitHub issue or in any publicly accessible forum.
"@
	if ($anonAnswer -match '^[Yy]') { $script:Anonymize = $true }
}

# ---------- Helpers ----------
function New-StringBuilder {
	return New-Object System.Text.StringBuilder
}

function Mask-Tokens {
	param([string]$line)
	if ([string]::IsNullOrEmpty($line)) { return $line }
	$masked = $line
	foreach ($tok in $script:KnownTokens) {
		if ([string]::IsNullOrWhiteSpace($tok)) { continue }
		$masked = [regex]::Replace($masked, [regex]::Escape($tok), '<SHARE_TOKEN(masked)>')
	}
	return $masked
}

function Add-Line {
	param(
		[System.Text.StringBuilder]$sb,
		[string]$text = ''
	)
	[void]$sb.AppendLine($text)
}

# Masking runs over the finished report, not while it is written: a host, a user
# or a token is only known once the configuration it comes from has been read, so
# masking a line as it is composed would let every first occurrence through.
# Tokens go always, anonymized report or not: they are keys, not names.
function Mask-Report {
	param([string]$text)
	if ([string]::IsNullOrEmpty($text)) { return $text }
	$lines = $text -split "`r?`n"
	for ($i = 0; $i -lt $lines.Count; $i++) {
		if ($script:KnownTokens.Count -gt 0) { $lines[$i] = Mask-Tokens $lines[$i] }
		if ($script:Anonymize) { $lines[$i] = Mask-InLine $lines[$i] }
	}
	return ($lines -join [Environment]::NewLine)
}

function Add-Section {
	param(
		[System.Text.StringBuilder]$sb,
		[string]$title
	)
	Add-Line $sb ''
	Add-Line $sb ('===== {0} =====' -f $title)
}

function New-ConfigRecord {
	param(
		[string]$Path,
		[psobject]$Mount
	)
	if (-not $Mount) { return $null }
	$kind = [string]$Mount.Kind
	if (-not $kind) { $kind = 'account' }
	$drive = [string]$Mount.Drive
	if (-not $drive -and ($Mount.PSObject.Properties.Name -contains 'DriveLetter')) { $drive = [string]$Mount.DriveLetter }
	$port = $false
	try { $port = [bool]$Mount.ExplicitPort } catch {}
	return [PSCustomObject]@{
		Path         = $Path
		Server       = [string]$Mount.Server
		Kind         = $kind
		Drive        = $drive
		User         = [string]$Mount.User
		Token        = [string]$Mount.Token
		SubPath      = [string]$Mount.SubPath
		Label        = [string]$Mount.Label
		ExplicitPort = $port
	}
}

# Since 2.0.0 a portable copy keeps every mount in one file, under Mounts. Up to
# 1.2.2 the file held a single account in its top level, which is what the second
# branch reads: a copy that has not been started by 2.x yet still looks like that.
function Read-ConfigFile {
	param(
		[string]$Path
	)
	$result = @()
	if (-not (Test-Path -LiteralPath $Path)) { return $result }
	$cfg = $null
	try {
		$raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
		if ([string]::IsNullOrWhiteSpace($raw)) { return $result }
		$cfg = $raw | ConvertFrom-Json -ErrorAction Stop
	} catch {
		return $result
	}
	if (-not $cfg) { return $result }
	$have = $cfg.PSObject.Properties.Name
	if ($have -contains 'Mounts') {
		foreach ($m in @($cfg.Mounts)) {
			$rec = New-ConfigRecord -Path $Path -Mount $m
			if ($rec -and $rec.Server) { $result += $rec }
		}
		return $result
	}
	if ($cfg.Server) {
		$rec = New-ConfigRecord -Path $Path -Mount $cfg
		if ($rec) { $result += $rec }
	}
	return $result
}

# The settings that sit beside the mount list, in both storage forms
function Add-SettingsLines {
	param(
		[System.Text.StringBuilder]$sb,
		[psobject]$Source
	)
	if (-not $Source) { return }
	$have = $Source.PSObject.Properties.Name
	foreach ($n in @('IntervalS', 'LangPref', 'TrayIcons', 'UpdateCheck')) {
		if ($have -contains $n) { Add-Line $sb ("  {0}: {1}" -f $n, $Source.$n) }
	}
}

function Normalize-SubPath([string]$sp) {
	if ([string]::IsNullOrWhiteSpace($sp) -or $sp -eq '/') { return '' }
	$sp = $sp.Trim().Trim('/', '\')
	if ($sp.Length -eq 0) { return '' }
	$parts = ($sp -split '[\\/]+') | Where-Object { $_ -ne '' }
	return ($parts -join '/')
}

# Host part, path segments, UNC path and MountPoints2 key names are built the way
# NcDavTray builds them (Split-ServerString, Get-MountHostPart,
# Get-MountPathSegments, Get-MP2KeyNames).
# An explicit port is part of the host string and therefore part of the identity
# the redirector keys its session on, so a check that leaves it out compares a
# healthy mount against a path it was never mapped under. An instance installed
# in a subdirectory carries that path in its segments, not in its host.
function Split-ServerString([string]$server) {
	$s = ([string]$server).Trim().Trim('/')
	$i = $s.IndexOf('/')
	$h = if ($i -lt 0) { $s } else { $s.Substring(0, $i) }
	$b = if ($i -lt 0) { '' } else { $s.Substring($i + 1).Trim('/') }
	$key = if ($b) { '{0}/{1}' -f $h.ToLowerInvariant(), $b } else { $h.ToLowerInvariant() }
	return @{ Host = $h; BasePath = $b; Key = $key }
}

function Build-HostPart([psobject]$cfg) {
	$h = (Split-ServerString $cfg.Server).Host
	if ($cfg.ExplicitPort) { return ('{0}@ssl@443' -f $h) }
	return ('{0}@ssl' -f $h)
}

function Build-PathSegments([psobject]$cfg) {
	$segs = @()
	$base = (Split-ServerString $cfg.Server).BasePath
	if ($base) { $segs += @(($base -split '/') | Where-Object { $_ }) }
	$segs += switch ($cfg.Kind) {
		'share'        { @('public.php', 'dav', 'files', $cfg.Token) }
		'share-legacy' { @('public.php', 'webdav') }
		default        { @('remote.php', 'dav', 'files', $cfg.User) }
	}
	$norm = Normalize-SubPath $cfg.SubPath
	if ($norm) { $segs += ($norm -split '/') }
	return , $segs
}

function Build-Unc([psobject]$cfg) {
	$segs = Build-PathSegments $cfg
	return ('\\{0}\{1}' -f (Build-HostPart $cfg), ($segs -join '\'))
}

function Build-Mp2Names([psobject]$cfg) {
	$hostPart = Build-HostPart $cfg
	$path     = (Build-PathSegments $cfg) -join '#'
	return @(
		('##{0}#{1}' -f $hostPart, $path),
		('##{0}#DavWWWRoot#{1}' -f $hostPart, $path)
	)
}

# What a mount needs before a path can be built from it at all
function Test-ConfigMappable([psobject]$cfg) {
	if (-not $cfg.Server) { return $false }
	switch ($cfg.Kind) {
		'share'        { return [bool]$cfg.Token }
		'share-legacy' { return $true }
		default        { return [bool]$cfg.User }
	}
}

# One number per distinct folder name, held for the whole report, so that two lines
# naming the same folder still look alike. A segment that is also a label keeps the
# label placeholder, which is what shows that the two are the same name.
function Get-SegmentPlaceholder([string]$seg) {
	foreach ($lbl in $script:KnownLabels) {
		if ($lbl -and [string]::Equals($lbl, $seg, 'OrdinalIgnoreCase')) { return '<LABEL(anonymized)>' }
	}
	$key = $seg.ToLowerInvariant()
	if (-not $script:SegNumbers.ContainsKey($key)) { $script:SegNumbers[$key] = $script:SegNumbers.Count + 1 }
	return ('<PATH{0}(anonymized)>' -f $script:SegNumbers[$key])
}

# Only the connected path is replaced, in each of the three separators it appears
# with, and only where a path ends: a mount's subfolder is always the tail of the
# path it sits in. Without that anchor a folder named dav, Temp or Windows would
# take apart every path in the report that happens to contain the word.
function Mask-SubPaths {
	param([string]$line)
	if ([string]::IsNullOrEmpty($line) -or $script:KnownSubPaths.Count -eq 0) { return $line }
	$masked = $line
	# Longest first, so a deeper path is not half-replaced by one of its parents
	foreach ($sp in ($script:KnownSubPaths | Select-Object -Unique | Sort-Object -Property Length -Descending)) {
		$segs = @($sp -split '/')
		$repl = @($segs | ForEach-Object { Get-SegmentPlaceholder $_ })
		foreach ($sep in @('/', '\', '#')) {
			# Preceded by a separator or an assignment, followed by the end of the
			# path: end of line, whitespace, a quote, or the trailing separator a
			# MountPoints2 key name carries.
			$pattern = ('(?<=[=/\\#]){0}(?=[/\\#]?(\s|$|"))' -f [regex]::Escape(($segs -join $sep)))
			$masked  = [regex]::Replace($masked, $pattern, ($repl -join $sep), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
		}
	}
	return $masked
}

function Mask-InLine {
	param([string]$line)
	if ([string]::IsNullOrEmpty($line)) { return $line }

	$masked = $line

	# Paths go first: once a single segment has been replaced on its own, the path
	# around it can no longer be recognized as one.
	$masked = Mask-SubPaths $masked

	# Windows hosts / domains (machine name, USERDOMAIN)
	if ($script:KnownWinHosts -and $script:KnownWinHosts.Count -gt 0) {
		foreach ($wh in $script:KnownWinHosts) {
			if ([string]::IsNullOrWhiteSpace($wh)) { continue }
			$escapedWH = [regex]::Escape($wh)
			$masked    = [regex]::Replace($masked, $escapedWH, '<WIN_HOST(anonymized)>')
		}
	}

	# Windows user (local logon name)
	if ($script:KnownWinUsers -and $script:KnownWinUsers.Count -gt 0) {
		foreach ($wu in $script:KnownWinUsers) {
			if ([string]::IsNullOrWhiteSpace($wu)) { continue }
			$escapedWU = [regex]::Escape($wu)
			$patternWU = ('\b{0}\b' -f $escapedWU)
			$masked    = [regex]::Replace($masked, $patternWU, '<WIN_USER(anonymized)>')
		}
	}

	# Nextcloud host. Longest first: an instance in a subdirectory is on record
	# under both spellings, and 'host/nc' has to go before 'host' or the path
	# would be left standing next to the placeholder.
	if ($script:KnownHosts -and $script:KnownHosts.Count -gt 0) {
		foreach ($h in @($script:KnownHosts | Sort-Object -Property Length -Descending)) {
			if ([string]::IsNullOrWhiteSpace($h)) { continue }
			$escaped = [regex]::Escape($h)
			$masked  = [regex]::Replace($masked, $escaped, '<NC_HOST(anonymized)>')
		}
	}

	# Nextcloud user (account from NcDavTray config)
	if ($script:KnownNcUsers -and $script:KnownNcUsers.Count -gt 0) {
		foreach ($nu in $script:KnownNcUsers) {
			if ([string]::IsNullOrWhiteSpace($nu)) { continue }
			$escapedNU = [regex]::Escape($nu)
			$patternNU = ('\b{0}\b' -f $escapedNU)
			$masked    = [regex]::Replace($masked, $patternNU, '<NC_USER(anonymized)>')
		}
	}

	# Label from NcDavTray config
	if ($script:KnownLabels -and $script:KnownLabels.Count -gt 0) {
		foreach ($lbl in $script:KnownLabels) {
			if ([string]::IsNullOrWhiteSpace($lbl)) { continue }
			$escapedLBL = [regex]::Escape($lbl)
			$masked     = [regex]::Replace($masked, $escapedLBL, '<LABEL(anonymized)>')
		}
	}

	return $masked
}

function Get-FontMapValue {
	param(
		[object]$Substitutes,
		[string]$Name
	)
	if ($Substitutes -and $Substitutes.PSObject.Properties.Name -contains $Name) {
		return ("{0} => {1}" -f $Name, $Substitutes.$Name)
	}
	return ("{0} => <not set>" -f $Name)
}

function Get-FontRegValue {
	param(
		[object]$FontReg,
		[string]$Name
	)
	if ($FontReg -and $FontReg.PSObject.Properties.Name -contains $Name) {
		return $FontReg.$Name
	}
	return "<missing>"
}

function Select-PortableFolder {
	try {
		Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
	} catch {
		Write-Host "Folder selection dialog not available, please enter the folder path manually." -ForegroundColor Yellow
		return (Read-Host ("Enter portable folder (where {0} and {1} live)" -f $PortJson, $SecretPath))
	}

	$initial = $HOME
	if ([string]::IsNullOrWhiteSpace($initial)) { $initial = $env:USERPROFILE }
	if ([string]::IsNullOrWhiteSpace($initial)) {
		try { $initial = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile) } catch {}
	}

	$dlg = New-Object System.Windows.Forms.FolderBrowserDialog
	$dlg.Description        = ("Select {0} portable folder (where {1} and {2} live)" -f $AppName, $PortJson, $SecretPath)
	$dlg.ShowNewFolderButton = $false
	if (-not [string]::IsNullOrWhiteSpace($initial)) {
		$dlg.SelectedPath = $initial
	}

	$result = $dlg.ShowDialog()
	if ($result -eq [System.Windows.Forms.DialogResult]::OK -and -not [string]::IsNullOrWhiteSpace($dlg.SelectedPath)) {
		return $dlg.SelectedPath
	}

	Write-Host "No folder selected." -ForegroundColor Yellow
	return ''
}

$sb = New-StringBuilder

$now = Get-Date

Add-Line $sb 'NcDavTray WebDAV / WebClient diagnostics'
Add-Line $sb ('Timestamp: {0:yyyy-MM-dd HH:mm:ss}' -f $now)
Add-Line $sb ''

# ---------- System / PowerShell ----------
Add-Section $sb 'System / PowerShell'

try {
	$os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
	$arch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
	Add-Line $sb ("Edition: {0}" -f $os.EditionID)
	Add-Line $sb ("Version: {0}  (Build {1}.{2})" -f $os.DisplayVersion, $os.CurrentBuild, $os.UBR)
	Add-Line $sb ("Architecture: {0}" -f $arch)
} catch {
	Add-Line $sb "Failed to read OS version from registry."
}

try {
	Add-Line $sb ("PowerShell version: {0}" -f $PSVersionTable.PSVersion)
	Add-Line $sb ("CLR version: {0}" -f [System.Environment]::Version)
} catch {
	Add-Line $sb "Failed to read PowerShell / CLR versions."
}

try {
	$culture = Get-Culture
	$sysLoc  = Get-WinSystemLocale
	Add-Line $sb ("UILanguage_Region: {0} | {1}" -f $culture.Name, $sysLoc.Name)
} catch {
	Add-Line $sb "Failed to read culture / system locale."
}

# ---------- Current user / elevation ----------
Add-Section $sb 'Current user / elevation'

try {
	$userName = $env:USERNAME
	$userDom  = $env:USERDOMAIN
	Add-Line $sb ("User name: {0}\{1}" -f $userDom, $userName)
} catch {
	Add-Line $sb "User name: <error reading>"
}

try {
	$id        = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = New-Object Security.Principal.WindowsPrincipal($id)
	$tokenIsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

	Add-Line $sb ("Current process token is elevated as admin: {0}" -f $tokenIsAdmin)

	# Group membership and integrity level via whoami /groups
	$accountCanElevate = $false
	$level = '<unknown>'
	try {
		$who = & whoami.exe /groups 2>$null
		if ($who) {
			foreach ($line in $who) {
				# Local Administrators group (S-1-5-32-544)
				if ($line -match 'S-1-5-32-544' -or $line -match 'BUILTIN\\Administrators') {
					$accountCanElevate = $true
				}
				if     ($line -match 'Mandatory Label\\High Mandatory Level')   { $level = 'High' }
				elseif ($line -match 'Mandatory Label\\Medium Mandatory Level') { $level = 'Medium' }
				elseif ($line -match 'Mandatory Label\\Low Mandatory Level')    { $level = 'Low' }
				elseif ($line -match 'Mandatory Label\\System Mandatory Level') { $level = 'System' }
				elseif ($line -match 'Mandatory Label\\Protected Process')      { $level = 'Protected' }
			}
		}
	} catch {}
	Add-Line $sb ("User account is member of local Administrators group (can request elevation): {0}" -f $accountCanElevate)
	Add-Line $sb ("Integrity level (whoami): {0}" -f $level)
} catch {
	Add-Line $sb "Failed to read user / elevation info."
}

# ---------- NcDavTray presence ----------
Add-Section $sb 'NcDavTray presence'

$mode = Read-Host -Prompt @"

Select mode for this machine:
  1 = Installed mode (LOCALAPPDATA\NcDavTray)
  2 = Portable mode (you will enter the folder path)
  3 = Skip NcDavTray-specific checks

Mode [1/2/3]
"@

switch ($mode) {
	'1' {
		Add-Line $sb ("Mode: Installed")
		Add-Line $sb ("Expected install dir: {0}" -f $InstallDir)
		if (Test-Path $InstallDir) {
			Add-Line $sb "Install dir exists: yes"
			try {
				if (Test-Path $InstallBin) {
					Add-Line $sb ("{0} found: yes" -f $ScriptFile)
					$verLine = Select-String -Path $InstallBin -Pattern '^\s*\$Version\s*=\s*' -ErrorAction SilentlyContinue | Select-Object -First 1
					if ($verLine) {
						$m = [regex]::Match($verLine.Line, "'([^']+)'")
						if ($m.Success) {
							Add-Line $sb ("NcDavTray script version: {0}" -f $m.Groups[1].Value)
						}
					}
				} else {
					Add-Line $sb ("{0} found: no" -f $ScriptFile)
				}
				# An installed copy keeps its configuration in the registry. A JSON file
				# in here is therefore a leftover, and worth naming as one.
				$jsonFiles = Get-ChildItem -Path $InstallDir -Filter '*.json' -ErrorAction SilentlyContinue
				if ($jsonFiles) {
					Add-Line $sb ("Unexpected JSON files in install dir: {0}" -f (($jsonFiles | Select-Object -Expand FullName) -join '; '))
				} else {
					Add-Line $sb "Unexpected JSON files in install dir: none"
				}
				# Installed mode: read the shared mount list (no secrets, no host leakage)
				try {
					if (Test-Path $RegBase) {
						Add-Line $sb "Installed config found in registry."
						try { Add-SettingsLines $sb (Get-ItemProperty -Path $RegBase -ErrorAction Stop) } catch {}
						# The passwords of an installed copy: one DPAPI blob per server/user
						# pair, shared by every mount of that pair. Only the names are read,
						# and of those only whether one matches the mount at hand.
						$accountNames = @()
						if (Test-Path $RegAccounts) {
							try {
								$acc = Get-ItemProperty -Path $RegAccounts -ErrorAction Stop
								$accountNames = @($acc.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object -Expand Name)
							} catch { Add-Line $sb "  Accounts key: unreadable" }
						}
						Add-Line $sb ("  Stored account passwords: {0}" -f $accountNames.Count)
						$mountKeys = @()
						if (Test-Path $RegMounts) { $mountKeys = @(Get-ChildItem -Path $RegMounts -ErrorAction SilentlyContinue) }
						Add-Line $sb ("  Mounts in list: {0}" -f $mountKeys.Count)
						foreach ($mk in $mountKeys) {
							$m = $null
							try { $m = Get-ItemProperty -Path $mk.PSPath -ErrorAction Stop } catch { Add-Line $sb ("  - {0}: unreadable" -f $mk.PSChildName); continue }
							$has = $m.PSObject.Properties.Name
							$val = { param($n) if ($has -contains $n) { return [string]$m.$n } return '' }
							$kind = & $val 'Kind'
							if (-not $kind) { $kind = '<not set>' }
							Add-Line $sb ("  - {0}  kind: {1}" -f $mk.PSChildName, $kind)
							$srv = & $val 'Server'
							$drv = & $val 'Drive'
							$usr = & $val 'User'
							$lbl = & $val 'Label'
							$tok = & $val 'Token'
							Add-Line $sb ("      Server: {0}" -f $(if ($srv) { $srv } else { '<not set>' }))
							Add-Line $sb ("      Drive: {0}" -f $(if ($drv) { $drv } else { '<not set>' }))
							# A share is named by a token that grants access, so only its presence is reported
							Add-Line $sb ("      Token set: {0}" -f $(if ($tok) { 'yes' } else { 'no' }))
							if ($usr -and $srv) {
								$key = ('{0}|{1}' -f (Split-ServerString $srv).Key, $usr.Trim())
								Add-Line $sb ("      Password stored for this account: {0}" -f $(if ($accountNames -contains $key) { 'yes' } else { 'no' }))
							}
							if ($has -contains 'ExplicitPort') { Add-Line $sb ("      Explicit port: {0}" -f [bool][int]$m.ExplicitPort) }
							if ($has -contains 'Enabled') { Add-Line $sb ("      Enabled: {0}" -f [bool][int]$m.Enabled) }
							if ($has -contains 'Order') { Add-Line $sb ("      Order: {0}" -f [int]$m.Order) }
							if ($srv) { $script:KnownHosts += @($srv, (Split-ServerString $srv).Host) }
							if ($drv) { $script:KnownDrives += $drv }
							if ($usr) { $script:KnownNcUsers += $usr }
							if ($lbl) { $script:KnownLabels += $lbl }
							if ($tok) { $script:KnownTokens += $tok }
							$sub = Normalize-SubPath (& $val 'SubPath')
							if ($sub) { $script:KnownSubPaths += $sub }
							$rec = New-ConfigRecord -Path ("Registry:{0}\{1}" -f $RegMounts, $mk.PSChildName) -Mount $m
							if ($rec) { $script:Configs += $rec }
						}
						# Left over from before 2.0.0, when a single account lived directly in this
						# key. The migration copies them into the list and leaves them in place.
						try {
							$flat = Get-ItemProperty -Path $RegBase -ErrorAction Stop
							if (($flat.PSObject.Properties.Name -contains 'Server') -and $flat.Server) {
								Add-Line $sb ("  Legacy flat account still present: {0}" -f $flat.Server)
								$script:KnownHosts += @($flat.Server, (Split-ServerString $flat.Server).Host)
								if ($flat.PSObject.Properties.Name -contains 'Drive' -and $flat.Drive) { $script:KnownDrives += $flat.Drive }
								if ($flat.PSObject.Properties.Name -contains 'User' -and $flat.User) { $script:KnownNcUsers += $flat.User }
								if ($flat.PSObject.Properties.Name -contains 'Label' -and $flat.Label) { $script:KnownLabels += $flat.Label }
								if ($flat.PSObject.Properties.Name -contains 'SubPath' -and $flat.SubPath) {
									$flatSub = Normalize-SubPath $flat.SubPath
									if ($flatSub) { $script:KnownSubPaths += $flatSub }
								}
							}
						} catch {}
					} else {
						Add-Line $sb "Installed config registry key not found."
					}
				} catch {
					Add-Line $sb "Failed to read installed config from registry."
				}
			} catch {
				Add-Line $sb "Failed to inspect NcDavTray install directory."
			}
		} else {
			Add-Line $sb "Install dir exists: no"
		}
	}
	'2' {
		Add-Line $sb "Mode: Portable"
		$portableRoot = Select-PortableFolder
		if ([string]::IsNullOrWhiteSpace($portableRoot)) {
			Add-Line $sb "Portable folder: <none provided>"
		} elseif (-not (Test-Path $portableRoot)) {
			Add-Line $sb ("Portable folder: {0} (NOT found)" -f $portableRoot)
		} else {
			Add-Line $sb ("Portable folder: {0}" -f $portableRoot)
			$configPath = Join-Path $portableRoot $PortJson
			$legacyPath = Join-Path $portableRoot $LegacyJson
			$secretFile = Join-Path $portableRoot $SecretPath
			$readFrom   = ''
			try {
				Add-Line $sb ("{0}: {1}" -f $PortJson, $(if (Test-Path -LiteralPath $configPath) { 'found' } else { 'none' }))
				# A copy that has not been started by 2.x yet still has only this one
				Add-Line $sb ("{0}: {1}" -f $LegacyJson, $(if (Test-Path -LiteralPath $legacyPath) { 'found (pre-2.0.0)' } else { 'none' }))
				Add-Line $sb ("{0}: {1}" -f $SecretPath, $(if (Test-Path -LiteralPath $secretFile) { 'found' } else { 'none' }))
			} catch {
				Add-Line $sb "Failed to inspect portable folder."
			}

			$portableConfigs = @()
			if (Test-Path -LiteralPath $configPath) {
				$readFrom = $configPath
			} elseif (Test-Path -LiteralPath $legacyPath) {
				$readFrom = $legacyPath
			}
			if ($readFrom) {
				$portableConfigs = @(Read-ConfigFile -Path $readFrom)
				try {
					$rawCfg = (Get-Content -LiteralPath $readFrom -Raw -ErrorAction Stop) | ConvertFrom-Json -ErrorAction Stop
					Add-SettingsLines $sb $rawCfg
				} catch {}
			}

			if ($portableConfigs.Count -gt 0) {
				$script:Configs += $portableConfigs
				Add-Line $sb ("Mounts in list: {0}" -f $portableConfigs.Count)
				foreach ($cfg in $portableConfigs) {
					Add-Line $sb ("  - kind: {0}" -f $cfg.Kind)
					Add-Line $sb ("      Server: {0}" -f $(if ($cfg.Server) { $cfg.Server } else { '<not set>' }))
					Add-Line $sb ("      Drive: {0}" -f $(if ($cfg.Drive) { $cfg.Drive } else { '<not set>' }))
					# A share is named by a token that grants access, so only its presence is reported
					Add-Line $sb ("      Token set: {0}" -f $(if ($cfg.Token) { 'yes' } else { 'no' }))
					Add-Line $sb ("      Explicit port: {0}" -f $cfg.ExplicitPort)
					if ($cfg.Server) { $script:KnownHosts += @($cfg.Server, (Split-ServerString $cfg.Server).Host) }
					if ($cfg.Drive)  { $script:KnownDrives += $cfg.Drive }
					if ($cfg.User)   { $script:KnownNcUsers += $cfg.User }
					if ($cfg.Label)  { $script:KnownLabels += $cfg.Label }
					if ($cfg.Token)  { $script:KnownTokens += $cfg.Token }
					$sub = Normalize-SubPath $cfg.SubPath
					if ($sub) { $script:KnownSubPaths += $sub }
				}
			} else {
				Add-Line $sb "Mounts in list: none"
			}
		}
	}
	default {
		Add-Line $sb "Mode: skipped (no NcDavTray-specific inspection)"
	}
}

# ---------- WebClient service ----------
Add-Section $sb 'WebClient service'

try {
	$svc = Get-Service -Name WebClient -ErrorAction Stop
	Add-Line $sb ("Status: {0}" -f $svc.Status)
} catch {
	Add-Line $sb "Status: WebClient service not found"
	$svc = $null
}

try {
	$svcWmi = Get-CimInstance Win32_Service -Filter "Name='WebClient'" -ErrorAction SilentlyContinue
	if ($svcWmi) {
		Add-Line $sb ("Start mode: {0}" -f $svcWmi.StartMode)
		Add-Line $sb ("PathName: {0}" -f $svcWmi.PathName)
	} else {
		Add-Line $sb "Start mode / PathName: <not available>"
	}
} catch {
	Add-Line $sb "Failed to read WebClient WMI data."
}

# ---------- WebClient registry parameters ----------
Add-Section $sb 'WebClient registry parameters'

try {
	$reg = Get-ItemProperty -Path $RegWebClient -ErrorAction Stop
	Add-Line $sb ("Registry path: {0}" -f $RegWebClient)

	function Format-Dword {
		param([long]$v)
		if ($v -lt 0) { $v = 0 }
		$u = [uint32]$v
		return ("0x{0:x8} ({1})" -f $u, $u)
	}

	$names = @(
		'BasicAuthLevel',
		'FileAttributesLimitInBytes',
		'FileSizeLimitInBytes',
		'LocalServerTimeoutInSec',
		'InternetServerTimeoutInSec',
		'SendReceiveTimeoutInSec',
		'ServerNotFoundCacheLifeTimeInSec'
	)

	foreach ($n in $names) {
		if ($reg.PSObject.Properties.Name -contains $n) {
			$val = [int64]$reg.$n
			Add-Line $sb ("{0} = {1}" -f $n, (Format-Dword $val))
		} else {
			Add-Line $sb ("{0} = <not set>" -f $n)
		}
	}
} catch {
	Add-Line $sb ("Failed to read registry path: {0}" -f $RegWebClient)
}

# ---------- WebDAV cache and cache watcher ----------
Add-Section $sb 'WebDAV cache / cache watcher'

# The cache itself belongs to the LOCAL SERVICE account, so an unelevated run can
# see the directory but not read it. That is the normal case, not a fault, and the
# watcher is the elevated helper that reports on it instead. The report therefore
# names counts and sizes only: file names in this cache are file names from the
# server, and they are none of a report's business.
try {
	Add-Line $sb ("Cache root: {0}" -f $CacheRoot)
	if (Test-Path -LiteralPath $CacheRoot) {
		Add-Line $sb "Cache root exists: yes"
		$readable = $false
		try {
			Get-ChildItem -LiteralPath $CacheRoot -Force -ErrorAction Stop | Out-Null
			$readable = $true
		} catch {}
		Add-Line $sb ("Readable from this process: {0} (elevation required)" -f $readable)
	} else {
		Add-Line $sb "Cache root exists: no"
	}

	$statePath = Join-Path $CacheStateDir 'state.json'
	$cmdPath   = Join-Path $CacheStateDir 'command.json'
	Add-Line $sb ("Agent state dir: {0}" -f $CacheStateDir)
	if (Test-Path -LiteralPath $statePath) {
		try {
			$st = (Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop) | ConvertFrom-Json -ErrorAction Stop
			$stamp = [datetime]::MinValue
			$ageOk = [datetime]::TryParse([string]$st.TimestampUtc, [ref]$stamp)
			if ($ageOk) {
				Add-Line $sb ("state.json age: {0:N0} s" -f ((Get-Date).ToUniversalTime() - $stamp.ToUniversalTime()).TotalSeconds)
			} else {
				Add-Line $sb "state.json age: <no timestamp>"
			}
			if ($st.Snapshot) {
				Add-Line $sb ("  Cache files: {0}" -f $st.Snapshot.FileCount)
				Add-Line $sb ("  Cache size: {0:N0} bytes" -f [int64]$st.Snapshot.TotalBytes)
				Add-Line $sb ("  Oldest entry (UTC): {0}" -f $(if ($st.Snapshot.OldestWriteTimeUtc) { $st.Snapshot.OldestWriteTimeUtc } else { '<none>' }))
				Add-Line $sb ("  Newest entry (UTC): {0}" -f $(if ($st.Snapshot.NewestWriteTimeUtc) { $st.Snapshot.NewestWriteTimeUtc } else { '<none>' }))
			}
			if ($st.LastAction) { Add-Line $sb ("  Last action: {0}" -f $st.LastAction) }
			if ($st.LastError)  { Add-Line $sb ("  Last error: {0}" -f $st.LastError) }
		} catch {
			Add-Line $sb "state.json: unreadable or malformed"
		}
	} else {
		# The agent removes it on the way out, so its absence is the normal resting state
		Add-Line $sb "state.json: none (no watcher running)"
	}
	# A command waits here only between two ticks of the agent; one that stays is
	# a command nobody picked up.
	Add-Line $sb ("command.json pending: {0}" -f (Test-Path -LiteralPath $cmdPath))

	Add-Line $sb ("Instance list: {0}" -f $InstanceList)
	if (Test-Path -LiteralPath $InstanceList) {
		try {
			$entries = @((Get-Content -LiteralPath $InstanceList -Raw -ErrorAction Stop) | ConvertFrom-Json -ErrorAction Stop)
			$aliveUi = 0
			$aliveWatcher = 0
			$stale = 0
			foreach ($e in $entries) {
				$pidValue = 0
				try { $pidValue = [int]$e.Pid } catch {}
				$running = $false
				if ($pidValue -gt 0) {
					try { $running = [bool](Get-Process -Id $pidValue -ErrorAction Stop) } catch {}
				}
				if (-not $running) { $stale++; continue }
				switch ([string]$e.Role) {
					'Ui'      { $aliveUi++ }
					'Watcher' { $aliveWatcher++ }
				}
			}
			Add-Line $sb ("  Entries: {0} (UI alive: {1}, watcher alive: {2}, stale: {3})" -f $entries.Count, $aliveUi, $aliveWatcher, $stale)
		} catch {
			Add-Line $sb "  Instance list: unreadable or malformed"
		}
	} else {
		Add-Line $sb "  Instance list: none"
	}
} catch {
	Add-Line $sb "Failed to inspect the WebDAV cache state."
}

# ---------- Mapped drives (net use) ----------
Add-Section $sb 'Mapped drives (net use)'

try {
    $netUse = & net.exe use 2>&1
    foreach ($line in $netUse) {
        Add-Line $sb ("{0}" -f $line)
    }
} catch {
    Add-Line $sb "Failed to run 'net use'."
}

# ---------- Mapped drives (CIM Win32_LogicalDisk) ----------
Add-Section $sb 'Mapped drives (CIM Win32_LogicalDisk)'

try {
	$ld = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=4" -ErrorAction Stop
	if (-not $ld) {
		Add-Line $sb "No network drives found via Win32_LogicalDisk."
	} else {
		foreach ($d in $ld) {
			$prov = if ($d.ProviderName) { $d.ProviderName } else { '' }
			$fs   = if ($d.FileSystem)   { $d.FileSystem }   else { '' }
			$vol  = if ($d.VolumeName)   { $d.VolumeName }   else { '' }
			$line = ("Drive {0}: Provider={1} FileSystem={2} VolumeName={3}" -f $d.DeviceID, $prov, $fs, $vol)
			Add-Line $sb $line
		}
	}
} catch {
	Add-Line $sb "Failed to query Win32_LogicalDisk for network drives."
}

# ---------- NcDavTray mapping / branding checks ----------
Add-Section $sb 'NcDavTray mapping / branding checks'

if (-not $script:Configs -or $script:Configs.Count -eq 0) {
	Add-Line $sb "No NcDavTray configs collected; skipping branding checks."
} else {
	try {
		$mp2Exists = Test-Path -LiteralPath $RegMP2
		if (-not $mp2Exists) {
			Add-Line $sb ("MountPoints2 base key not found: {0}" -f $RegMP2)
		}

		$netDrives = @()
		try {
			$netDrives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=4" -ErrorAction Stop
		} catch {}

		foreach ($cfg in $script:Configs) {
			$server  = $cfg.Server
			$user    = $cfg.User
			$drive   = $cfg.Drive
			$subPath = $cfg.SubPath
			$label   = $cfg.Label
			$mappable = Test-ConfigMappable $cfg

			Add-Line $sb ("Config: Server={0} Kind={1} User={2} Drive={3} SubPath={4}" -f $server, $cfg.Kind, $user, $drive, $subPath)

			if ($mappable) {
				$unc = Build-Unc $cfg
				Add-Line $sb ("  Expected UNC: {0}" -f $unc)

				if ($netDrives -and $drive) {
					$match = $netDrives | Where-Object { $_.DeviceID -ieq $drive }
					if ($match) {
						$prov = $match.ProviderName
						Add-Line $sb ("  Drive provider: {0}" -f $prov)
						Add-Line $sb ("  Provider matches expected UNC: {0}" -f ([string]::Equals($prov, $unc, 'OrdinalIgnoreCase')))
					} else {
						Add-Line $sb ("  Network drive {0} not found in Win32_LogicalDisk." -f $drive)
					}
				} else {
					Add-Line $sb "  Skipping UNC/provider check (no drive or no CIM data)."
				}
			} else {
				Add-Line $sb "  Skipping UNC/provider check (config incomplete for its kind)."
			}

			if ($mp2Exists -and $mappable -and $label) {
				$names = Build-Mp2Names $cfg

				$labelOk = $false
				foreach ($name in $names) {
					$p = Join-Path $RegMP2 $name
					if (Test-Path -LiteralPath $p) {
						try {
							$val = (Get-ItemProperty -LiteralPath $p -ErrorAction Stop).'_LabelFromReg'
							if ($val) {
								Add-Line $sb ("  MountPoints2: {0} -> _LabelFromReg = {1}" -f $name, $val)
								if ($val -eq $label) { $labelOk = $true }
							} else {
								Add-Line $sb ("  MountPoints2: {0} present but _LabelFromReg is empty or missing." -f $name)
							}
						} catch {
							Add-Line $sb ("  MountPoints2: failed to read {0}" -f $name)
						}
						$s = $p + '#'
						if (Test-Path -LiteralPath $s) {
							try {
								$val2 = (Get-ItemProperty -LiteralPath $s -ErrorAction Stop).'_LabelFromReg'
								if ($val2) {
									Add-Line $sb ("  MountPoints2: {0} -> _LabelFromReg = {1}" -f ($name + '#'), $val2)
									if ($val2 -eq $label) { $labelOk = $true }
								}
							} catch {}
						}
					}
				}
				Add-Line $sb ("  Label matches config.Label: {0}" -f $labelOk)
			} else {
				Add-Line $sb "  Skipping MountPoints2 label check (missing key, incomplete config or no label)."
			}
			# Explorer drive icon branding (HKCU\Software\Classes\Applications\Explorer.exe\Drives\<X>\DefaultIcon)
			if ($drive -and $drive -match '^[A-Za-z]:$') {
				$dl          = $drive.Substring(0,1).ToUpper()
				$iconRelKey  = "Software\Classes\Applications\Explorer.exe\Drives\$dl\DefaultIcon"
				$iconRegPath = "HKCU:\$iconRelKey"

				$iconVal       = $null
				$iconFilePath  = $null
				$iconFileExist = $false

				try {
					$cu  = [Microsoft.Win32.Registry]::CurrentUser
					$def = $cu.OpenSubKey($iconRelKey, $false)
					if ($def -ne $null) {
						$iconVal = $def.GetValue('')
						$def.Close()
					}
				} catch {}

				if (-not $iconVal) {
					Add-Line $sb ("  Drive icon key {0} present: False" -f $iconRegPath)
				} else {
					Add-Line $sb ("  Drive icon key {0} present: True" -f $iconRegPath)
					Add-Line $sb ("  Drive icon raw value: {0}" -f $iconVal)

					# Extract file path part from "<path>, index"
					$iconFilePath = $iconVal
					if ($iconFilePath -match '^(.*?),\s*\d+\s*$') {
						$iconFilePath = $matches[1]
					}
					$iconFileExist = Test-Path -LiteralPath $iconFilePath
					Add-Line $sb ("  Drive icon file path: {0}" -f $iconFilePath)
					Add-Line $sb ("  Drive icon file exists: {0}" -f $iconFileExist)

					# Check whether icon path is under NcDavTray folder (installed or portable)
					$baseDir = $null
					if ($mode -eq '1') {
						$baseDir = $InstallDir
					} elseif ($mode -eq '2') {
						$baseDir = $portableRoot
					}

					if ($baseDir -and (Test-Path -LiteralPath $baseDir) -and $iconFileExist) {
						try {
							$baseResolved = (Resolve-Path -LiteralPath $baseDir).Path
							$iconResolved = (Resolve-Path -LiteralPath $iconFilePath -ErrorAction SilentlyContinue).Path
							if ($baseResolved -and $iconResolved) {
								$underBase = $iconResolved.StartsWith($baseResolved, [System.StringComparison]::OrdinalIgnoreCase)
								Add-Line $sb ("  Drive icon located under NcDavTray folder: {0}" -f $underBase)
							}
						} catch {}
					}
				}
			} else {
				Add-Line $sb "  Drive icon branding check skipped (no valid drive letter)."
			}
		}
	} catch {
		Add-Line $sb "Failed to run NcDavTray mapping / branding checks."
	}
}

# ---------- Optional UI / font / DPI environment ----------
Add-Section $sb 'Optional UI / font / DPI environment'

Write-Host ""
Write-Host "Optional: You can collect UI / font / DPI diagnostics (for layout / font issues)." -ForegroundColor Yellow
$doUi = Read-Host "Collect UI / font / DPI diagnostics? [y/N]"

if ($doUi -match '^[Yy]') {
	try {
		Add-Type -AssemblyName System.Drawing -ErrorAction Stop
	} catch {
		Add-Line $sb "UI probe: failed to load System.Drawing; runtime font checks will be limited."
	}

	try {
		$acc   = Get-ItemProperty 'HKCU:\Software\Microsoft\Accessibility' -ErrorAction SilentlyContinue
		$hc    = Get-ItemProperty 'HKCU:\Control Panel\Accessibility\HighContrast' -ErrorAction SilentlyContinue
		$desk  = Get-ItemProperty 'HKCU:\Control Panel\Desktop' -ErrorAction SilentlyContinue
		$sub   = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes' -ErrorAction SilentlyContinue
		$reg   = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts'           -ErrorAction SilentlyContinue

		$installed = $null
		try {
			$installed = [System.Drawing.Text.InstalledFontCollection]::new().Families | Select-Object -Expand Name
		} catch {}

		$tahomaFiles = Get-ChildItem 'C:\Windows\Fonts\tahoma*' -ErrorAction SilentlyContinue |
		               Select-Object -Expand Name

		$textScale = "100% (default)"
		if ($acc -and $acc.PSObject.Properties.Name -contains 'TextScaleFactor' -and $acc.TextScaleFactor) {
			$textScale = ("{0}%" -f $acc.TextScaleFactor)
		}

		$hcFlags = if ($hc -and $hc.PSObject.Properties.Name -contains 'Flags') { $hc.Flags } else { '<not set>' }

		$dpiLogPixels = '<not set>'
		if ($desk -and $desk.PSObject.Properties.Name -contains 'LogPixels' -and $desk.LogPixels) {
			$dpiLogPixels = $desk.LogPixels
		}

		$probeTahoma = $null
		$probeShell2 = $null
		try {
			$probeTahoma = (New-Object System.Drawing.Font('Tahoma', 9)).Name
			$probeShell2 = (New-Object System.Drawing.Font('MS Shell Dlg 2', 9)).Name
		} catch {}

		$uiReport = [ordered]@{}
		$uiReport['Text_Size_Percent']        = $textScale
		$uiReport['HighContrast_Flags']       = $hcFlags
		$uiReport['Desktop_DPI_LogPixels']    = $dpiLogPixels

		$uiReport['FontSub_MS_Shell_Dlg']   = Get-FontMapValue -Substitutes $sub -Name 'MS Shell Dlg'
		$uiReport['FontSub_MS_Shell_Dlg_2'] = Get-FontMapValue -Substitutes $sub -Name 'MS Shell Dlg 2'
		$uiReport['FontSub_Tahoma']         = Get-FontMapValue -Substitutes $sub -Name 'Tahoma'

		$uiReport['Reg_Tahoma_Regular'] = Get-FontRegValue -FontReg $reg -Name 'Tahoma (TrueType)'
		$uiReport['Reg_Tahoma_Bold']    = Get-FontRegValue -FontReg $reg -Name 'Tahoma Bold (TrueType)'

		if ($installed) {
			$uiReport['Installed_Tahoma']        = ($installed -contains 'Tahoma')
			$uiReport['Installed_MSSansSerif']   = ($installed -contains 'Microsoft Sans Serif')
			$uiReport['Installed_SegoeUI']       = ($installed -contains 'Segoe UI')
		} else {
			$uiReport['Installed_Fonts_Probe']   = '<failed to enumerate runtime fonts>'
		}

		if ($probeTahoma) { $uiReport['Probe_Tahoma_Runtime']    = $probeTahoma }
		if ($probeShell2) { $uiReport['Probe_ShellDlg2_Runtime'] = $probeShell2 }

		if ($tahomaFiles -and $tahomaFiles.Count -gt 0) {
			$uiReport['Tahoma_FontFiles_OnDisk'] = ($tahomaFiles -join '; ')
		} else {
			$uiReport['Tahoma_FontFiles_OnDisk'] = '<none found>'
		}

		foreach ($entry in $uiReport.GetEnumerator()) {
			Add-Line $sb ("{0}: {1}" -f $entry.Key, $entry.Value)
		}
	} catch {
		Add-Line $sb "UI probe: failed to collect UI / font / DPI diagnostics."
	}
} else {
	Add-Line $sb "UI / font / DPI diagnostics: skipped by user."
}

# ---------- System event log (WebClient / MRxDAV) ----------
Add-Section $sb 'System event log (WebClient / MRxDAV)'

try {
	$events = Get-WinEvent -LogName System -MaxEvents 300 -ErrorAction Stop |
			  Where-Object {
				  $_.ProviderName -like '*WebClient*' -or
				  $_.ProviderName -like '*WebDav*'   -or
				  $_.ProviderName -like '*MRxDAV*'
			  } |
			  Select-Object -First 50

	if (-not $events) {
		Add-Line $sb "No recent WebClient / MRxDAV events found in System log."
	} else {
		foreach ($e in $events) {
			$msg = $e.Message
			if ($msg.Length -gt 300) { $msg = $msg.Substring(0,300) + ' ...' }
			$msg = ($msg -replace '\s+', ' ')
			Add-Line $sb ("[{0:yyyy-MM-dd HH:mm:ss}] {1} Id={2} Level={3} - {4}" -f $e.TimeCreated, $e.ProviderName, $e.Id, $e.LevelDisplayName, $msg)
		}
	}
} catch {
	Add-Line $sb "Failed to read System event log for WebClient / MRxDAV."
}

# ---------- Optional HTTP connectivity test ----------
Add-Section $sb 'Optional HTTP connectivity test (no credentials)'

Write-Host ""
Write-Host "Optional: You can test plain HTTPS reachability of your Nextcloud server." -ForegroundColor Yellow
Write-Host "The server host will NOT be written to the report."

$doHttp = Read-Host "Run HTTP test? [y/N]"
if ($doHttp -match '^[Yy]') {
	$httpHost = $null

	if ($script:KnownHosts -and $script:KnownHosts.Count -gt 0) {
		# Use first host from NcDavTray config
		$httpHost = $script:KnownHosts[0]
		Write-Host "Using Nextcloud host from NcDavTray config (hidden in report)." -ForegroundColor Cyan
	} else {
		# Fallback: ask user
		$httpHost = Read-Host "Enter Nextcloud server address without https:// (e.g. cloud.example.com or cloud.example.com/nextcloud)"
	}

	if (-not [string]::IsNullOrWhiteSpace($httpHost)) {
		try {
			$uri = "https://$httpHost/status.php"
			$sw  = [System.Diagnostics.Stopwatch]::StartNew()
			$resp = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 10
			$sw.Stop()

			$status = if ($resp -and $resp.StatusCode) { [int]$resp.StatusCode } else { '<none>' }

			Add-Line $sb "HTTP test: enabled"
			if ($script:KnownHosts -and $script:KnownHosts.Count -gt 0) {
				Add-Line $sb "  Target: /status.php on NcDavTray-configured host (hidden in report)"
			} else {
				Add-Line $sb "  Target: /status.php on user-supplied host (hidden in report)"
			}
			Add-Line $sb ("  StatusCode: {0}" -f $status)
			Add-Line $sb ("  Elapsed ms: {0}" -f $sw.ElapsedMilliseconds)
		} catch {
			Add-Line $sb "HTTP test: failed"
			Add-Line $sb ("  Error: {0}" -f $_.Exception.Message)
		}
	} else {
		Add-Line $sb "HTTP test: skipped (no host entered)"
	}
} else {
	Add-Line $sb "HTTP test: skipped by user"
}

# ---------- Write report ----------
Add-Section $sb 'Output'

try {
	$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
	# Prefer script folder; fallback: current working directory
	$baseDir = $PSScriptRoot
	if (-not $baseDir) {
		$baseDir = (Get-Location).Path
	}

	$outFile = Join-Path $baseDir ("NcDavTray_diag_{0}.txt" -f $ts)
	$text = Mask-Report $sb.ToString()
	$text | Out-File -LiteralPath $outFile -Encoding UTF8
	Add-Line $sb ("Report file: {0}" -f $outFile)
} catch {
	Add-Line $sb "Failed to write report file; dumping to console only."
	$outFile = $null
}

Write-Host ""
if ($outFile) {
	Write-Host "Diagnostics finished." -ForegroundColor Green
	Write-Host ("Report saved to: {0}" -f $outFile)
	Write-Host "Use this diagnostics report when you create an issue on GitHub."
} else {
	Write-Host "Diagnostics finished, but could not write the report file." -ForegroundColor Yellow
	Write-Host "Below is the output:"
	Write-Host ""
	Write-Output (Mask-Report $sb.ToString())
}
