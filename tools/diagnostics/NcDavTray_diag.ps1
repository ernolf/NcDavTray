# NcDavTray - WebDAV / WebClient diagnostics
# Read-only: collects environment info to debug "mapping failed" issues.
# No server names or passwords are written to the report.

# SPDX-FileCopyrightText: 2025 [ernolf] Raphael Gradenwitz <raphael.gradenwitz@googlemail.com>
# SPDX-License-Identifier: GPL-3.0-or-later


$AppName      = 'NcDavTray'
$AppNameShort = 'NDT' 
$HereDir      = Split-Path -Parent $PSCommandPath
$ScriptFile   = ("{0}.ps1" -f $AppNameShort)
$InstallDir   = Join-Path $env:LOCALAPPDATA $AppName
$InstallBin   = Join-Path $InstallDir $ScriptFile
$PortJson     = ("{0}_portable.json" -f $AppName)
$SecretPath   = ("{0}_secret.dat" -f $AppNameShort)
$RegBase      = ("HKCU:\Software\{0}" -f $AppName)
$RegMP2       = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2'
$RegWebClient = 'HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters'

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

function Add-Line {
	param(
		[System.Text.StringBuilder]$sb,
		[string]$text = ''
	)
	if ($script:Anonymize -and $text) {
		$text = Mask-InLine $text
	}
	[void]$sb.AppendLine($text)
}

function Add-Section {
	param(
		[System.Text.StringBuilder]$sb,
		[string]$title
	)
	Add-Line $sb ''
	Add-Line $sb ('===== {0} =====' -f $title)
}

function Get-NcDavTrayConfigsFromFolder {
	param(
		[string]$Folder
	)
	$result = @()
	if (-not (Test-Path $Folder)) { return $result }

	try {
		$jsonFiles = Get-ChildItem -Path $Folder -Filter '*.json' -ErrorAction SilentlyContinue
		foreach ($file in $jsonFiles) {
			try {
				$raw = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
				if ([string]::IsNullOrWhiteSpace($raw)) { continue }

				$cfg = $raw | ConvertFrom-Json -ErrorAction Stop
				if (-not $cfg) { continue }

				# Only treat JSON files as NcDavTray config if they have a non-empty Server field
				if (-not $cfg.Server) { continue }

				$driveVal = $cfg.Drive
				if (-not $driveVal) { $driveVal = $cfg.DriveLetter }

				$result += [PSCustomObject]@{
					Path    = $file.FullName
					Server  = $cfg.Server
					Drive   = $driveVal
					User    = $cfg.User
					SubPath = $cfg.SubPath
					Label   = $cfg.Label
				}
			} catch {
				# ignore malformed JSON or unexpected content
			}
		}
	} catch {
		# best-effort: return whatever we collected so far
	}

	return $result
}

function Normalize-SubPath([string]$sp) {
	if ([string]::IsNullOrWhiteSpace($sp) -or $sp -eq '/') { return '' }
	$sp = $sp.Trim().Trim('/', '\')
	if ($sp.Length -eq 0) { return '' }
	$parts = ($sp -split '[\\/]+') | Where-Object { $_ -ne '' }
	return ($parts -join '/')
}

function Build-Unc([string]$server, [string]$user, [string]$sub) {
	$norm   = Normalize-SubPath $sub
	$suffix = if ($norm) { '\' + ($norm -replace '/', '\') } else { '' }
	return "\\$server@ssl\remote.php\dav\files\$user$suffix"
}

function Mask-InLine {
	param([string]$line)
	if ([string]::IsNullOrEmpty($line)) { return $line }

	$masked = $line

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

	# Nextcloud host
	if ($script:KnownHosts -and $script:KnownHosts.Count -gt 0) {
		foreach ($h in $script:KnownHosts) {
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
		return (Read-Host "Enter portable folder (where *_portable.json and *_secret.dat live)")
	}

	$initial = $HOME
	if ([string]::IsNullOrWhiteSpace($initial)) { $initial = $env:USERPROFILE }
	if ([string]::IsNullOrWhiteSpace($initial)) {
		try { $initial = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile) } catch {}
	}

	$dlg = New-Object System.Windows.Forms.FolderBrowserDialog
	$dlg.Description        = "Select NcDavTray portable folder (where *_portable.json and *_secret.dat live)"
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
				$jsonFiles = Get-ChildItem -Path $InstallDir -Filter '*.json' -ErrorAction SilentlyContinue
				if ($jsonFiles) {
					Add-Line $sb ("Config JSON files: {0}" -f (($jsonFiles | Select-Object -Expand FullName) -join '; '))
				} else {
					Add-Line $sb "Config JSON files: none"
				}
				# Try to load NcDavTray configs and collect host / drive info (without leaking host names)
				$configs = Get-NcDavTrayConfigsFromFolder -Folder $InstallDir
				if ($configs -and $configs.Count -gt 0) {
					$script:Configs += $configs
					Add-Line $sb ("Configs with server info: {0}" -f $configs.Count)
					foreach ($cfg in $configs) {
						if ($cfg.Server) {
							$script:KnownHosts += $cfg.Server
							Add-Line $sb ("  Server: {0}" -f $cfg.Server)
						}
						if ($cfg.Drive) {
							$script:KnownDrives += $cfg.Drive
							Add-Line $sb ("  Drive: {0}" -f $cfg.Drive)
						}
						if ($cfg.User) {
							$script:KnownNcUsers += $cfg.User
						}
						if ($cfg.Label) {
							$script:KnownLabels += $cfg.Label
						}
					}
				} else {
					Add-Line $sb "Configs with server info: none"
				}
				# Installed mode: read config from registry (no secrets, no host leakage)
				try {
					if (Test-Path $RegBase) {
						$regCfg = Get-ItemProperty -Path $RegBase -ErrorAction Stop
						Add-Line $sb "Installed config found in registry."
						if ($regCfg.PSObject.Properties.Name -contains 'Server' -and $regCfg.Server) {
							$script:KnownHosts += $regCfg.Server
							Add-Line $sb ("  Server (registry): {0}" -f $regCfg.Server)
						} else {
							Add-Line $sb "  Server (registry): <not set>"
						}
						if ($regCfg.PSObject.Properties.Name -contains 'Drive' -and $regCfg.Drive) {
							$script:KnownDrives += $regCfg.Drive
							Add-Line $sb ("  Drive (registry): {0}" -f $regCfg.Drive)
						} else {
							Add-Line $sb "  Drive (registry): <not set>"
						}
						if ($regCfg.PSObject.Properties.Name -contains 'User' -and $regCfg.User) {
							$script:KnownNcUsers += $regCfg.User
						}
						if ($regCfg.PSObject.Properties.Name -contains 'Label' -and $regCfg.Label) {
							$script:KnownLabels += $regCfg.Label
						}
						$cfgObj = [PSCustomObject]@{
							Path    = ("Registry:{0}" -f $RegBase)
							Server  = $null
							Drive   = $null
							User    = $null
							SubPath = $null
							Label   = $null
						}
						if ($regCfg.PSObject.Properties.Name -contains 'Server')  { $cfgObj.Server  = $regCfg.Server }
						if ($regCfg.PSObject.Properties.Name -contains 'Drive')   { $cfgObj.Drive   = $regCfg.Drive }
						if ($regCfg.PSObject.Properties.Name -contains 'User')    { $cfgObj.User    = $regCfg.User }
						if ($regCfg.PSObject.Properties.Name -contains 'SubPath') { $cfgObj.SubPath = $regCfg.SubPath }
						if ($regCfg.PSObject.Properties.Name -contains 'Label')   { $cfgObj.Label   = $regCfg.Label }

						if ($cfgObj.Label) {
							$script:KnownLabels += $cfgObj.Label
						}
						if ($cfgObj.Server -or $cfgObj.Drive -or $cfgObj.User) {
							$script:Configs += $cfgObj
						}
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
			try {
				$portableJson = Get-ChildItem -Path $portableRoot -Filter $PortJson   -ErrorAction SilentlyContinue
				$secretFiles  = Get-ChildItem -Path $portableRoot -Filter $SecretPath -ErrorAction SilentlyContinue
				if ($portableJson) {
					Add-Line $sb ("Portable config JSON: {0}" -f (($portableJson | Select-Object -Expand FullName) -join '; '))
				} else {
					Add-Line $sb "Portable config JSON: none"
				}
				if ($secretFiles) {
					Add-Line $sb ("Secret data files: {0}" -f (($secretFiles | Select-Object -Expand FullName) -join '; '))
				} else {
					Add-Line $sb "Secret data files: none"
				}
			} catch {
				Add-Line $sb "Failed to inspect portable folder."
			}

			# Load NcDavTray portable config(s) from *_portable.json (exact schema as shown)
			$portableConfigs = @()
			if ($portableJson) {
				foreach ($file in $portableJson) {
					try {
						$raw = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
						if ([string]::IsNullOrWhiteSpace($raw)) { continue }

						$cfg = $raw | ConvertFrom-Json -ErrorAction Stop
						if (-not $cfg) { continue }

						# Expecting keys: SubPath, Server, Label, LangPref, IntervalS, Drive, User
						if (-not $cfg.Server) { continue }

						$driveVal = $cfg.Drive
						if (-not $driveVal -and $cfg.PSObject.Properties.Name -contains 'DriveLetter') {
							$driveVal = $cfg.DriveLetter
						}

						$portableConfigs += [PSCustomObject]@{
							Path    = $file.FullName
							Server  = $cfg.Server
							Drive   = $driveVal
							User    = $cfg.User
							SubPath = $cfg.SubPath
							Label   = $cfg.Label
						}
					} catch {
						# ignore malformed JSON
					}
				}
			}

			if ($portableConfigs -and $portableConfigs.Count -gt 0) {
				$script:Configs += $portableConfigs
				Add-Line $sb ("Configs with server info: {0}" -f $portableConfigs.Count)
				foreach ($cfg in $portableConfigs) {
					if ($cfg.Server) {
						$script:KnownHosts += $cfg.Server
						Add-Line $sb ("  Server: {0}" -f $cfg.Server)
					}
					if ($cfg.Drive) {
						$script:KnownDrives += $cfg.Drive
						Add-Line $sb ("  Drive: {0}" -f $cfg.Drive)
					}
					if ($cfg.User) {
						$script:KnownNcUsers += $cfg.User
					}
					if ($cfg.Label) {
						$script:KnownLabels += $cfg.Label
					}
				}
			} else {
				Add-Line $sb "Configs with server info: none"
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

			Add-Line $sb ("Config: Server={0} User={1} Drive={2} SubPath={3}" -f $server, $user, $drive, $subPath)

			if ($server -and $user) {
				$unc = Build-Unc $server $user $subPath
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
				Add-Line $sb "  Skipping UNC/provider check (missing server or user)."
			}

			if ($mp2Exists -and $server -and $user -and $label) {
				$norm  = Normalize-SubPath $subPath
				$frag  = if ($norm) { '#' + ($norm -replace '/', '#') } else { '' }
				$names = @(
					"##$server@ssl#remote.php#dav#files#$user$frag",
					"##$server@ssl#DavWWWRoot#remote.php#dav#files#$user$frag"
				)

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
				Add-Line $sb "  Skipping MountPoints2 label check (missing key, server, user or label)."
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
		$httpHost = Read-Host "Enter Nextcloud server host only (e.g. cloud.example.com)"
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
	$text = $sb.ToString()
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
	Write-Host "Below is the raw output:"
	Write-Host ""
	Write-Output ($sb.ToString())
}
