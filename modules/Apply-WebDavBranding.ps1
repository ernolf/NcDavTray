function Apply-WebDavBranding {
	# Apply label (MountPoints2) and icon (HKCU per-drive). No DavWWWRoot, no MP2 icon writes.
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	if ([string]::IsNullOrWhiteSpace($Spec.Server) -or [string]::IsNullOrWhiteSpace((Get-MountIdentity $Spec)) -or -not (Test-ValidDrive $Spec.Drive)) { return }
	# Ensure .ico file exists locally; fetch immediately if missing. Always fetch for
	# this server: $script:ServerFaviconBmp holds whichever server the UI looked at
	# last, so writing it here would give one server's icon to another.
	$icoPath = Get-FavIconFilePath $Spec.Server
	if (-not (Test-Path -LiteralPath $icoPath)) { [void](Fetch-ServerFavicon $Spec.Server) }
	# Apply label via MountPoints2 (this is what Explorer honors for WebDAV name)
	try { Set-MP2LabelExactExact $Spec } catch {}
	# Apply icon via HKCU per-drive override (reliable for mapped letters)
	try { Set-DriveIconHKCU -DriveLetter $Spec.Drive -IconPath $icoPath } catch {}
	try { Refresh-ShellIcons } catch {}
}
