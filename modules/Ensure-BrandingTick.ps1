function Ensure-BrandingTick {
	# Idempotent, cheap; called from timer when drive is accessible.
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	try {
		# Ensure ICO exists; only download once if missing
		$icoPath = Get-FavIconFilePath $Spec.Server
		# Always fetch for this server rather than reusing $script:ServerFaviconBmp:
		# that cache holds whichever server the UI looked at last, which with several
		# mounts is not necessarily this one.
		if (-not (Test-Path -LiteralPath $icoPath)) { [void](Fetch-ServerFavicon $Spec.Server) }
		# Per-drive icon under HKCU\...\Explorer.exe\Drives\<X>\DefaultIcon
		if (-not (Test-DriveIconApplied -DriveLetter $Spec.Drive -IconPath $icoPath)) { Set-DriveIconHKCU -DriveLetter $Spec.Drive -IconPath $icoPath }
	} catch {}
	try {
		# MountPoints2 label (create canonical key if none exists)
		if (-not (Test-MP2LabelApplied $Spec)) { Set-MP2LabelExactExact $Spec }
	} catch {}
}
