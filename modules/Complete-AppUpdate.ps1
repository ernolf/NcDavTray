# Writes the downloaded copy over the one that asked for it and starts it again.
# This runs in the new copy and never in the one being replaced -- see
# Start-UpdateHandover for why it has to be that way round.
# Replaced is the program and nothing else: an installed copy keeps its mounts and
# its passwords in the registry, a portable folder keeps the two files it carries.
# Neither is part of a release. Autostart and the shortcuts are left alone too --
# an update is not an install, and a setting the user switched off does not come
# back because a new version arrived.
function Complete-AppUpdate {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Target, [int]$WaitForPid = 0 )
	if (-not (Test-Path -LiteralPath $Target -PathType Container)) { return $false }
	# The copy that handed over is still winding its drives down, and it holds the
	# single-instance lock until it is gone. A replacement started against that lock
	# exits without a word, so this waits for the process rather than for a timeout.
	if ($WaitForPid -gt 0) {
		$deadline = [DateTime]::UtcNow.AddSeconds(20)
		while ([DateTime]::UtcNow -lt $deadline) {
			$alive = $false
			try { $alive = -not (Get-Process -Id $WaitForPid -ErrorAction Stop).HasExited } catch { $alive = $false }
			if (-not $alive) { break }
			Start-Sleep -Milliseconds 250
		}
	}
	$installed = ($Target -ieq $InstallDir)
	# Whatever else is still running from the install folder -- a second window, or
	# the one that handed over and did not get all the way out.
	if ($installed) { [void](Stop-InstalledInstance -TimeoutSec 12 -ForceOnTimeout) }
	$dstPs1 = Join-Path $Target $ScriptFile
	try {
		Copy-Item -LiteralPath $PSCommandPath -Destination $dstPs1 -Force
		# Language packs are merged, never pruned: a pack put there by hand is not
		# ours to remove.
		$srcI18n = Join-Path $HereDir 'i18n'; $dstI18n = Join-Path $Target 'i18n'
		if (-not (Test-Path -LiteralPath $dstI18n)) { New-Item -ItemType Directory -Path $dstI18n -Force | Out-Null }
		if (Test-Path -LiteralPath $srcI18n) { Copy-Item -Path (Join-Path $srcI18n '*') -Destination $dstI18n -Recurse -Force }
	} catch { return $false }
	if ($installed) {
		# The file the shortcuts take their icon from, in case this release carries
		# another one. The shortcuts themselves are not rewritten.
		try { [System.IO.File]::WriteAllBytes((Join-Path $Target ("{0}.ico" -f $AppNameShort)), (Get-EmbeddedIconBytes)) } catch {}
		return [bool](Start-InstalledInstance)
	}
	try {
		Write-PortableLaunchers -Destination $Target -ScriptName $ScriptFile -SpdxFrom $dstPs1
		$exe, $args = Get-LauncherFor $dstPs1
		Start-Process -FilePath $exe -ArgumentList $args -WorkingDirectory $Target -WindowStyle Hidden | Out-Null
	} catch { return $false }
	return $true
}
