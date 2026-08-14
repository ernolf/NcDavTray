# Brings the installed instances down before the installer writes over the script
# they are running. A window cannot be asked politely from outside, so the stop is
# a stop; the wait is there because a process needs a moment to let go of its
# drives, and the force is for the one that does not.
# Reports whether the install folder is clear.
function Stop-InstalledInstance {
	[CmdletBinding()] param( [int]$TimeoutSec = 12, [switch]$ForceOnTimeout )
	$procs = @(Get-RunningInstalledMain)
	if ($procs.Count -eq 0) { return $true }
	foreach ($p in $procs) { try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -ErrorAction SilentlyContinue } } catch {} }
	$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
	while ([DateTime]::UtcNow -lt $deadline) {
		$alive = @()
		foreach ($p in $procs) { try { $p.Refresh(); if (-not $p.HasExited) { $alive += $p } } catch {} }
		if ($alive.Count -eq 0) { break }
		Start-Sleep -Milliseconds 300
	}
	$still = @()
	foreach ($p in $procs) { try { $p.Refresh(); if (-not $p.HasExited) { $still += $p } } catch {} }
	if ($still.Count -gt 0 -and $ForceOnTimeout) {
		foreach ($p in $still) { try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {} }
	}
	$rem = @()
	foreach ($p in $procs) { try { $p.Refresh(); if (-not $p.HasExited) { $rem += $p } } catch {} }
	return ($rem.Count -eq 0)
}