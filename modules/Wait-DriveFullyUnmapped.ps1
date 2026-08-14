function Wait-DriveFullyUnmapped {
	[CmdletBinding()] param( [string]$Drive, [int]$TimeoutMs = 3000 )
	if (-not (Test-ValidDrive $Drive)) { return $true }
	# Initial cool-down to let Mini-Redirector tear down
	Start-Sleep -Milliseconds 1000
	$sw = [System.Diagnostics.Stopwatch]::StartNew()
	while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
		$exists = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { ('{0}:' -f $_.Name) -ieq $Drive } | Select-Object -First 1
		if (-not $exists) { return $true }; Start-Sleep -Milliseconds 150
	}
	return $false
}
