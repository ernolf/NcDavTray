# Reads the list and drops every entry whose process is gone. An instance that
# was killed leaves its entry behind, so pruning on read is the only thing that
# keeps the list honest. The pruned list is written back only when something was
# actually dropped, to keep idle polling from touching the disk.
function Get-AliveInstanceEntries {
	$entries = Read-InstanceEntries
	if (-not $entries -or $entries.Count -eq 0) { Write-Verbose "[Instances] Get-AliveInstanceEntries: no entries"; return @() }
	$alive = @()
	foreach ($e in $entries) {
		[int]$pidValue = 0
		try { $pidValue = [int]$e.Pid } catch { $pidValue = 0 }
		if ($pidValue -le 0) { continue }
		try { $p = Get-Process -Id $pidValue -ErrorAction Stop; if (-not $p.HasExited) { $alive += $e } } catch { <# process dead, skip #> }
	}
	Write-Verbose ("[Instances] Get-AliveInstanceEntries: {0} alive of {1}" -f $alive.Count, $entries.Count)
	if ($alive.Count -ne $entries.Count) { Write-InstanceEntries $alive }
	return $alive
}
