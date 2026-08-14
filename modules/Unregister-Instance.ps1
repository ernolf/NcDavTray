# Takes this process out of the shared list on its way down. Without it the
# entry would linger until the next reader prunes it, and until then anything
# that waits for the last instance to go would wait for a process that is
# already gone. An empty -Role removes every role this PID holds.
function Unregister-Instance {
	[CmdletBinding()] param(
		[int]$ProcessId = $PID,
		[string]$Role = ''
	)
	Write-Verbose ("[Instances] Unregister-Instance: Pid={0}, Role={1}" -f $ProcessId, $Role)
	$entries = Read-InstanceEntries
	if (-not $entries -or $entries.Count -eq 0) { return }
	$kept = @()
	foreach ($e in $entries) {
		[int]$pidValue = 0; try { $pidValue = [int]$e.Pid } catch { $pidValue = 0 }
		if ($pidValue -eq $ProcessId -and ([string]::IsNullOrEmpty($Role) -or [string]$e.Role -eq $Role)) { continue }
		$kept += $e
	}
	if ($kept.Count -ne $entries.Count) { Write-InstanceEntries $kept }
}
