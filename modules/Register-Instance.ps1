# Puts this process into the shared list, or refreshes what is already there.
# Pid and Role together identify an entry: one process can hold two roles, but
# never the same role twice. App and Path say which of the two deliverables is
# running and where it lives, which is what a reader needs to tell the instances
# apart without asking them.
function Register-Instance {
	[CmdletBinding()] param(
		[int]$ProcessId = $PID,
		[Parameter(Mandatory)][string]$Role,
		[string]$Tag = '',
		[string]$App = $AppNameShort,
		[string]$Path = (Get-ThisScriptPath)
	)
	Write-Verbose ("[Instances] Register-Instance: Pid={0}, Role={1}, App={2}, Tag={3}" -f $ProcessId, $Role, $App, $Tag)
	$entries = Get-AliveInstanceEntries; $filtered = @()
	foreach ($e in $entries) { [int]$pidValue = 0; try { $pidValue = [int]$e.Pid } catch { $pidValue = 0 }; if ($pidValue -eq $ProcessId -and [string]$e.Role -eq $Role) { continue }; $filtered += $e }
	$new = [pscustomobject]@{ Pid = $ProcessId; Role = $Role; Tag = $Tag; App = $App; Path = $Path; Started = ([DateTime]::UtcNow.ToString('o')) }
	$filtered += $new; Write-InstanceEntries $filtered
}
