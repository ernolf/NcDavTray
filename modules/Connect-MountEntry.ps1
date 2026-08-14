# One mount, both server identities. Windows holds one set of credentials per
# server identity and a host offers exactly two of them -- with and without the
# explicit port -- so 1219 only says that the one this entry asks for is taken,
# not that the mount is impossible. The other one has to be tried before anything
# reports a failure, which is why this sits between the callers and Map-MountEntry
# rather than in one of them: the poll and the menu owe the user the same answer.
# The flip is persisted only where it worked. With both identities spoken for the
# entry keeps the one it came with, so a poll tick leaves the configuration alone.
function Connect-MountEntry {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Entry, [ref]$LastError )
	[int]$rc = 0
	$ok = Map-MountEntry -Entry $Entry -LastError ([ref]$rc)
	if (-not $ok -and $rc -eq 1219) {
		# The claim goes with the old identity: the other one is a different mount key.
		$oldSpec = New-MountSpecFromEntry $Entry
		try { Remove-MapMutex -Spec $oldSpec } catch {}
		try { Remove-DriveGuard -Drive $oldSpec.Drive } catch {}
		$Entry.ExplicitPort = -not [bool]$Entry.ExplicitPort
		$ok = Map-MountEntry -Entry $Entry -LastError ([ref]$rc)
		if ($ok) {
			Save-Config
		} else {
			$newSpec = New-MountSpecFromEntry $Entry
			try { Remove-MapMutex -Spec $newSpec } catch {}
			try { Remove-DriveGuard -Drive $newSpec.Drive } catch {}
			$Entry.ExplicitPort = -not [bool]$Entry.ExplicitPort
		}
	}
	if ($PSBoundParameters.ContainsKey('LastError')) { $LastError.Value = $rc }
	return $ok
}