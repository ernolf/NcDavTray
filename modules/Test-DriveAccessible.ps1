# Whether the drive letter is connected to the target the spec describes and can
# actually be read. A letter that matches but does not answer counts as not
# accessible, which is what distinguishes a live mount from a stale one.
function Test-DriveAccessible {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	try {
		if (-not (Test-ValidDrive $Spec.Drive)) { return $false }
		if (-not (Test-DriveMatchesDesired $Spec)) { return $false }
		# One entry is enough to know the letter answers, and asking for one is a
		# single request where listing the root is every name and every attribute in
		# it, fetched over the WebDAV connection and dropped. This runs for every
		# mount on every poll and again for every row of the settings list.
		# A directory with nothing in it is still a directory that answered.
		$walk = [System.IO.Directory]::EnumerateFileSystemEntries(("{0}\" -f $Spec.Drive)).GetEnumerator()
		try { [void]$walk.MoveNext() } finally { $walk.Dispose() }
		return $true
	} catch { return $false }
}
