# Claims the mount so a second instance does not map the same target twice, and
# reports whether this process holds the claim. Claims are kept in $script:MapMutexes,
# one entry per mount, so a process can hold several at once. A claim is held until
# the mount is dropped from the configuration or the process exits, not merely
# while the drive is connected: a temporarily unreachable server must not let
# another instance take the mount over.
function Ensure-MapMutex {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	$name = Get-MapMutexName $Spec
	if (-not $script:MapMutexes.ContainsKey($name)) {
		$owned = $false
		$obj = New-Object System.Threading.Mutex($true, $name, [ref]$owned)
		$script:MapMutexes[$name] = [pscustomobject]@{ Obj = $obj; Owned = $owned }
	}
	return [bool]$script:MapMutexes[$name].Owned
}
