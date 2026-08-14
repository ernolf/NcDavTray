# Name of the system-wide claim on a mount. The prefix is the literal product
# name so the claim survives a rename of $AppName: an older copy still running
# has to see it.
function Get-MapMutexName {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	return 'Local\NcDavTray:map:{0}' -f (Get-MountKey $Spec)
}
