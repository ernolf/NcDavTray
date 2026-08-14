# The field that identifies the target of a mount: the account name for an
# account mount, the share token for a public share.
function Get-MountIdentity {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	if ($Spec.Kind -eq 'account') { return $Spec.User }
	return $Spec.Token
}
