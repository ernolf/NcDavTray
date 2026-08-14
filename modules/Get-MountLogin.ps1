# The user name the endpoint expects in the Basic auth header. This is not the
# mount identity: a modern public share carries its token in the path and
# authenticates as 'anonymous', while the legacy endpoint carries the token in
# this field instead of in the path.
function Get-MountLogin {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	switch ($Spec.Kind) {
		'share' { return 'anonymous' }
		'share-legacy' { return $Spec.Token }
		default { return $Spec.User }
	}
}
