# The login name an account of this server is already stored under, when it is the
# same account as the given user id -- '' when this server has no mount of it yet.
# A stored name that is the id needs nobody asked: no other account can carry it.
# Every other name on this server has to be asked about, because a login name says
# nothing about the id behind it, which is the whole reason this exists.
# The comparison is case sensitive throughout: Nextcloud tells "Anna" and "anna"
# apart, and folding them here would declare two accounts to be one.
function Find-AccountByUserId {
	[CmdletBinding()] param( [Parameter(Mandatory)][AllowEmptyString()][string]$Server, [Parameter(Mandatory)][AllowEmptyString()][string]$UserId )
	if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($UserId)) { return '' }
	$srv = ([string]$Server).Trim()
	$others = New-Object System.Collections.Generic.List[string]
	foreach ($e in @($State.Mounts)) {
		if (-not $e) { continue }
		if ([string]$e.Kind -ne 'account') { continue }
		if (([string]$e.Server).Trim() -ne $srv) { continue }
		$u = ([string]$e.User).Trim()
		if ([string]::IsNullOrWhiteSpace($u)) { continue }
		if ($u -ceq $UserId) { return $u }
		if (-not $others.Contains($u)) { [void]$others.Add($u) }
	}
	# One request per remaining name of this server, and only for names that have a
	# password to ask with. A name that turns out to belong to somebody else answers
	# with their id and is left alone.
	foreach ($u in $others) {
		$pass = Unprotect-MountSecret -Entry ([pscustomobject]@{ Server = $srv; Kind = 'account'; User = $u; Token = '' })
		if ([string]::IsNullOrEmpty($pass)) { continue }
		if ((Get-NcUserId -Server $srv -User $u -Pass $pass) -ceq $UserId) { return $u }
	}
	return ''
}
