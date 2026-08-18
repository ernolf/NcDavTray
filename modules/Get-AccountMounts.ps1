# Every mount that signs in as one server/user pair. The password, the login and
# the identity Windows keys its session on all belong to the pair rather than to
# the single mount, so anything that changes one of them has to see them all.
# Callers wrap the result in @() -- see Read-MountEntriesFromRegistry for why the
# comma that would keep a one-entry list from unrolling is not the answer here.
function Get-AccountMounts {
	[CmdletBinding()] param( [Parameter(Mandatory)][AllowEmptyString()][string]$Server, [Parameter(Mandatory)][AllowEmptyString()][string]$User )
	$out = @()
	if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($User)) { return $out }
	$srv = ([string]$Server).Trim()
	$usr = ([string]$User).Trim()
	foreach ($e in @($State.Mounts)) {
		if (-not $e) { continue }
		if ([string]$e.Kind -ne 'account') { continue }
		if (([string]$e.Server).Trim() -ne $srv) { continue }
		if (([string]$e.User).Trim() -cne $usr) { continue }
		$out += $e
	}
	return $out
}
