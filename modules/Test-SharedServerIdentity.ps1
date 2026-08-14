# Whether this mount can ride on a connection that is already up. Windows keeps
# one login per server identity, and a mount presenting the login an existing
# connection already carries joins that connection instead of needing a place of
# its own -- error 1219 is about a second, different login, not about a second
# drive on the same one.
# The same means: same host, same port variant, same kind and same identity. Those
# four decide the login and the password together, and anything less than all four
# is a different connection.
# HeldBy names the drives that hold the identities in question, so an entry that is
# merely configured counts for nothing -- there has to be a connection to join.
function Test-SharedServerIdentity {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][psobject]$Entry,
		[Parameter(Mandatory)][AllowEmptyCollection()][psobject[]]$Others,
		[Parameter(Mandatory)][AllowEmptyCollection()][string[]]$HeldBy
	)
	$held = @{}
	foreach ($d in @($HeldBy)) { if ($d) { $held[([string]$d).ToUpperInvariant()] = $true } }
	foreach ($o in @($Others)) {
		if (-not $o -or ([string]$o.Id -eq [string]$Entry.Id)) { continue }
		if ([string]$o.Server -ne [string]$Entry.Server) { continue }
		if ([bool]$o.ExplicitPort -ne [bool]$Entry.ExplicitPort) { continue }
		if ([string]$o.Kind -ne [string]$Entry.Kind) { continue }
		if ((Get-MountIdentity -Spec $o) -ne (Get-MountIdentity -Spec $Entry)) { continue }
		if ($held.ContainsKey(([string]$o.Drive).ToUpperInvariant())) { return $true }
	}
	return $false
}