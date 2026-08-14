# What to call this mount in a menu, a tooltip or a message. The label the user
# gave it wins; without one, an account is known by who it signs in as and a share
# only by its host, because a share token is not something anyone recognizes.
function Get-MountDisplayName([psobject]$Entry) {
	if (-not [string]::IsNullOrWhiteSpace($Entry.Label)) { return $Entry.Label }
	$server = [string]$Entry.Server
	if (($Entry.Kind -eq 'account') -and -not [string]::IsNullOrWhiteSpace($Entry.User)) {
		if ($server) { return ('{0}@{1}' -f $Entry.User, $server) }
		return [string]$Entry.User
	}
	if (-not [string]::IsNullOrWhiteSpace($server)) { return $server }
	return $Entry.Id.Substring(0, 8)
}