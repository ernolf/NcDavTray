# The name a server/user pair is stored under. The host is folded to lower case
# because DNS makes no distinction there; the installation path and the account
# name are left as they are, because a directory on the server and a Nextcloud
# account both tell "Anna" and "anna" apart, and folding either here would hand
# one of them the other's password.
# The bar is safe as a separator: a value name may hold it, a hostname may not.
function Get-AccountKey {
	[CmdletBinding()] param( [Parameter(Mandatory)][AllowEmptyString()][string]$Server, [Parameter(Mandatory)][AllowEmptyString()][string]$User )
	return ('{0}|{1}' -f (Split-ServerString $Server).Key, ([string]$User).Trim())
}