# The name a mount's password is stored under, as the user part of the account
# key. An account is its own name, so every mount of a server/user pair keeps
# sharing the one password. A share is its token, prefixed: a token is a random
# string that could read like an account name, and the two must never end up
# pointing at the same stored password.
function Get-MountSecretName {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Entry )
	if ([string]$Entry.Kind -eq 'account') { return [string]$Entry.User }
	return ('s:{0}' -f [string]$Entry.Token)
}