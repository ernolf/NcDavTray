# The plain password of one mount, or an empty string when it has none. An account
# always has one to be found, a share only where the user asked for it to be kept.
# Whether the blob can be unwrapped at all is DPAPI's decision, and one written by
# another user or on another machine simply fails here.
function Unprotect-MountSecret {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Entry )
	$enc = Get-AccountSecret -Server $Entry.Server -User (Get-MountSecretName $Entry)
	if ([string]::IsNullOrEmpty($enc)) { return '' }
	try {
		$sec = ConvertTo-SecureString $enc
		return (New-Object System.Net.NetworkCredential('', $sec)).Password
	} catch { return '' }
}