# The name a mount is listed under, with its kind spelled out. An account and a
# share are two different things -- one signs in as a person and reaches
# everything that person has, the other opens the one folder somebody handed out
# -- and a list holding both has to say which is which. Both get their word, not
# only one of them: a name that stands there bare is read as a name, not as the
# absence of a marker.
function Get-MountEntryLabel {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Entry )
	$name = Get-MountDisplayName $Entry
	$key = if ($Entry.Kind -eq 'account') { 'label.kind_account' } else { 'label.kind_share' }
	return (T $key @{ name = $name })
}