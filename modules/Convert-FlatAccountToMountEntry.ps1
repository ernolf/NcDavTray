# The single account of the versions before 2.0.0, as one entry of the list that
# replaced it. Source is whatever held it: the flat registry values, or the
# portable json of an NDT copy -- both carry the same field names.
# ExplicitPort is off because that is the identity the old copy asked for. Taking
# the other one here would present Windows with a mount it has never seen, and
# the drive would lose the label and the icon it has been carrying.
function Convert-FlatAccountToMountEntry {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Source )
	$have = $Source.PSObject.Properties.Name
	$get = { param($name) if ($have -contains $name) { return [string]$Source.$name } return '' }
	$server = & $get 'Server'
	if ([string]::IsNullOrWhiteSpace($server)) { return $null }
	return (New-MountEntry -Server $server -Kind 'account' -User (& $get 'User') -SubPath (& $get 'SubPath') -Drive (& $get 'Drive') -Label (& $get 'Label') -ExplicitPort $false -Enabled $true)
}