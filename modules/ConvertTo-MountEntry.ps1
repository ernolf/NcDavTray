# Rebuilds an entry from a deserialized config object, field by field, so a file
# written by another version or edited by hand cannot inject unknown members and
# a missing field falls back to the constructor's default. An unusable value is
# dropped rather than repaired: an entry with an empty token simply never maps.
function ConvertTo-MountEntry {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Source )
	$have = $Source.PSObject.Properties.Name
	$e = New-MountEntry
	if (($have -contains 'Id') -and $Source.Id) { $e.Id = [string]$Source.Id }
	if ($have -contains 'Server') { $e.Server = [string]$Source.Server }
	if (($have -contains 'Kind') -and ($Source.Kind -in @('account', 'share', 'share-legacy'))) { $e.Kind = [string]$Source.Kind }
	if ($have -contains 'User') { $e.User = [string]$Source.User }
	if ($have -contains 'Token') { $e.Token = [string]$Source.Token }
	if ($have -contains 'SubPath') { $e.SubPath = [string]$Source.SubPath }
	if ($have -contains 'Drive') { $e.Drive = [string]$Source.Drive }
	if ($have -contains 'Label') { $e.Label = [string]$Source.Label }
	if ($have -contains 'ExplicitPort') { $e.ExplicitPort = [bool]$Source.ExplicitPort }
	if ($have -contains 'Enabled') { $e.Enabled = [bool]$Source.Enabled }
	return $e
}