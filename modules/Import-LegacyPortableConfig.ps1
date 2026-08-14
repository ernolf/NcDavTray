# Up to 1.2.2 a portable copy kept its single account in <AppName>_portable.json
# beside the script, in the flat shape the registry held it in. It is read once,
# when this copy has no configuration of its own yet, and becomes the first entry
# of the list.
# The file is left where it is: an older copy started again from the same folder
# must still find its configuration.
# The password is not read here. It sits in <AppNameShort>_secret.dat, behind the
# passphrase this version asks for as well, and it is taken over on the way in --
# see Read-PortableSecretStore, which needs this list to already exist to know
# whose password it is holding.
# Returns whether anything was taken over.
function Import-LegacyPortableConfig {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Path )
	if (-not (Test-Path -LiteralPath $Path)) { return $false }
	$raw = $null
	try { $raw = Get-Content -Raw -Path $Path -Encoding UTF8 | ConvertFrom-Json } catch { return $false }
	if (-not $raw) { return $false }
	$entry = Convert-FlatAccountToMountEntry $raw
	if (-not $entry) { return $false }
	$have = $raw.PSObject.Properties.Name
	if ($have -contains 'IntervalS') { try { $State.IntervalS = [int]$raw.IntervalS } catch {} }
	if ($have -contains 'LangPref') { $State.LangPref = [string]$raw.LangPref }
	$State.Mounts = @($entry)
	return $true
}
