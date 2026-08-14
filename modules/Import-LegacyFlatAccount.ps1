# The single account of an installation before 2.0.0, as the first entry of the
# list that replaced it. IntervalS and LangPref are not touched: this version
# keeps them under the same names in the same key and reads them itself.
# The account values are removed once they have been read. Their absence is what
# says this has already happened -- no ledger, and no second copy of an account
# that would come back to life the day the list is emptied.
function Import-LegacyFlatAccount {
	$base = Get-RegBase
	if (-not (Test-Path -LiteralPath $base)) { return }
	$flat = $null
	try { $flat = Get-ItemProperty -LiteralPath $base -ErrorAction Stop } catch { return }
	$have = $flat.PSObject.Properties.Name
	if (-not ($have -contains 'Server')) { return }
	$entry = Convert-FlatAccountToMountEntry $flat
	# A list that is already there was written by this version, and the account it
	# describes is in it. The old values are cleared either way.
	if ($entry -and (@(Read-MountEntriesFromRegistry).Count -eq 0)) {
		Write-MountEntry -Entry $entry
		# Straight into the pair store, where a password belongs from here on. Putting
		# it in the mount first would only have to be undone.
		if ($have -contains 'EncPass') { Set-AccountSecret -Server $entry.Server -User $entry.User -EncPass ([string]$flat.EncPass) }
	}
	foreach ($n in @('Server', 'User', 'SubPath', 'Drive', 'Label', 'EncPass')) {
		try { Remove-ItemProperty -LiteralPath $base -Name $n -Force -ErrorAction SilentlyContinue } catch {}
	}
}
