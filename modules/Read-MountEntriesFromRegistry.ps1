# The stored list, in the order the user arranged it. Order is a value of its own
# because subkeys come back sorted by name, and an Id sorts by nothing anybody
# chose. An entry that cannot be read is skipped rather than guessed at: one
# damaged subkey must not cost the user the other mounts.
# Callers wrap the result in @(). The comma that would keep a one-entry list from
# unrolling turns an empty one into a list of one empty item, and a caller asking
# whether anything is stored would be told yes.
function Read-MountEntriesFromRegistry {
	$root = Get-MountsRegPath
	if (-not (Test-Path -LiteralPath $root)) { return @() }
	$rows = @()
	foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
		try {
			$props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
			$entry = ConvertTo-MountEntry $props
			$entry.Id = $key.PSChildName
			$order = 0
			if ($props.PSObject.Properties.Name -contains 'Order') { $order = [int]$props.Order }
			$rows += [pscustomobject]@{ Order = $order; Entry = $entry }
		} catch {}
	}
	return @($rows | Sort-Object Order | ForEach-Object { $_.Entry })
}