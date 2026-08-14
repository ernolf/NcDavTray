# Writes the whole list in the order it is given and drops the subkeys of mounts
# that are no longer in it. Write-MountEntry is for a single entry and leaves the
# rest of the store alone.
function Write-MountEntriesToRegistry {
	[CmdletBinding()] param(
		[Parameter(Mandatory)][AllowEmptyCollection()][psobject[]]$Entries
	)
	$root = Get-MountsRegPath
	if (-not (Test-Path -LiteralPath $root)) { New-Item -Path $root -Force | Out-Null }
	$keep = @{}
	$order = 0
	foreach ($entry in @($Entries)) {
		if (-not $entry) { continue }
		$keep[$entry.Id] = $true
		Write-MountEntry -Entry $entry -Order $order
		$order++
	}
	foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
		if (-not $keep.ContainsKey($key.PSChildName)) { try { Remove-Item -LiteralPath $key.PSPath -Recurse -Force } catch {} }
	}
}