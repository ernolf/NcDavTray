# Writes one mount without touching any other. An existing subkey is written into
# rather than replaced: the place the entry holds in the list sits in it, and that
# is not part of what a caller with an entry in hand is writing.
# Order is the list's business, not the entry's: a program that writes only its
# own entry appends once and afterwards keeps the place the list gave it.
function Write-MountEntry {
	[CmdletBinding()] param(
		[Parameter(Mandatory)][psobject]$Entry,
		[int]$Order = -1
	)
	$root = Get-MountsRegPath
	if (-not (Test-Path -LiteralPath $root)) { New-Item -Path $root -Force | Out-Null }
	$path = Join-Path $root $Entry.Id
	$hasOrder = $false
	if (Test-Path -LiteralPath $path) {
		try { $hasOrder = ((Get-ItemProperty -LiteralPath $path -ErrorAction Stop).PSObject.Properties.Name -contains 'Order') } catch {}
	} else {
		New-Item -Path $path -Force | Out-Null
	}
	foreach ($name in @('Server', 'Kind', 'User', 'Token', 'SubPath', 'Drive', 'Label')) {
		New-ItemProperty -LiteralPath $path -Name $name -Value ([string]$Entry.$name) -PropertyType String -Force | Out-Null
	}
	foreach ($name in @('ExplicitPort', 'Enabled')) {
		New-ItemProperty -LiteralPath $path -Name $name -Value ([int][bool]$Entry.$name) -PropertyType DWord -Force | Out-Null
	}
	if ($Order -lt 0) {
		if ($hasOrder) { return }
		$used = @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
			try { [int](Get-ItemProperty -LiteralPath $_.PSPath -Name 'Order' -ErrorAction Stop).Order } catch { -1 }
		})
		$Order = 0
		if ($used.Count -gt 0) { $Order = ((($used | Measure-Object -Maximum).Maximum) + 1) }
	}
	New-ItemProperty -LiteralPath $path -Name 'Order' -Value $Order -PropertyType DWord -Force | Out-Null
}