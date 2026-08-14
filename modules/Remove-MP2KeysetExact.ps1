# Delete the MP2 keys of one mount (and their trailing '#' siblings), both
# variants (with/without DavWWWRoot)
function Remove-MP2KeysetExact {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	foreach ($name in (Get-MP2KeyNames $Spec)) {
		$key = Join-Path $RegMP2 $name
		foreach ($p in @($key, ($key + '#'))) { try { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force } } catch {} }
	}
}
