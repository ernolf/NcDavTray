# Written to a sibling file and moved into place, so a reader never sees a half
# written list. Several instances write here without any lock between them; the
# move is what keeps the file consistent, and a lost update only costs one entry
# that the next Register-Instance puts back.
function Write-InstanceEntries([object[]]$entries) {
	$path = Get-InstanceListPath; $tmp = $path + '.tmp'
	try {
		Write-Verbose ("[Instances] Write-InstanceEntries: writing {0} entries" -f ($entries.Count))
		$json = $entries | ConvertTo-Json -Depth 4
		$json | Set-Content -LiteralPath $tmp -Encoding UTF8
		Move-Item -LiteralPath $tmp -Destination $path -Force
	} catch { Write-Verbose ("[Instances] Write-InstanceEntries: ERROR {0}" -f $_.Exception.Message); try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch {} }
}
