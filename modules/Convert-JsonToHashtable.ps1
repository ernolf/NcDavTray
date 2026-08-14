function Convert-JsonToHashtable([string]$Json) {
	try { $o = $Json | ConvertFrom-Json } catch { return @{} }
	# Convert PSCustomObject to Hashtable (flat keys only expected)
	$ht = @{}; if ($o) { foreach($p in $o.PSObject.Properties) { $ht[$p.Name] = [string]$p.Value } }
	return $ht
}
