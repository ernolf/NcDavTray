<# Simple translation lookup by key with optional named placeholders.
 - Looks up from Current (override) first, then Fallback.
 - If missing, returns the key itself.
 - Named replacements: T 'greet' @{ name = 'Alice' } with JSON { "greet": "Hello {name}!" } #>
function global:T([string]$Key, [hashtable]$Vars) {
	$text = if ($script:I18N.Current.ContainsKey($Key)) { $script:I18N.Current[$Key] } elseif ($script:I18N.Fallback.ContainsKey($Key)) { $script:I18N.Fallback[$Key] } else { return $Key }
	if ($Vars) { foreach($k in $Vars.Keys) { $text = $text.Replace('{'+[string]$k+'}', [string]$Vars[$k]) } }
	return $text
}
