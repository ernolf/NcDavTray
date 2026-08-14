# Optional explicit lang (e.g., 'de'); if omitted, pick from State.Language or UI culture.
function Initialize-I18n([string]$Lang) {
	# 1) build fallback (embedded English minimal safety net)
	$script:I18N.Fallback = Convert-JsonToHashtable $script:I18N_Embedded_En
	# 2) decide requested language. Priority: a) explicit param b) $State.LangPref
	#    (the stored choice) c) Windows UI culture (auto)
	$chosen = $null
	if ($Lang -and $Lang.Trim()) { $chosen = $Lang.Trim() }
	elseif ($State -and ($State.PSObject.Properties.Name -contains 'LangPref') -and $State.LangPref) { $chosen = [string]$State.LangPref }
	else { $chosen = Get-SystemLang2 }
	$script:I18N.Language = $chosen
	# 3) try to load external override file (NDTi18n.<lang>.json)
	$fp = Resolve-I18nFilePath $chosen
	$override = @{}
	if (Test-Path -LiteralPath $fp) { try { $override = Convert-JsonToHashtable (Get-Content -LiteralPath $fp -Raw -Encoding UTF8); $script:I18N.FilePath = $fp } catch { $override = @{}; $script:I18N.FilePath = $null } } else { $script:I18N.FilePath = $null }
	# 4) merge fallback + override
	$merged = @{}
	foreach ($k in $script:I18N.Fallback.Keys) { $merged[$k] = $script:I18N.Fallback[$k] }
	foreach ($k in $override.Keys) { $merged[$k] = $override[$k] }
	$script:I18N.Current = $merged
	Write-Verbose ("Initialize-I18n: lang = {0} override = {1}" -f $script:I18N.Language, $(if ($script:I18N.FilePath) {$script:I18N.FilePath} else {'<none>'}))
}
