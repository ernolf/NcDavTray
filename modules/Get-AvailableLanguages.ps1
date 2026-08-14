# The languages this copy actually has, read from the pack file names beside the
# script. The folder comes from Resolve-I18nFilePath rather than from a path
# built here, so the list can never name a language Initialize-I18n would then
# fail to load. 'en' is always in it: it is compiled in and needs no file.
function Get-AvailableLanguages {
	$dir = Split-Path -Parent (Resolve-I18nFilePath 'en')
	$base = Get-I18nBaseName
	$langs = @()
	try {
		if ($dir -and (Test-Path -LiteralPath $dir)) {
			$pattern = '^{0}\.([^.]+)\.json$' -f ([regex]::Escape($base))
			foreach ($f in (Get-ChildItem -LiteralPath $dir -Filter ("{0}.*.json" -f $base) -File -ErrorAction SilentlyContinue)) {
				$m = [regex]::Match($f.Name, $pattern)
				if ($m.Success) { $langs += $m.Groups[1].Value }
			}
		}
	} catch {}
	if ($langs -notcontains 'en') { $langs += 'en' }
	return @($langs | Sort-Object -Unique)
}
