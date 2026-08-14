# The stem every pack file shares, taken from the one function that builds the
# path so the two cannot disagree. Not derived from $AppNameShort any more: both
# deliverables read the same packs, and a name that changes with the program
# would give each of them a set of its own again.
function Get-I18nBaseName {
	$name = Split-Path -Leaf (Resolve-I18nFilePath 'en')
	return ($name -replace '\.en\.json$', '')
}
