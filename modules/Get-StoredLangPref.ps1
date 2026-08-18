# The language an installation was set to, read on its own without loading a
# configuration. The installer actions run in a copy unpacked from the archive:
# it has no configuration of its own, and Load-Config would write a portable one
# into the folder the archive was unpacked into. Empty when nothing is stored --
# a first install has no preference yet, and the system language is the answer.
function Get-StoredLangPref {
	try {
		$base = Get-RegBase
		if (-not (Test-Path -LiteralPath $base)) { return '' }
		$p = Get-ItemProperty -LiteralPath $base -ErrorAction Stop
		if ($p.PSObject.Properties.Name -contains 'LangPref') { return [string]$p.LangPref }
	} catch {}
	return ''
}
