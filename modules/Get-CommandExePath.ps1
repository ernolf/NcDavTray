# The program out of a registered shell command. The value is a command line, not
# a path: quoted or not, with or without arguments behind it. Unquoted paths with
# a space in them are the reason this ends at the extension and not at the first
# blank -- 'C:\Program Files\...' would otherwise become 'C:\Program'.
function Get-CommandExePath([string]$Command) {
	if ([string]::IsNullOrWhiteSpace($Command)) { return '' }
	$c = $Command.Trim()
	if ($c.StartsWith('"')) {
		$end = $c.IndexOf('"', 1)
		if ($end -gt 1) { return $c.Substring(1, $end - 1) }
		return ''
	}
	$i = $c.IndexOf('.exe', [System.StringComparison]::OrdinalIgnoreCase)
	if ($i -gt 0) { return $c.Substring(0, $i + 4) }
	$sp = $c.IndexOf(' ')
	if ($sp -gt 0) { return $c.Substring(0, $sp) }
	return $c
}
