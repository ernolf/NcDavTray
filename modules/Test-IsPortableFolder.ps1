# Helper: detect whether a folder already contains a portable package of the
# calling program. Anything it would write itself counts as a mark.
function Test-IsPortableFolder {
	[CmdletBinding()] param( [Parameter(Mandatory = $true)][string]$Path )
	try {
		if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $false }
		$items = Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue
		if (-not $items) { return $false }
		foreach ($it in $items) {
			$name = $it.Name
			if ($name -like ("Start {0}.cmd" -f $AppName)) { return $true }
			if ($name -ieq ("{0}.vbs" -f $AppNameShort)) { return $true }
			if ($name -ieq ("{0}_portable.json" -f $AppName)) { return $true }
			if ($name -ieq ("{0}_config.json" -f $AppNameShort)) { return $true }
			if ($name -ieq ("{0}_secret.dat" -f $AppNameShort)) { return $true }
			if ($name -ieq ("{0}.ps1" -f $AppNameShort)) { return $true }
		}
		return $false
	} catch { return $false }
}