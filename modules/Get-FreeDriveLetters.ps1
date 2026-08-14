# Drive letters that are neither in use on this machine nor already spoken for by
# a configured mount. Counted down from Z, because that is the end users reach
# for and the low letters belong to hardware.
# Callers wrap the result in @(). The comma that would keep a one-letter list from
# unrolling turns an empty one into a list of one empty item, and a caller asking
# whether anything is still free would be told yes.
function Get-FreeDriveLetters {
	[CmdletBinding()] param( [string[]]$Exclude = @() )
	$used = @{}
	foreach ($d in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
		if ($d.Name.Length -eq 1) { $used[$d.Name.ToUpperInvariant()] = $true }
	}
	foreach ($x in @($Exclude)) {
		if (-not [string]::IsNullOrWhiteSpace($x)) { $used[$x.Substring(0, 1).ToUpperInvariant()] = $true }
	}
	$free = @()
	foreach ($c in [char[]]'ZYXWVUTSRQPONMLKJIHGFED') {
		if (-not $used.ContainsKey([string]$c)) { $free += ('{0}:' -f $c) }
	}
	return @($free)
}
