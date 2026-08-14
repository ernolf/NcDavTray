# --- Robust script-path resolver (PS 5.1 safe) ---
function Get-ThisScriptPath {
	[CmdletBinding()] param( [string]$FallbackName = "$($AppNameShort).ps1" )
	try {
		# Prefer an explicit anchor if present and valid
		if ($script:ThisScriptPath -and (Test-Path -LiteralPath $script:ThisScriptPath)) { return (Resolve-Path -LiteralPath $script:ThisScriptPath).Path }
		# PSCommandPath is set in scripts
		if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) { return (Resolve-Path -LiteralPath $PSCommandPath).Path }
		# MyInvocation works in many contexts
		if ($MyInvocation -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) { $mi = $MyInvocation.MyCommand.Path; if (Test-Path -LiteralPath $mi) { return (Resolve-Path -LiteralPath $mi).Path } }
		# Try PSScriptRoot + known filename
		if ($PSScriptRoot) { $try1 = Join-Path $PSScriptRoot $FallbackName; if (Test-Path -LiteralPath $try1) { return (Resolve-Path -LiteralPath $try1).Path } }
		# Try current directory + known filename (last resort)
		$try2 = Join-Path (Get-Location).Path $FallbackName
		if (Test-Path -LiteralPath $try2) { return (Resolve-Path -LiteralPath $try2).Path }
		return $null
	} catch { return $null }
}
