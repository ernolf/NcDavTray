# Opens a URL, in a named browser or in whatever Windows would use for it.
function Open-UrlInBrowser([string]$Url, [string]$BrowserPath = '') {
	if ([string]::IsNullOrWhiteSpace($Url)) { return }
	try {
		$psi = New-Object System.Diagnostics.ProcessStartInfo
		$psi.UseShellExecute = $true
		if (-not [string]::IsNullOrWhiteSpace($BrowserPath) -and (Test-Path -LiteralPath $BrowserPath)) {
			$psi.FileName = $BrowserPath
			$psi.Arguments = ('"{0}"' -f $Url)
		} else {
			$psi.FileName = $Url
		}
		[System.Diagnostics.Process]::Start($psi) | Out-Null
	} catch {}
}
