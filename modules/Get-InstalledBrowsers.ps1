# The browsers Windows knows about, with the default one marked. Which browser a
# login page opens in decides whether the user is already signed in there, so the
# choice is worth offering -- see Show-NcLoginFlowDialog.
# Registered browsers live under Clients\StartMenuInternet, per machine and per
# user; the default is the https handler of the current user.
function Get-InstalledBrowsers {
	[CmdletBinding()] param()
	$defaultExe = ''
	try {
		$progId = [string](Get-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' -Name 'ProgId' -ErrorAction Stop).ProgId
		if (-not [string]::IsNullOrWhiteSpace($progId)) { $defaultExe = Get-CommandExePath ([string](Get-Item -LiteralPath ("Registry::HKEY_CLASSES_ROOT\{0}\shell\open\command" -f $progId) -ErrorAction Stop).GetValue('')) }
	} catch {}
	$seen = @{}
	$list = @()
	# The 32-bit branch is not the same list: a 32-bit browser on a 64-bit Windows
	# registers behind Wow6432Node, and which of the two a process sees depends on
	# what bitness it happens to run as.
	foreach ($root in @('HKLM:\SOFTWARE\Clients\StartMenuInternet', 'HKLM:\SOFTWARE\WOW6432Node\Clients\StartMenuInternet', 'HKCU:\SOFTWARE\Clients\StartMenuInternet')) {
		if (-not (Test-Path -LiteralPath $root)) { continue }
		foreach ($k in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
			$exe = ''
			try { $exe = Get-CommandExePath ([string](Get-Item -LiteralPath (Join-Path $k.PSPath 'shell\open\command') -ErrorAction Stop).GetValue('')) } catch {}
			if ([string]::IsNullOrWhiteSpace($exe) -or -not (Test-Path -LiteralPath $exe)) { continue }
			# Still registered, no longer a browser: iexplore.exe hands the address to Edge,
			# and a login page that opens somewhere else than where it was sent is the one
			# thing this list exists to prevent.
			if ([System.IO.Path]::GetFileName($exe) -ieq 'iexplore.exe') { continue }
			$key = $exe.ToLowerInvariant()
			if ($seen.ContainsKey($key)) { continue }
			$seen[$key] = $true
			$name = ''
			try { $name = [string]$k.GetValue('') } catch {}
			if ([string]::IsNullOrWhiteSpace($name)) { $name = $k.PSChildName }
			$list += [pscustomobject]@{ Name = $name; Path = $exe; IsDefault = [string]::Equals($exe, $defaultExe, 'OrdinalIgnoreCase') }
		}
	}
	return @($list | Sort-Object Name)
}
