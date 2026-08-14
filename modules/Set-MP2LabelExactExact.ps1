function Set-MP2LabelExactExact {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	# Canonical WebDAV MP2 key (no DavWWWRoot)
	$keyName = (Get-MP2KeyNames $Spec)[0]
	try {
		# Open MP2 base with write access
		$cu = [Microsoft.Win32.Registry]::CurrentUser; $mp2 = $cu.CreateSubKey(($RegMP2 -replace '^HKCU:\\'), $true)
		if ($null -eq $mp2) { return }
		# Ensure exact key exists (create if missing), then set/remove label
		try {
			$key = $mp2.OpenSubKey($keyName, $true)
			if (-not $key) { $key = $mp2.CreateSubKey($keyName, $true) }
			if ($key) { if ([string]::IsNullOrWhiteSpace($Spec.Label)) { try { $key.DeleteValue('_LabelFromReg', $false) } catch {} } else { $key.SetValue('_LabelFromReg', $Spec.Label, [Microsoft.Win32.RegistryValueKind]::String) }; $key.Close() }
		} catch {}
		try { $mp2.Close() } catch {}
	} catch {} # best-effort; timer can retry
	# Nudge Explorer caches (best-effort)
	try { Refresh-ShellIcons } catch {}
}
