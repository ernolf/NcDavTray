# Writes the whole session table to the secret file. Whole, not the one pair that
# changed: the container is encrypted in one piece, and rewriting it entirely is
# what keeps the file from disagreeing with the table about which accounts exist.
# An empty table takes the file with it. An empty container would still ask for
# its passphrase on every start and hand back nothing for it.
function Save-PortableSecretStore {
	[CmdletBinding()] param()
	if ($IsInstalled) { return $true }
	if ($script:AccountSecretCache.Count -eq 0) {
		if (Test-Path -LiteralPath $SecretPath) { try { Remove-Item -LiteralPath $SecretPath -Force } catch {} }
		$script:SecretPassphrase = $null
		return $true
	}
	if (-not (Ensure-SecretPassphrase)) { return $false }
	$tab = @{}
	foreach ($k in @($script:AccountSecretCache.Keys)) {
		$blob = [string]$script:AccountSecretCache[$k]
		if ([string]::IsNullOrEmpty($blob)) { continue }
		# Out of the DPAPI wrapping the table keeps them in: that wrapping is bound to
		# this user on this machine, which is the one promise a folder carried to
		# another machine cannot keep. The passphrase is what protects them in the file.
		try { $sec = ConvertTo-SecureString $blob; $tab[$k] = (New-Object System.Net.NetworkCredential('', $sec)).Password } catch { continue }
	}
	try { Protect-PortableSecret -Plain ($tab | ConvertTo-Json -Depth 2) -Passphrase $script:SecretPassphrase -Path $SecretPath }
	catch { Show-ErrorT 'message.write_secret_failed' @{ err = $_.Exception.Message }; return $false }
	return $true
}