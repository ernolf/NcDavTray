# Fills the session table from the secret file. A passphrase that does not fit
# throws out of the container, and it is left to throw: the caller has to tell it
# apart from an empty file, and only one of the two is worth asking again about.
# Reports whether the file should be written back afterwards.
function Read-PortableSecretStore {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Passphrase )
	$res = Unprotect-PortableSecret -Passphrase $Passphrase -Path $SecretPath
	$script:AccountSecretCache = @{}
	if ($res.Format -eq 'NCPT1') {
		# One password and no name to go with it -- a copy before 2.0.0 had one account
		# and needed none. It belongs to the account Load-Config has just put in the
		# list, and it is worth writing back under that name: worked out once here,
		# rather than again on every start.
		$first = @($State.Mounts) | Where-Object { $_ -and ([string]$_.Kind -eq 'account') } | Select-Object -First 1
		if ($first) { Set-AccountPassword -Server $first.Server -User $first.User -Plain $res.Text }
		return $true
	}
	$tab = $null
	try { $tab = $res.Text | ConvertFrom-Json } catch { throw 'Secret file is corrupt.' }
	if ($tab) {
		foreach ($p in $tab.PSObject.Properties) {
			$plain = [string]$p.Value
			if ([string]::IsNullOrEmpty($plain)) { continue }
			# Into the table as a DPAPI blob, which is what every reader of it expects --
			# the file holds plain passwords because it has to travel, the table does not.
			$sec = ConvertTo-SecureString $plain -AsPlainText -Force
			$script:AccountSecretCache[$p.Name] = ($sec | ConvertFrom-SecureString)
		}
	}
	return $false
}