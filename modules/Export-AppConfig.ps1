# The whole configuration in one file: the list as it stands plus the DPAPI blob
# of every password it holds. Those blobs are readable to this user on this
# machine and to nobody else, which makes the file a way to put an installation
# back the way it was -- not a package to carry around. That is what the portable
# export is for.
function Export-AppConfig {
	[CmdletBinding()] param([switch]$SkipConfirm)
	if ($PortableMode) { return }
	if (-not $SkipConfirm) { $ans = Ask-YesNoQuestT 'prompt.export2json' @{ app = $AppName }; if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) { return } }
	try {
		$dlg = New-Object System.Windows.Forms.SaveFileDialog
		$dlg.Title = (T 'title.export_config'); $dlg.Filter = 'JSON (*.json)|*.json'; $dlg.FileName = ('{0}_installed.json' -f $AppName); $dlg.InitialDirectory = [Environment]::GetFolderPath('Desktop')
		if ($dlg.ShowDialog() -ne 'OK') { return }
		# One secret per server/user pair, however many mounts share it.
		$seen = @{}
		$accounts = @()
		foreach ($m in @($State.Mounts)) {
			if (-not $m) { continue }
			$name = Get-MountSecretName $m
			$key = Get-AccountKey -Server $m.Server -User $name
			if ($seen.ContainsKey($key)) { continue }
			$seen[$key] = $true
			$enc = Get-AccountSecret -Server $m.Server -User $name
			if ([string]::IsNullOrEmpty($enc)) { continue }
			$accounts += [pscustomobject]@{ Key = $key; DPAPI = $enc }
		}
		$payload = [pscustomobject]@{
			SchemaVersion = $State.SchemaVersion; IntervalS = [int]$State.IntervalS; LangPref = [string]$State.LangPref
			Mounts = @($State.Mounts); Accounts = $accounts
		}
		$payload | ConvertTo-Json -Depth 4 | Set-Content -Path $dlg.FileName -Encoding UTF8
		Show-InfoT 'message.installed_config_exported'
	} catch { Show-ErrorT 'message.export_failed' @{ err = $_.Exception.Message } }
}