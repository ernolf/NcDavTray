# Opens the settings page on one account of the mount list.
# That page and the main settings window name a handful of things alike, and this
# window is opened out of that one while it stays up. So what the page takes over
# is put back afterwards -- it tears its own down on close.
function Show-AccountSettingsDialog {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Entry )
	$keepTip = $script:Tip; $keepHost = $script:HostForm; $keepLang = $script:ApplyLanguageNow; $keepClose = $script:ButtonClose1
	try {
		Set-AccountEditorContext -Entry $Entry
		# The window this one was opened from is blocked for as long as it is up, and
		# it cannot be pushed aside either -- so it goes out of the way by itself.
		return (Invoke-WithWindowMinimized -Window $script:SettingsForm -Body { Show-AccountSettingsWindow })
	} finally {
		$script:Tip = $keepTip; $script:HostForm = $keepHost; $script:ApplyLanguageNow = $keepLang; $script:ButtonClose1 = $keepClose
	}
}
