# Forgets a tray icon that is about to be disposed. Its text would otherwise stay
# behind in the store, and a tooltip open over it would be left following an icon
# that no longer exists.
function Unregister-TrayHoverTip {
	[CmdletBinding()]
	param([System.Windows.Forms.NotifyIcon]$Notify)
	if (-not $Notify) { return }
	if ($script:TrayTipIcon -eq $Notify) {
		if ($script:TrayTipHide -is [scriptblock]) { & $script:TrayTipHide }
		$script:TrayTipIcon = $null
	}
	if ($script:TrayTipTexts -is [hashtable]) { $script:TrayTipTexts.Remove($Notify) }
}