# The text a tray icon shows on hover. It lives here rather than in
# NotifyIcon.Text, which stays empty so that Windows draws no second tooltip of
# its own -- see Register-TrayHoverTip. Written this way a status change also
# reaches a tooltip that is standing open at that moment.
function Set-TrayTipText {
	[CmdletBinding()]
	param(
		[Parameter(Position = 0)][System.Windows.Forms.NotifyIcon]$Notify,
		[Parameter(Position = 1)][string]$Text = ''
	)
	if (-not $Notify) { return }
	if (-not ($script:TrayTipTexts -is [hashtable])) { $script:TrayTipTexts = @{} }
	$script:TrayTipTexts[$Notify] = $Text
	if ($Notify.Text -ne '') { $Notify.Text = '' }
}