# The settings window itself, and nothing around it. Which account it is about and
# what has to happen when it saves was answered before the call -- see
# Set-AccountEditorContext. Returns the DialogResult.
function Show-AccountSettingsWindow {
	[CmdletBinding()] param()
	# global tooltip (single instance, reused everywhere)
	$script:Tip = New-Object System.Windows.Forms.ToolTip
	# Small tooltip helper (shared for all controls)
#	$script:Tip.AutoPopDelay = 8000 # how long the tooltip stays visible (ms)
	$script:Tip.InitialDelay = 300 # delay before first show (ms)
	$script:Tip.ReshowDelay = 100 # delay for subsequent shows (ms)
	$script:Tip.ShowAlways = $true # also show for disabled controls
	# Create host form (chrome only)
	$f = $script:HostForm = New-Object System.Windows.Forms.Form; Apply-BrandIconToForm $f; Hook-FormDpi $f; Hook-FormScreen $f
	$f.Text = (T 'title.settings_dialog' @{ app = $AppName }); $f.ShowInTaskbar = $false; $f.TopMost = $true; $f.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$f.MaximizeBox = $false; $f.MinimizeBox = $false
	# This window covers one drive and nothing else. Everything that is set once for
	# the whole machine -- WebClient tuning, the WebDAV cache, the interface language,
	# the poll interval, autostart, shortcuts and the install/export buttons -- lives
	# in the main settings window, so a single page is left and it needs no tab strip.
	# The padding stands in for what the TabControl frame and the TabPage padding
	# used to contribute, which keeps the page itself at its old width.
	$f.Padding = New-Object System.Windows.Forms.Padding(18, 12, 18, 12)
	$f.ClientSize = New-Object System.Drawing.Size(674, 250)
	$f.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
	Render-BasicSettingsTab -HostTab $null
	# Tracked separately from the main settings window: this one is opened out of it
	# while it stays up.
	$script:AccountSettingsForm = $f
	$dlg = $f.ShowDialog()
	$script:AccountSettingsForm = $null
	return $dlg
}
