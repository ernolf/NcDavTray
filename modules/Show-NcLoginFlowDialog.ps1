# The waiting window of a browser login. It opens the session and polls until the
# server confirms, then hands back what came with that confirmation: server, login
# name and a fresh app password. Where the login page is opened is the user's
# decision -- nothing opens by itself.
# Returns $null when the user cancels, when the session runs out, or when the
# server never opened one.
function Show-NcLoginFlowDialog {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Server )
	$srv = $Server.Trim().Trim('/')
	$flow = Start-NcLoginFlow -Server $srv
	if (-not $flow) { Show-ErrorT 'message.login_flow_failed' @{ server = $srv }; return $null }
	# Shared with the timer handler, which cannot assign to a plain local of this scope
	$state = @{ Result = $null; TimedOut = $false; BrowserPath = '' }
	# Whoever is already signed in somewhere decides where this page should open, and
	# that is not always the default browser. The default is what it starts with.
	$browsers = @(Get-InstalledBrowsers)
	foreach ($b in $browsers) { if ($b.IsDefault) { $state.BrowserPath = $b.Path } }
	# The session the server just opened is good for 20 minutes, and polling past
	# that only asks about a token that no longer exists.
	$deadline = (Get-Date).AddMinutes(20)
	$f = New-Object System.Windows.Forms.Form; Apply-BrandIconToForm $f; Hook-FormDpi $f; Hook-FormScreen $f
	$f.Text = (T 'title.login_flow' @{ app = $AppName }); $f.StartPosition = 'CenterScreen'
	$f.FormBorderStyle = 'FixedDialog'; $f.MinimizeBox = $false; $f.MaximizeBox = $false; $f.ShowInTaskbar = $false; $f.TopMost = $true
	$f.AutoScaleMode = 'Dpi'; $f.Width = 620; $f.Height = 280; $f.Font = New-Object System.Drawing.Font($UiFontFamily, 9)
	$wrapW = [Math]::Max(200, $f.ClientSize.Width - 32)
	$root = New-Object System.Windows.Forms.TableLayoutPanel; $root.Dock = 'Fill'; $root.Padding = New-Object System.Windows.Forms.Padding(12, 12, 12, 12); $root.ColumnCount = 1; $root.RowCount = 3
	$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
	$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
	$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, ($script:ButtonXH + (2 * $script:ButtonPadY))))) | Out-Null
	$lblBody = New-Object System.Windows.Forms.Label; $lblBody.AutoSize = $true; $lblBody.UseMnemonic = $false
	$lblBody.MaximumSize = New-Object System.Drawing.Size($wrapW, 0)
	$lblBody.Text = (T 'message.login_flow_wait' @{ server = $srv; app = $AppName })
	$row = New-Object System.Windows.Forms.FlowLayoutPanel; $row.AutoSize = $true; $row.FlowDirection = 'LeftToRight'; $row.WrapContents = $false; $row.Margin = New-Object System.Windows.Forms.Padding(0, 12, 0, 0)
	# One browser and there is nothing to choose. Several, and the one the user is
	# already signed in with turns the whole login into a single click.
	if ($browsers.Count -gt 1) {
		$lblBrowser = New-Object System.Windows.Forms.Label; $lblBrowser.Text = (T 'label.browser'); $lblBrowser.AutoSize = $true; $lblBrowser.Margin = New-Object System.Windows.Forms.Padding(0, 9, 8, 0)
		$cmbBrowser = New-Object System.Windows.Forms.ComboBox; $cmbBrowser.DropDownStyle = 'DropDownList'; $cmbBrowser.Width = 200; $cmbBrowser.Margin = New-Object System.Windows.Forms.Padding(0, 6, 8, 0)
		foreach ($b in $browsers) { [void]$cmbBrowser.Items.Add($b.Name) }
		$sel = 0
		for ($i = 0; $i -lt $browsers.Count; $i++) { if ($browsers[$i].IsDefault) { $sel = $i } }
		$cmbBrowser.SelectedIndex = $sel
		$state.BrowserPath = $browsers[$sel].Path
		$cmbBrowser.add_SelectedIndexChanged({ $i = $cmbBrowser.SelectedIndex; if ($i -ge 0) { $state.BrowserPath = $browsers[$i].Path } })
		$row.Controls.AddRange(@($lblBrowser, $cmbBrowser))
	}
	# Choosing a browser does not open it: the page is opened here, once, and only
	# when it is asked for. The address leads somewhere else just as well -- a
	# private window, or a browser on another device.
	$btnOpen = New-Object System.Windows.Forms.Button; $btnOpen.Text = (T 'button.open_login_page'); $btnOpen.AutoSize = $true; $btnOpen.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowOnly; $btnOpen.Height = $script:ButtonH; $btnOpen.Margin = New-Object System.Windows.Forms.Padding(0, 3, 8, 0)
	$btnOpen.Add_Click({ Open-UrlInBrowser $flow.LoginUrl $state.BrowserPath })
	$btnCopy = New-Object System.Windows.Forms.Button; $btnCopy.Text = (T 'button.copy_url'); $btnCopy.AutoSize = $true; $btnCopy.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowOnly; $btnCopy.Height = $script:ButtonH; $btnCopy.Margin = New-Object System.Windows.Forms.Padding(0, 3, 0, 0)
	$btnCopy.Add_Click({ try { [System.Windows.Forms.Clipboard]::SetText($flow.LoginUrl) } catch {} })
	$row.Controls.AddRange(@($btnOpen, $btnCopy))
	$btnRow = New-Object System.Windows.Forms.FlowLayoutPanel; $btnRow.Dock = 'Bottom'; $btnRow.FlowDirection = 'RightToLeft'; $btnRow.AutoSize = $false; $btnRow.Height = $script:ButtonXH + (2 * $script:ButtonPadY); $btnRow.Padding = New-Object System.Windows.Forms.Padding(0, $script:ButtonPadY, 0, 0)
	# Wide enough for its label and never narrower than the others: 'Cancel' is one
	# word in English and a longer one in most of the languages beside it.
	$btnCancel = New-Object System.Windows.Forms.Button; $btnCancel.Text = (T 'button.cancel'); $btnCancel.Height = $script:ButtonXH
	$btnCancel.AutoSize = $true; $btnCancel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowOnly
	$btnCancel.MaximumSize = New-Object System.Drawing.Size(0, $btnCancel.Height)
	$btnCancel.MinimumSize = New-Object System.Drawing.Size($script:ButtonMinW, 0)
	$btnCancel.Add_Click({ $f.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $f.Close() })
	$btnRow.Controls.Add($btnCancel)
	$f.CancelButton = $btnCancel
	$root.Controls.Add($lblBody)
	$root.Controls.Add($row)
	$root.Controls.Add($btnRow)
	$f.Controls.Add($root)
	$need = $root.GetPreferredSize((New-Object System.Drawing.Size($f.ClientSize.Width, 0))).Height + ($f.Height - $f.ClientSize.Height)
	if ($need -gt $f.Height) { $f.Height = $need }
	# Polling runs on a timer and not in a loop: the window has to stay answerable
	# while it waits, and the wait is measured in minutes.
	$timer = New-Object System.Windows.Forms.Timer; $timer.Interval = 2000
	$timer.add_Tick({
		# Stopped for the duration of the call, so a slow answer cannot overlap itself
		$timer.Stop()
		$r = Invoke-NcLoginFlowPoll -Endpoint $flow.PollEndpoint -Token $flow.PollToken
		if ($r.State -eq 'Ok') { $state.Result = $r; $f.DialogResult = [System.Windows.Forms.DialogResult]::OK; $f.Close(); return }
		if ($r.State -eq 'Failed') { $f.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $f.Close(); return }
		if ((Get-Date) -gt $deadline) { $state.TimedOut = $true; $f.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $f.Close(); return }
		$timer.Start()
	})
	# Polling starts with the window and not with the button: the address can be
	# confirmed from anywhere, and this window has no way of knowing where.
	$f.add_Shown({ $timer.Start() })
	$f.add_FormClosed({ try { $timer.Stop(); $timer.Dispose() } catch {} })
	[void]$f.ShowDialog()
	if ($state.TimedOut) { Show-InfoT 'message.login_flow_timeout' }
	return $state.Result
}
