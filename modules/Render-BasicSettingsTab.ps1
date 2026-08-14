function Render-BasicSettingsTab([System.Windows.Forms.Control] $HostTab = $null) {
	# Use provided host form (container owns chrome)
	$f = $script:HostForm
	# Choose the container for controls
	$c = if ($HostTab -ne $null) { $HostTab } else { $f }
	$panelMain = New-Object Windows.Forms.Panel; $panelMain.Dock = 'Fill'
	$panelFooter = New-Object Windows.Forms.Panel; $panelFooter.Dock = 'Bottom'; $panelFooter.Height = $script:ButtonXH
	$panelMain.TabIndex = 0; $panelFooter.TabIndex = 1 # Explicit tab order between sibling containers
	$c.Controls.AddRange(@( $panelFooter, $panelMain ))
	$script:LabelServer = New-Object Windows.Forms.Label; $script:LabelServer.Text = (T 'label.server'); $script:LabelServer.Left = 12; $script:LabelServer.Top = 12; $script:LabelServer.AutoSize = $true
	$script:TextServer = New-Object Windows.Forms.TextBox; $script:TextServer.Top = 10; $script:TextServer.Width = 400; $script:TextServer.Left = $panelMain.ClientSize.Width - $script:TextServer.Width - 2; $script:TextServer.Text = $script:Edit.Server; $script:TextServer.Anchor = 'Top, Right'
	$script:LabelUser = New-Object Windows.Forms.Label; $script:LabelUser.Text = (T 'label.user'); $script:LabelUser.Left = 12; $script:LabelUser.Top = 42; $script:LabelUser.AutoSize = $true
	$script:TextUser = New-Object Windows.Forms.TextBox; $script:TextUser.Top = 40; $script:TextUser.Width = $script:TextServer.Width; $script:TextUser.Left = $script:TextServer.Left; $script:TextUser.Text = $script:Edit.User; $script:TextUser.Anchor = 'Top, Right'
	# Small images next to Server/User
	$script:PicFavicon = New-Object System.Windows.Forms.PictureBox; $script:PicFavicon.Width = 24; $script:PicFavicon.Height = 24; $script:PicFavicon.SizeMode = 'Zoom'; $script:PicFavicon.Left = $script:TextServer.Left - 28; $script:PicFavicon.Top = $script:TextServer.Top - 2; $script:PicFavicon.Anchor = 'Top, Right'
	$script:PicAvatar = New-Object System.Windows.Forms.PictureBox; $script:PicAvatar.Width = 24; $script:PicAvatar.Height = 24; $script:PicAvatar.SizeMode = 'Zoom'; $script:PicAvatar.Left = $script:PicFavicon.Left; $script:PicAvatar.Top = $script:TextUser.Top - 2; $script:PicAvatar.Anchor = 'Top, Right'
	# FaviconTimer tick
	if (-not $script:FaviconTimer) { $script:FaviconTimer = New-Object System.Windows.Forms.Timer; $script:FaviconTimer.Interval = 500 }
	$script:FaviconTimer.add_Tick({
		$script:FaviconTimer.Stop()
		# reset favicon cache before fetch
		$script:ServerFaviconBmp = $null
		$srv = $script:TextServer.Text.Trim()
		if ([string]::IsNullOrWhiteSpace($srv)) { Clear-PictureImage $script:PicFavicon; return }
		$null = Fetch-ServerFavicon ($srv)
		if ($script:ServerFaviconBmp) { Set-PictureImageSafe $script:PicFavicon $script:ServerFaviconBmp } else { Clear-PictureImage $script:PicFavicon }
	})
	# AvatarTimer tick
	if (-not $script:AvatarTimer) { $script:AvatarTimer = New-Object System.Windows.Forms.Timer; $script:AvatarTimer.Interval = 500 }
	$script:AvatarTimer.add_Tick({
		$script:AvatarTimer.Stop()
		# reset avatar cache before fetch
		$script:UserAvatarBmp = $null
		$srv = $script:TextServer.Text.Trim()
		$usr = $script:TextUser.Text.Trim()
		if ([string]::IsNullOrWhiteSpace($srv) -or [string]::IsNullOrWhiteSpace($usr)) { Clear-PictureImage $script:PicAvatar; return }
		$null = Fetch-UserAvatar ($srv) ($usr)
		if ($script:UserAvatarBmp) { Set-PictureImageSafe $script:PicAvatar $script:UserAvatarBmp } else { Clear-PictureImage $script:PicAvatar }
	})
	# TextServer TextChanged handler
	$script:TextServer.add_TextChanged({
		# reset favicon/avatar caches
		$script:ServerFaviconBmp = $null; $script:UserAvatarBmp = $null
		# favicon debounce
		Clear-PictureImage $script:PicFavicon; $script:FaviconTimer.Stop()
		if (-not [string]::IsNullOrWhiteSpace($script:TextServer.Text)) { $script:FaviconTimer.Start() }
		# avatar debounce
		Clear-PictureImage $script:PicAvatar; $script:AvatarTimer.Stop()
		if (-not [string]::IsNullOrWhiteSpace($script:TextServer.Text) -and -not [string]::IsNullOrWhiteSpace($script:TextUser.Text)) { $script:AvatarTimer.Start() }
		# auto display name update (only if user did not customize)
		$newDefault = (& $script:ComputeDefaultLabel $script:TxtSub.Text $script:TextUser.Text.Trim() $script:TextServer.Text.Trim())
		if ([string]::IsNullOrWhiteSpace($script:TxtDisp.Text) -or ($script:TxtDisp.Text -eq $script:BasicSettings_Auto.LastAuto)) { $script:TxtDisp.Text = $newDefault; $script:BasicSettings_Auto.LastAuto = $newDefault }
		& $script:UpdateSaveButton
	})
	# TextUser TextChanged handler
	$script:TextUser.add_TextChanged({
		# reset avatar cache on user edit
		$script:UserAvatarBmp = $null
		Clear-PictureImage $script:PicAvatar; $script:AvatarTimer.Stop()
		if (-not [string]::IsNullOrWhiteSpace($script:TextServer.Text) -and -not [string]::IsNullOrWhiteSpace($script:TextUser.Text)) { $script:AvatarTimer.Start() }
	})
	# Initial favicon fetch + assign
	if ([string]::IsNullOrWhiteSpace($script:TextServer.Text)) { Clear-PictureImage $script:PicFavicon }
	else { $null = Fetch-ServerFavicon ($script:TextServer.Text.Trim()); if ($script:ServerFaviconBmp) { Set-PictureImageSafe $script:PicFavicon $script:ServerFaviconBmp } else { Clear-PictureImage $script:PicFavicon } }
	# Initial avatar fetch + assign
	if ([string]::IsNullOrWhiteSpace($script:TextServer.Text) -or [string]::IsNullOrWhiteSpace($script:TextUser.Text)) { Clear-PictureImage $script:PicAvatar }
	else { $null = Fetch-UserAvatar ($script:TextServer.Text.Trim()) ($script:TextUser.Text.Trim()); if ($script:UserAvatarBmp) { Set-PictureImageSafe $script:PicAvatar $script:UserAvatarBmp } else { Clear-PictureImage $script:PicAvatar } }
	# Password
	$script:LabelPassword = New-Object Windows.Forms.Label; $script:LabelPassword.Text = T 'app_password'; $script:LabelPassword.Left = 12; $script:LabelPassword.Top = 72; $script:LabelPassword.AutoSize = $true
	# Small "?" help button next to the password box
	$script:ButtonPasswordHelp = New-Object Windows.Forms.Button; $script:ButtonPasswordHelp.Text = '?'; $script:ButtonPasswordHelp.Width = 28; $script:ButtonPasswordHelp.Left = $script:PicFavicon.Left - 2; $script:ButtonPasswordHelp.Top = 66; $script:ButtonPasswordHelp.Height = $script:ButtonH; $script:ButtonPasswordHelp.Anchor = 'Top, Right'
	# Encrypt button (right of password TextBox)
	$script:ButtonEncrypt = New-Object Windows.Forms.Button; $script:ButtonEncrypt.Top = $script:LabelPassword.Top - 6; $script:ButtonEncrypt.Text = (T 'button.encrypt'); $script:ButtonEncrypt.Width = 100; $script:ButtonEncrypt.Left = $panelMain.ClientSize.Width - $script:ButtonEncrypt.Width -2; $script:ButtonEncrypt.Height = $script:ButtonH; $script:ButtonEncrypt.Anchor = 'Top, Right'
	$script:TextPassword = New-Object Windows.Forms.TextBox; $script:TextPassword.Top = $script:LabelPassword.Top - 2; $script:TextPassword.Left = $script:TextServer.Left; $script:TextPassword.Width = $script:ButtonEncrypt.Left - $script:TextPassword.Left - 10; $script:TextPassword.UseSystemPasswordChar = $true; $script:TextPassword.Anchor = 'Top, Right'
	# Click handler: builds URL from current Server field or falls back
	# capture once, so the handler will later have stable references. The parent form
	# has to come from the captured $f: inside a closure, $script: addresses the
	# closure's own scope and would read empty.
	# Store both: textbox + app name
	$script:ButtonPasswordHelp.Tag = @{ tb = $script:TextServer; app = $AppName }
	$script:ButtonPasswordHelp.Add_Click(({
		param($sender, $args)
		$tb = $sender.Tag.tb
		$app = [string]$sender.Tag.app
		$raw = if ($tb) { $tb.Text } else { '' }
		$host = '<cloud.example.com>'
		if (-not [string]::IsNullOrWhiteSpace($raw)) { $h = $raw.Trim(); if ($h -match '^\s*https?://') { try { $u = [Uri]$h; $h = $u.Host } catch {} }; $h = $h.Trim('/').Trim(); if (-not [string]::IsNullOrWhiteSpace($h)) { $host = $h } }
		$url = "https://$host/index.php/settings/user/security"
		[void](Show-HelpT -TitleKey 'title.app_password_help' -TitleVars @{ app = $app } -BodyKey 'message.app_password_help' -BodyVars @{ url = $url; app = $app } -Url $url -Width 640 -Height 320 -Parent $f)
	}).GetNewClosure())
	# Subfolder (read-only -> only selection via picker)
	$script:LabelSubfolder = New-Object Windows.Forms.Label; $script:LabelSubfolder.Text = (T 'label.subfolder'); $script:LabelSubfolder.Left = 12; $script:LabelSubfolder.Top = 102; $script:LabelSubfolder.AutoSize = $true
	$script:TxtSub = New-Object Windows.Forms.TextBox; $script:TxtSub.Top = 100; $script:TxtSub.Width = $script:TextServer.Width; $script:TxtSub.Left = $script:TextServer.Left; $script:TxtSub.Text = $script:Edit.SubPath; $script:TxtSub.ReadOnly = $true; $script:TxtSub.BackColor = [System.Drawing.SystemColors]::ControlLightLight; $script:TxtSub.Anchor = 'Top, Right'
	# Helper: compute default display name from subfolder/user/server
	$script:ComputeDefaultLabel = {
		param([string]$sub, [string]$user, [string]$server)
		if ($null -eq $sub) { $sub = '' }
		$subNorm = $sub.Trim('/')
		if (-not [string]::IsNullOrWhiteSpace($subNorm)) { $parts = $subNorm.Split('/'); return $parts[$parts.Length - 1] }
		# empty subfolder -> "user@server"
		$u = if ($null -ne $user) { $user.Trim() } else { '' }
		$s = if ($null -ne $server) { $server.Trim() } else { '' }
		return ("{0}@{1}" -f $u, $s)
	}
	# Shared state for auto-filled display name; using hashtable to keep reference across event scopes
	$script:BasicSettings_Auto = @{ LastAuto = $null }
	# Helper to open the subfolder picker and update txtSub / txtDisp
	$script:OpenSubfolderPicker = {
		# remember old subfolder to detect a real change
		$oldSub = $script:TxtSub.Text
		$pick = Show-NcFolderPicker -Server $script:Edit.Server -User $script:Edit.User -Pass (& $script:EditPlainPassword) -SubPath $script:Edit.SubPath
		if ($pick -ne $null) {
			$oldDefault = (& $script:ComputeDefaultLabel $oldSub $script:TextUser.Text.Trim() $script:TextServer.Text.Trim())
			$newDefault = (& $script:ComputeDefaultLabel $pick $script:TextUser.Text.Trim() $script:TextServer.Text.Trim())
			# user actually changed folder -> suggest new label
			if ($pick -ne $oldSub) { $script:TxtDisp.Text = $newDefault; $script:BasicSettings_Auto.LastAuto = $newDefault }
			# same folder -> only update label if user hasn't customized manually
			elseif ([string]::IsNullOrWhiteSpace($script:TxtDisp.Text) -or ($script:TxtDisp.Text -eq $oldDefault) -or ($script:TxtDisp.Text -eq $script:BasicSettings_Auto.LastAuto)) { $script:TxtDisp.Text = $newDefault; $script:BasicSettings_Auto.LastAuto = $newDefault }
			$script:TxtSub.Text = $pick
			& $script:UpdateSaveButton
		}
	}
	# shared browse-state flag (controls picker availability)
	$script:BrowseState = @{ CanBrowse = $false }
	# Small tooltip for disabled controls
	# Hover tooltips for Server/User/Password
	$script:Tip.SetToolTip($script:TextServer, (T 'tip.enter_server'))
	$script:Tip.SetToolTip($script:TextUser, (T 'tip.enter_user'))
	$script:Tip.SetToolTip($script:ButtonPasswordHelp, (T 'title.app_password_help'))
	# Local helper: controls state depending on encrypted password presence
	$script:RefreshPasswordState = {
		$hasEncPortable = $script:EditSecretFile -and (& $script:EditHasSecret)
		$hasEncInstalled = (-not $script:EditSecretFile) -and (-not [string]::IsNullOrEmpty($script:Edit.EncPass))
		# Decide if browsing is allowed
		$localCanBrowse = ($hasEncPortable -or $hasEncInstalled)
		# Publish new state so MouseDown/KeyDown see it immediately
		$script:BrowseState.CanBrowse = $localCanBrowse
		# Update tooltip text
		if ($localCanBrowse) { $script:Tip.SetToolTip($script:TxtSub, $null) } else { $script:Tip.SetToolTip($script:TxtSub, (T 'tip.enter_password_and_encrypt')) }
		# Toggle Encrypt/Clear UI and show info text when a secret exists
		if ($script:EditSecretFile) {
			$script:ButtonEncrypt.Text = $(if ($hasEncPortable) { (T 'button.delete_secrets') } else { (T 'button.encrypt') })
			# Show info message instead of password dots
			if ($hasEncPortable) { $msg = (T 'password.encrypted_secret'); $script:TextPassword.ReadOnly = $true; $script:TextPassword.Enabled = $true; $script:TextPassword.UseSystemPasswordChar = $false; $script:TextPassword.ForeColor = [System.Drawing.SystemColors]::GrayText; $script:TextPassword.Text = $msg; $script:TextPassword.Tag = 'info' }
			# Back to normal editable password field
			else { if ($script:TextPassword.Tag -eq 'info') { $script:TextPassword.Text = '' }; $script:TextPassword.Tag = $null; $script:TextPassword.ReadOnly = $false; $script:TextPassword.Enabled = $true; $script:TextPassword.UseSystemPasswordChar = $true; $script:TextPassword.ForeColor = [System.Drawing.SystemColors]::WindowText }
		} else {
			$script:ButtonEncrypt.Text = $(if ($hasEncInstalled) { (T 'button.clear') } else { (T 'button.encrypt') })
			if ($hasEncInstalled) { $msg = (T 'password.encrypted_dpapi'); $script:TextPassword.ReadOnly = $true; $script:TextPassword.Enabled = $true; $script:TextPassword.UseSystemPasswordChar = $false; $script:TextPassword.ForeColor = [System.Drawing.SystemColors]::GrayText; $script:TextPassword.Text = $msg; $script:TextPassword.Tag = 'info' }
			else { if ($script:TextPassword.Tag -eq 'info') { $script:TextPassword.Text = '' }; $script:TextPassword.Tag = $null; $script:TextPassword.ReadOnly = $false; $script:TextPassword.Enabled = $true; $script:TextPassword.UseSystemPasswordChar = $true; $script:TextPassword.ForeColor = [System.Drawing.SystemColors]::WindowText }
		}
		# Password tooltip (hover only when not yet stored/encrypted)
		$pwEmpty = ([string]::IsNullOrWhiteSpace($script:TextPassword.Text) -or $script:TextPassword.Tag -eq 'info')
		$needPwd = (-not $hasEncPortable -and -not $hasEncInstalled)
		if ($needPwd -and $pwEmpty) { $script:Tip.SetToolTip($script:TextPassword, (T 'app_password')) } else { $script:Tip.SetToolTip($script:TextPassword, $null) }
	}
	# Clicking the readonly path box
	$script:TxtSub.add_MouseDown({
		# open picker directly
		if ($script:BrowseState.CanBrowse) { try { & $script:OpenSubfolderPicker } catch {} }
		# show enforced tooltip popup near the box for ~4s
		else { try { $msg = (T 'tip.enter_password_and_encrypt'); $script:Tip.Show($msg, $script:TxtSub, 0, $script:TxtSub.Height + 2, 4000) } catch {} }
		# move focus away so txtSub does not look "active"
		try { $script:ButtonEncrypt.Focus() } catch {}
	})
	# keyboard interaction in the readonly path box
	$script:TxtSub.add_KeyDown({
		param($sender, $e)
		# prevent the default "ding" sound from read-only TextBox
		$e.SuppressKeyPress = $true
		if ($script:BrowseState.CanBrowse) { try { & $script:OpenSubfolderPicker } catch {} }
		else { try { $msg = (T 'tip.enter_password_and_encrypt'); $script:Tip.Show($msg, $script:TxtSub, 0, $script:TxtSub.Height + 2, 4000) } catch {} }
		try { $script:ButtonEncrypt.Focus() } catch {}
	})
	# Encrypt/Clear toggle
	$script:ButtonEncrypt.Add_Click({
		if ($script:EditSecretFile) {
			# FILE STORE: toggle between Encrypt and Delete secrets. Asking for the
			# passphrase, writing the file and clearing the session cache is the
			# program's business -- see Set-AccountEditorContext.
			if (& $script:EditHasSecret) { if (-not (& $script:EditRemoveSecret)) { return }; $script:TextPassword.Text = ''; $script:TextPassword.Enabled = $true }
			elseif ([string]::IsNullOrWhiteSpace($script:TextPassword.Text)) { Show-InfoT 'message.enter_password_first'; return }
			else { if (-not (& $script:EditWriteSecret $script:TextPassword.Text)) { return }; $script:TextPassword.Text = '' }
		} else {
			# PAIR STORE: toggle between Encrypt and Clear
			if (-not [string]::IsNullOrEmpty($script:Edit.EncPass)) { $ans = Ask-YesNoQuestT 'prompt.clear_stored_password'; if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) { return }; & $script:EditClearPassword <# wipe secret everywhere + persist #>; $script:TextPassword.Text = '' <# reset UI textbox immediately #> }
			elseif ([string]::IsNullOrWhiteSpace($script:TextPassword.Text)) { Show-InfoT 'message.enter_password_first'; return }
			else { try { & $script:EditSetPassword $script:TextPassword.Text } catch { Show-ErrorT 'message.store_password_failed' @{ err = $_.Exception.Message }; return } }
		}
		& $script:RefreshPasswordState
	})
	# Keep UI reactive if user edits the field
	$script:TextPassword.add_TextChanged({ & $script:RefreshPasswordState })
	# The password belongs to the server/user pair, so it is found the moment that
	# pair is complete: setting up a second mount of an account that is configured
	# elsewhere means typing the two names and finding nothing left to enter. A pair
	# without one empties the field again -- what the page shows has to be about the
	# pair in the boxes and not about the one that stood there a moment ago.
	$script:RefreshPairPassword = {
		if (-not $script:Edit) { return }
		# The working copy follows the boxes, and from here on everything that acts on
		# the pair acts on the one that is on screen: an account being added has no pair
		# anywhere else, and a password stored under an empty one is stored nowhere.
		$script:Edit.Server = $script:TextServer.Text.Trim()
		$script:Edit.User = $script:TextUser.Text.Trim()
		$script:Edit.EncPass = Get-AccountSecret -Server $script:Edit.Server -User $script:Edit.User
		& $script:RefreshPasswordState
	}
	$script:TextServer.add_TextChanged({ & $script:RefreshPairPassword })
	$script:TextUser.add_TextChanged({ & $script:RefreshPairPassword })
	# Initial state (now $script:ButtonBrowse exists)
	& $script:RefreshPasswordState
	# Drive selector
	$script:LabelDriveLetter = New-Object Windows.Forms.Label; $script:LabelDriveLetter.Text = (T 'label.drive'); $script:LabelDriveLetter.Left = 12; $script:LabelDriveLetter.Top = 132; $script:LabelDriveLetter.AutoSize = $true
	$script:ComboBoxDrive = New-Object Windows.Forms.ComboBox; $script:ComboBoxDrive.Top = 130; $script:ComboBoxDrive.Width = 60; $script:ComboBoxDrive.Left = $script:TextServer.Left; $script:ComboBoxDrive.DropDownStyle = 'DropDownList'; $script:ComboBoxDrive.Anchor = 'Top, Right'
	# Display name
	$script:LabelDisplayName = New-Object Windows.Forms.Label; $script:LabelDisplayName.Text = (T 'label.display_name'); $script:LabelDisplayName.Left = 12; $script:LabelDisplayName.Top = 162; $script:LabelDisplayName.AutoSize = $true
	$script:TxtDisp = New-Object Windows.Forms.TextBox; $script:TxtDisp.Top = 160; $script:TxtDisp.Width = $script:TextServer.Width; $script:TxtDisp.Left = $script:TextServer.Left; $script:TxtDisp.Text = $script:Edit.Label; $script:TxtDisp.Anchor = 'Top, Right'
	# Initial prefill for display name if empty (and remember that it was auto-filled)
	if ([string]::IsNullOrWhiteSpace($script:TxtDisp.Text)) {
		$script:TxtDisp.Text = (& $script:ComputeDefaultLabel $script:TxtSub.Text $script:TextUser.Text.Trim() $script:TextServer.Text.Trim())
		$script:BasicSettings_Auto.LastAuto = $script:TxtDisp.Text
	}
	$script:TextUser.add_TextChanged({
		$newDefault = (& $script:ComputeDefaultLabel $script:TxtSub.Text $script:TextUser.Text.Trim() $script:TextServer.Text.Trim())
		if ([string]::IsNullOrWhiteSpace($script:TxtDisp.Text) -or ($script:TxtDisp.Text -eq $script:BasicSettings_Auto.LastAuto)) { $script:TxtDisp.Text = $newDefault; $script:BasicSettings_Auto.LastAuto = $newDefault }
		& $script:UpdateSaveButton
	})
	# If the user edits the Display name manually, stop auto-overwriting
	$script:TxtDisp.add_TextChanged({ if ($script:TxtDisp.Focused) { $script:BasicSettings_Auto.LastAuto = $null }; & $script:UpdateSaveButton })
	# Rebind all Basic Settings controls from the edited account after an Import/Reload
	$script:RebindUIFromEdit = {
		try { $panelMain.SuspendLayout(); $panelFooter.SuspendLayout() } catch {} # Avoid flicker and cascading events
		try {
			$script:TextServer.Text = ($script:Edit.Server -as [string]); $script:TextUser.Text = ($script:Edit.User -as [string]) # Core fields
			# Subfolder textbox expects trimmed value ('' means no subpath)
			$sp = ($script:Edit.SubPath -as [string]); if ($sp -eq '/') { $sp = '' } else { $sp = ($sp -as [string]).Trim('/','\') }; $script:TxtSub.Text = $sp
			$script:TxtDisp.Text = ($script:Edit.Label -as [string]) # Display name exactly as persisted (do NOT recompute)
			$script:BasicSettings_Auto.LastAuto = $null # Prevent later auto-overwrite by the "auto" logic
			& $script:RebuildDriveList # Drive list + selection
			if ($script:Edit.Drive -and $script:ComboBoxDrive.Items.Contains($script:Edit.Drive)) { $script:ComboBoxDrive.SelectedItem = $script:Edit.Drive } else { <# Fallback: keep first free or current selection from RebuildDriveList #> }
			$script:ComboBoxDrive.Tag.Prev = if ($script:ComboBoxDrive.SelectedItem) { [string]$script:ComboBoxDrive.SelectedItem } else { $null }
			& $script:ApplyLanguageNow
		} finally { try { $panelMain.ResumeLayout($true); $panelFooter.ResumeLayout($true) } catch {} }
		$script:Baseline = & $script:GetPendingConfig # Make the freshly rebound UI the new baseline → no "unsaved changes" prompt
		& $script:UpdateSaveButton
	}
	# Buttons save and close
	$script:ButtonClose1 = New-Object Windows.Forms.Button; $script:ButtonClose1.Text = (T 'button.close'); $script:ButtonClose1.Width = 100; $script:ButtonClose1.Left = $panelFooter.ClientSize.Width - $script:ButtonClose1.Width - 2; $script:ButtonClose1.Height = $script:ButtonXH; $script:ButtonClose1.Top = 0; $script:ButtonClose1.Anchor = 'Top, Right'; $script:ButtonClose1.TabIndex = 1
	$script:ButtonSave = New-Object Windows.Forms.Button; $script:ButtonSave.Text = (T 'button.save'); $script:ButtonSave.Width = 100; $script:ButtonSave.Left = $script:ButtonClose1.Left - $script:ButtonSave.Width - 10; $script:ButtonSave.Height = $script:ButtonXH; $script:ButtonSave.Top = 0; $script:ButtonSave.Anchor = 'Top, Right'; $script:ButtonSave.TabIndex = 0
	# Set default buttons so Enter/Esc behave nicely
	$f.AcceptButton = $script:ButtonSave; $f.CancelButton = $script:ButtonClose1
	# Drive list with colors (used stays visible/red, not selectable; default = first free)
	Initialize-DriveLetterPicker -ComboBox $script:ComboBoxDrive -OnChanged { if ($script:UpdateSaveButton -is [scriptblock]) { & $script:UpdateSaveButton } }
	# Small rebuild helper, also used after an import brought another drive letter
	# The letters of the other configured mounts are out of the question here as
	# well: a letter one of them holds is taken whether or not it is connected right
	# now, and offering it would only make the mount fail the moment it comes up.
	$script:RebuildDriveList = { Update-DriveLetterPicker -ComboBox $script:ComboBoxDrive -Current $script:Edit.Drive -Reserved @(Get-ReservedDrives -ExceptId $script:Edit.Id) }
	# Build once
	& $script:RebuildDriveList
	# live language update helper (safe, no crash if some globals are not created yet)
	$script:ApplyLanguageNow = {
		# re-init i18n; the language itself comes from the shared family setting
		try { Initialize-I18n } catch {}
		# helper: safely set .Text on a control if it exists and supports Text
		$setTxt = { param($ctrl, $newText); if ($ctrl -and ($ctrl.PSObject.Properties.Name -contains 'Text')) { $ctrl.Text = $newText } }
		# helper: set localized ToolTip text on a control (static tips only; dynamic tips via RefreshPasswordState)
		$setTip = { param($ctrl, $key); if ($ctrl -and ($ctrl -is [System.Windows.Forms.Control])) { $script:Tip.SetToolTip($ctrl, (T $key)) } }
		# update dialog title
		& $setTxt $f (T 'title.settings_dialog' @{ app = $AppName })
		# update static labels / buttons in this window
		& $setTxt $script:LabelServer (T 'label.server')
		& $setTxt $script:LabelUser (T 'label.user')
		& $setTxt $script:LabelPassword (T 'app_password')
		& $setTxt $script:LabelSubfolder (T 'label.subfolder')
		& $setTxt $script:LabelDriveLetter (T 'label.drive')
		& $setTxt $script:LabelDisplayName (T 'label.display_name')
		& $setTxt $script:ButtonSave (T 'button.save')
		& $setTxt $script:ButtonClose1 (T 'button.close')
		# force-refresh all tooltips to avoid stale cached strings
		$script:Tip.RemoveAll()
		# apply i18n to static ToolTips
		& $setTip $script:TextServer 'tip.enter_server'
		& $setTip $script:TextUser 'tip.enter_user'
		& $setTip $script:ButtonPasswordHelp 'title.app_password_help'
		# dynamic ToolTips (txtSub/txtPwd) and encrypt/clear button text
		& $script:RefreshPasswordState
		# The tray and its menu belong to the program around this window and are
		# relabelled by it -- see Set-AccountEditorContext.
		& $script:EditApplyLanguage
	}
	# --- Dirty tracking (compare UI vs last-saved baseline) ---
	$script:GetPendingConfig = {
		# Normalize current UI state to what Save() would persist
		$sp = ($script:TxtSub.Text -as [string])
		if ($sp -eq '/') { $sp = '' } else { $sp = $sp.Trim('/','\') }
		return @{ Server = ($script:TextServer.Text.Trim()); User = ($script:TextUser.Text.Trim()); SubPath = $sp; Drive = [string]$script:ComboBoxDrive.SelectedItem; Label = $script:TxtDisp.Text }
	}
	# Baseline corresponds to the loaded/last saved state
	$script:Baseline = & $script:GetPendingConfig
	$script:HasUnsavedChanges = { $now = & $script:GetPendingConfig; foreach ($k in $script:Baseline.Keys) { if ( ($script:Baseline[$k] -as [string]) -ne ($now[$k] -as [string]) ) { return $true } } return $false }
	# Toggle Save button depending on dirty state
	$script:UpdateSaveButton = { try { if ($script:ButtonSave) { $dirty = (& $script:HasUnsavedChanges); $script:ButtonSave.Enabled = $dirty } } catch {} }
	& $script:UpdateSaveButton # Initial state
	$script:SuppressUnsavedCheck = $false
	# Warning dialog when closing (Close/Esc/[X])
	$f.add_FormClosing({
		param($sender, $e)
		if ($script:SuppressUnsavedCheck) { return }
		$dirty = $false
		try { $dirty = & $script:HasUnsavedChanges } catch {}
		if (-not $dirty) { return }
		$res = Ask-YesNoCancelQuestT 'prompt.unsaved_changes'
		switch ($res) {
			([System.Windows.Forms.DialogResult]::Yes) {
				# Cancel this close, then trigger Save AFTER the handler returns
				$e.Cancel = $true; $script:SuppressUnsavedCheck = $true # prevent re-prompt
				$f.BeginInvoke([System.Action]{ try { $script:ButtonSave.PerformClick() } catch {} }) | Out-Null
			}
			([System.Windows.Forms.DialogResult]::No) { $e.Cancel = $false } # Discard changes and close
			default { $e.Cancel = $true } # Cancel -> stay in dialog
		}
	})
	$script:ButtonSave.Add_Click({
		$savedOk = $false # prevent unsaved-prompt on intentional save-close
		$script:SuppressUnsavedCheck = $true
		try {
			$sel = [string]$script:ComboBoxDrive.SelectedItem
			if ([string]::IsNullOrWhiteSpace($script:TextServer.Text) -or [string]::IsNullOrWhiteSpace($script:TextUser.Text) -or -not ($sel -match '^[A-Za-z]:$')) { Show-InfoT 'message.fill_server_user_drive'; return }
			$usedNow = (Get-PSDrive -PSProvider FileSystem | Select-Object -Expand Name) | ForEach-Object { '{0}:' -f $_ }
			if ($sel -ne $script:Edit.Drive -and $usedNow -contains $sel) { Show-WarnT 'message.drive_already_in_use' @{ drive = $sel }; return }
			# What the running mount was built from. The working copy cannot say it any
			# more -- it has followed the boxes since the window opened -- but the baseline
			# is exactly the state that was last persisted.
			$oldServer = [string]$script:Baseline.Server
			$oldUser = [string]$script:Baseline.User
			$oldSubPath = [string]$script:Baseline.SubPath
			$oldDrive = [string]$script:Baseline.Drive
			# --- collect and persist password first (supports both flows: Encrypt or Save-only) ---
			if ($script:EditSecretFile) {
				# Nothing written yet but a password was typed: create the secret now
				if ((-not (& $script:EditHasSecret)) -and $script:TextPassword.Text -and ($script:TextPassword.Tag -ne 'info')) {
					if (-not (& $script:EditWriteSecret $script:TextPassword.Text)) { return }
					$script:TextPassword.Text = ''
				}
			# Pair store: if user typed a new password, persist immediately (DPAPI)
			} elseif ($script:TextPassword.Text -and ($script:TextPassword.Tag -ne 'info')) { try { & $script:EditSetPassword $script:TextPassword.Text } catch { Show-ErrorT 'message.store_password_failed' @{ err = $_.Exception.Message }; return } }
			# --- normalize subpath from UI (read-only textbox filled by picker) ---
			$valSub = $script:TxtSub.Text.Trim()
			if ($valSub -eq '/') { $valSub = '' } else { $valSub = $valSub.Trim('/').Replace('\', '/') }
			# --- validate subpath existence via OCS (only when not empty) ---
			if (-not [string]::IsNullOrWhiteSpace($valSub)) {
				# The password has to be usable before the folder can be asked about
				if (-not (& $script:EditUnlockSecret)) { return }
				if (-not (Test-NcFolderExists -Server $script:Edit.Server -User $script:Edit.User -Pass (& $script:EditPlainPassword) -SubPath $valSub)) { Show-WarnT 'message.folder_does_not_exist' @{ folder = $valSub }; return }
			}
			# now update State (safe)
			$script:Edit.SubPath = $valSub; $script:Edit.Drive = [string]$script:ComboBoxDrive.SelectedItem; $script:Edit.Label = $script:TxtDisp.Text
			& $script:EditSave | Out-Null
			# What the new values mean for the running mount is the program's business --
			# see Set-AccountEditorContext. The answer comes back in a flag: the calls in
			# there write to the output stream as well, and a return value would arrive
			# mixed in with that.
			$script:EditApplyOk = $true
			& $script:EditApplyChanges $oldServer $oldUser $oldSubPath $oldDrive | Out-Null
			if (-not $script:EditApplyOk) { return }
			$script:Baseline = & $script:GetPendingConfig # refresh "last saved" snapshot
			$savedOk = $true
			$f.DialogResult = [Windows.Forms.DialogResult]::OK
			$f.Close()
		}
		finally { if (-not $savedOk) { $script:SuppressUnsavedCheck = $false } }
	})
	$script:ButtonClose1.Add_Click({ $f.DialogResult = [Windows.Forms.DialogResult]::Cancel; $f.Close() })
	$panelMain.Controls.AddRange(@(
		$script:LabelServer, $script:PicFavicon, $script:TextServer,
		$script:LabelUser, $script:PicAvatar, $script:TextUser,
		$script:LabelPassword, $script:ButtonPasswordHelp, $script:TextPassword, $script:ButtonEncrypt,
		$script:LabelSubfolder, $script:TxtSub,
		$script:LabelDriveLetter, $script:ComboBoxDrive,
		$script:LabelDisplayName, $script:TxtDisp
	))
	$panelFooter.Controls.AddRange(@($script:ButtonSave, $script:ButtonClose1))
	# Cleanup timers and images when dialog closes
	$f.add_FormClosed({
		param($sender, $e)
		try { if ($script:FaviconTimer) { $script:FaviconTimer.Stop(); $script:FaviconTimer.Dispose() } } catch {}
		try { if ($script:AvatarTimer) { $script:AvatarTimer.Stop(); $script:AvatarTimer.Dispose() } } catch {}
		# break default buttons link to the form (defuse lingering refs)
		try { $sender.AcceptButton = $null; $sender.CancelButton = $null } catch {}
		# Dispose only the PictureBox-held clones; do NOT dispose global server/avatar bitmaps.
		try { if ($script:PicFavicon -and $script:PicFavicon.Image) { $script:PicFavicon.Image.Dispose(); $script:PicFavicon.Image = $null } } catch {}
		try { if ($script:PicAvatar -and $script:PicAvatar.Image) { $script:PicAvatar.Image.Dispose(); $script:PicAvatar.Image = $null } } catch {}
		# fully detach tooltip associations before disposing it
		try { if ($script:Tip) { $script:Tip.RemoveAll() } } catch {}
		try { if ($script:Tip) { $script:Tip.Dispose(); $script:Tip = $null } } catch {}
		# drop script-scope helpers/closures so GC can collect them
		try {
			$script:ComputeDefaultLabel = $null
			$script:OpenSubfolderPicker = $null
			$script:RefreshPasswordState = $null
			$script:RefreshPairPassword = $null
			$script:ApplyLanguageNow = $null
			$script:RebuildDriveList = $null
			$script:GetPendingConfig = $null
			$script:HasUnsavedChanges = $null
			$script:UpdateSaveButton = $null
			$script:RebindUIFromEdit = $null
			$script:BasicSettings_Auto = $null
			$script:BrowseState = $null
		} catch {}
		# encourage prompt collection of now-unrooted closures
		try { [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers() } catch {}
		try {
			$script:HostForm = $null
			$script:TextServer = $null; $script:TextUser = $null; $script:TxtSub = $null; $script:TextPassword = $null; $script:TxtDisp = $null
			$script:ComboBoxDrive = $null
			$script:ButtonPasswordHelp = $null; $script:ButtonEncrypt = $null; $script:ButtonSave = $null; $script:ButtonClose1 = $null
			$script:PicFavicon = $null; $script:PicAvatar = $null
			$script:FaviconTimer = $null; $script:AvatarTimer = $null
		} catch {}
	})
}
