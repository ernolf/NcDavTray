# The one place where the whole configuration is visible and editable. Adding,
# editing and removing all go through the same functions the tray menus use, so
# this tab holds no state of its own -- it shows what the configuration says
# and asks the list again after every action.
# It is also the only way back to a mount the user disconnected: a disabled mount
# has no tray icon.
# The language sits here and nowhere else: it is a setting of the installation,
# not of a single mount.
function Render-SharesTab {
	[CmdletBinding()] param([Parameter(Mandatory)][System.Windows.Forms.TabPage]$HostTab)
	$f = $script:HostForm

	# Row 0 holds the list beside its buttons, row 1 the footer across both columns.
	$mainPanel = New-Object System.Windows.Forms.TableLayoutPanel
	$mainPanel.ColumnCount = 2; $mainPanel.RowCount = 2
	$mainPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
	$mainPanel.Padding = New-Object System.Windows.Forms.Padding(12, 12, 12, 12)
	[void]$mainPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
	[void]$mainPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
	[void]$mainPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
	[void]$mainPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))

	$lv = $script:ShareListView = New-Object System.Windows.Forms.ListView
	$lv.View = [System.Windows.Forms.View]::Details
	$lv.FullRowSelect = $true; $lv.MultiSelect = $false; $lv.HideSelection = $false
	$lv.Dock = [System.Windows.Forms.DockStyle]::Fill
	$lv.Margin = New-Object System.Windows.Forms.Padding(0, 0, 12, 0)
	# No widths here: what a name, a server or a status needs is only known once
	# there is one, and it is another number in every language -- see
	# Update-ListViewColumns.
	[void]$lv.Columns.Add((T 'label.name'))
	[void]$lv.Columns.Add((T 'label.server'))
	[void]$lv.Columns.Add((T 'label.drive'))
	[void]$lv.Columns.Add((T 'label.status'))
	# One icon per row, and it is the icon the mount has in the tray rather than a
	# marker of its own: with the tray icons switched off this list is where the
	# colour is, and it says the same thing there as it says next to the clock.
	# The shell is asked for the size, the same way New-StatusIcon asks it.
	$script:ShareStatusIcons = New-Object System.Windows.Forms.ImageList
	$iconSize = 16
	try { $iconSize = [System.Windows.Forms.SystemInformation]::SmallIconSize.Width } catch {}
	$script:ShareStatusIcons.ImageSize = New-Object System.Drawing.Size([Math]::Max(16, $iconSize), [Math]::Max(16, $iconSize))
	$script:ShareStatusIcons.ColorDepth = [System.Windows.Forms.ColorDepth]::Depth32Bit
	$lv.SmallImageList = $script:ShareStatusIcons

	$sidePanel = New-Object System.Windows.Forms.FlowLayoutPanel
	$sidePanel.AutoSize = $true; $sidePanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$sidePanel.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
	$sidePanel.WrapContents = $false
	$sidePanel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)
	# The window does not resize, and this is the tallest fixed thing in it. What
	# the row leaves it is only known once the window is there, so Show-SettingsDialog
	# measures it in Load and gives the form what is missing.
	$script:ShareButtonPanel = $sidePanel

	# What can be added is a list that grows -- a share link, an account, and the
	# kinds that come after them -- so Add opens a menu instead of standing for one
	# of them; see Show-AddMenu. The arrow is written as a code point because the
	# script carries no byte order mark and is not read as UTF-8 without one.
	$script:ButtonShareAdd = New-Object System.Windows.Forms.Button
	$script:ButtonShareAdd.Text = "{0} {1}" -f (T 'button.add'), [char]0x25BE
	$script:ButtonShareEdit = New-Object System.Windows.Forms.Button; $script:ButtonShareEdit.Text = (T 'button.edit')
	$script:ButtonShareDuplicate = New-Object System.Windows.Forms.Button; $script:ButtonShareDuplicate.Text = (T 'button.duplicate')
	$script:ButtonShareRemove = New-Object System.Windows.Forms.Button; $script:ButtonShareRemove.Text = (T 'button.remove')
	$script:ButtonShareConnect = New-Object System.Windows.Forms.Button; $script:ButtonShareConnect.Text = (T 'menu.connect')
	$script:ButtonShareDisconnect = New-Object System.Windows.Forms.Button; $script:ButtonShareDisconnect.Text = (T 'menu.disconnect')
	# The one thing a mount could only be asked for from its own tray icon. With the
	# icons switched off it would be out of reach, so it is here as well -- under the
	# short label, because this column is as wide as its longest one and every pixel
	# it takes is one the list beside it loses.
	$script:ButtonShareOpen = New-Object System.Windows.Forms.Button; $script:ButtonShareOpen.Text = (T 'button.open')
	$script:ShareButtons = @($script:ButtonShareAdd, $script:ButtonShareEdit, $script:ButtonShareDuplicate, $script:ButtonShareRemove, $script:ButtonShareConnect, $script:ButtonShareDisconnect, $script:ButtonShareOpen)
	foreach ($btn in $script:ShareButtons) {
		$btn.AutoSize = $false
		$btn.Height = $script:ButtonXH
		$btn.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)
		[void]$sidePanel.Controls.Add($btn)
	}
	# One width for all of them, and it is the one the longest label needs. Left to
	# themselves they are each as wide as their own text, and a column of buttons
	# that all end somewhere else has no edge to line up with the list beside it.
	# It is worked out again after a language change, where another label is the
	# longest one.
	$script:SizeShareButtons = {
		$width = $script:ButtonMinW
		foreach ($btn in $script:ShareButtons) { $width = [Math]::Max($width, $btn.PreferredSize.Width) }
		foreach ($btn in $script:ShareButtons) { $btn.Width = $width }
	}
	& $script:SizeShareButtons
	# Everything but Add needs a row to work on
	foreach ($btn in @($script:ButtonShareEdit, $script:ButtonShareDuplicate, $script:ButtonShareRemove, $script:ButtonShareConnect, $script:ButtonShareDisconnect, $script:ButtonShareOpen)) { $btn.Enabled = $false }

	# Footer: everything that is set once for the whole installation, stacked the way
	# it was at the bottom of the account page it comes from. It sat there for as
	# long as there was one account; an interval, a language and an installation are
	# not properties of a single drive, so they live here now.
	# The list above gives up the space -- it scrolls, this does not.
	$footerPanel = New-Object System.Windows.Forms.TableLayoutPanel
	$footerPanel.ColumnCount = 1; $footerPanel.RowCount = 6
	$footerPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
	$footerPanel.AutoSize = $true; $footerPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$footerPanel.Margin = New-Object System.Windows.Forms.Padding(0, 12, 0, 0)
	[void]$footerPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
	for ($row = 0; $row -lt $footerPanel.RowCount; $row++) { [void]$footerPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) }

	# Which mode this copy runs in. What the window below can offer follows from
	# it: an installed copy is taken out again from here, a portable one is put in.
	$script:LabelMode = New-Object System.Windows.Forms.Label
	if ($PortableMode) { $script:LabelMode.Text = (T 'mode.portable'); $script:LabelMode.ForeColor = [System.Drawing.Color]::ForestGreen; $script:LabelMode.Font = New-Object System.Drawing.Font($UiFontFamily, 10, $UiFontStyleBold) }
	else { $script:LabelMode.Text = (T 'mode.installed'); $script:LabelMode.ForeColor = [System.Drawing.Color]::SteelBlue; $script:LabelMode.Font = New-Object System.Drawing.Font($UiFontFamily, 9, $UiFontStyleBold) }
	$script:LabelMode.AutoSize = $true; $script:LabelMode.Anchor = 'Top, Left'
	$script:LabelMode.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)
	# Whether the mounts show up in the tray at all. It shares the line with the mode,
	# which is one word against the width of the window: the switch costs no row of
	# its own there, and it is read on the way past instead of sitting among the boxes
	# below, which are about the installation. This one is not -- a portable copy has
	# a tray like any other, so it works where the three below it are switched off.
	# The box belongs in this window and nowhere else: with the icons gone there would
	# be no mount menu left to find it in.
	$modePanel = New-Object System.Windows.Forms.TableLayoutPanel
	$modePanel.Dock = [System.Windows.Forms.DockStyle]::Fill
	$modePanel.AutoSize = $true; $modePanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$modePanel.RowCount = 1; $modePanel.ColumnCount = 2
	$modePanel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)
	$modePanel.ColumnStyles.Clear()
	[void]$modePanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
	[void]$modePanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
	[void]$modePanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
	# Right and nothing else: the row is as tall as the mode word, which is set in a
	# larger face than the box, and anchoring it to the top would leave it hanging.
	$script:CheckboxTrayIcons = New-Object System.Windows.Forms.CheckBox; $script:CheckboxTrayIcons.Text = (T 'box.tray_icons'); $script:CheckboxTrayIcons.AutoSize = $true; $script:CheckboxTrayIcons.Anchor = 'Right'; $script:CheckboxTrayIcons.Checked = [bool]$State.TrayIcons
	$script:CheckboxTrayIcons.Margin = New-Object System.Windows.Forms.Padding(12, 0, 0, 6)
	[void]$modePanel.Controls.Add($script:LabelMode, 0, 0)
	[void]$modePanel.Controls.Add($script:CheckboxTrayIcons, 1, 0)

	# Poll interval and language on one line. The last column takes what is left,
	# so the import button ends flush with the button rows below it -- on the page
	# this comes from it was sized to the panel edge for the same reason.
	$globalsPanel = New-Object System.Windows.Forms.TableLayoutPanel
	$globalsPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
	$globalsPanel.AutoSize = $true; $globalsPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$globalsPanel.RowCount = 1; $globalsPanel.ColumnCount = 5
	$globalsPanel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)
	$globalsPanel.ColumnStyles.Clear()
	for ($col = 0; $col -lt 4; $col++) { [void]$globalsPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) }
	[void]$globalsPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
	[void]$globalsPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))

	$script:LabelCheckInterval = New-Object System.Windows.Forms.Label
	$script:LabelCheckInterval.Text = (T 'label.checkinterval'); $script:LabelCheckInterval.AutoSize = $true
	# Widths as they were on the account page this block comes from: the label is
	# given the room up to the field beside it, so the field sits where it sat. A
	# longer translation pushes the row along instead of running underneath it.
	$script:LabelCheckInterval.MinimumSize = New-Object System.Drawing.Size(123, 0)
	$script:LabelCheckInterval.Margin = New-Object System.Windows.Forms.Padding(0, 9, 0, 0)
	$script:NumInterval = New-Object System.Windows.Forms.NumericUpDown
	$script:NumInterval.Minimum = 5; $script:NumInterval.Maximum = 600; $script:NumInterval.Width = 45
	$script:NumInterval.Value = ([Math]::Min(600, [Math]::Max(5, [int]$State.IntervalS)))
	$script:NumInterval.Margin = New-Object System.Windows.Forms.Padding(0, 6, 24, 0)
	# This window has no Save button. What is changed here is in force at once, the
	# same way the language beside it is.
	$script:NumInterval.add_ValueChanged({
			$State.IntervalS = [int]$script:NumInterval.Value
			Save-Config
			try { if ($script:timer) { $script:timer.Interval = ([Math]::Max(5, [int]$State.IntervalS) * 1000) } } catch {}
		})

	# Language preference combo ("Auto" + available languages)
	$script:LabelLanguage = New-Object System.Windows.Forms.Label
	$script:LabelLanguage.Text = (T 'label.language'); $script:LabelLanguage.AutoSize = $true
	$script:LabelLanguage.MinimumSize = New-Object System.Drawing.Size(90, 0)
	$script:LabelLanguage.Margin = New-Object System.Windows.Forms.Padding(0, 9, 0, 0)
	$script:ComboBoxLanguage = New-Object System.Windows.Forms.ComboBox
	$script:ComboBoxLanguage.Width = 60; $script:ComboBoxLanguage.DropDownStyle = 'DropDownList'
	$script:ComboBoxLanguage.Margin = New-Object System.Windows.Forms.Padding(0, 6, 10, 0)
	$script:ButtonLanguageImport = New-Object System.Windows.Forms.Button
	$script:ButtonLanguageImport.Text = (T 'button.install_language')
	$script:ButtonLanguageImport.AutoSize = $false
	$script:ButtonLanguageImport.Height = $script:ButtonH
	$script:ButtonLanguageImport.Anchor = 'Left, Right'
	$script:ButtonLanguageImport.Margin = New-Object System.Windows.Forms.Padding(0, 3, 0, 0)
	[void]$globalsPanel.Controls.Add($script:LabelCheckInterval, 0, 0)
	[void]$globalsPanel.Controls.Add($script:NumInterval, 1, 0)
	[void]$globalsPanel.Controls.Add($script:LabelLanguage, 2, 0)
	[void]$globalsPanel.Controls.Add($script:ComboBoxLanguage, 3, 0)
	[void]$globalsPanel.Controls.Add($script:ButtonLanguageImport, 4, 0)

	# Autostart and shortcuts, one column each
	$checkPanel = New-Object System.Windows.Forms.TableLayoutPanel
	$checkPanel.Dock = [System.Windows.Forms.DockStyle]::Fill; $checkPanel.Height = 30
	$checkPanel.RowCount = 1; $checkPanel.ColumnCount = 3; $checkPanel.GrowStyle = 'FixedSize'
	$checkPanel.Margin = New-Object System.Windows.Forms.Padding(0, 8, 0, 0)
	$checkPanel.ColumnStyles.Clear()
	[void]$checkPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 34)))
	[void]$checkPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 34)))
	[void]$checkPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 32)))
	$script:CheckboxAutostart = New-Object System.Windows.Forms.CheckBox; $script:CheckboxAutostart.Text = (T 'box.autostart'); $script:CheckboxAutostart.AutoSize = $true; $script:CheckboxAutostart.Anchor = 'Top, Left'; $script:CheckboxAutostart.Checked = (Is-StartupRunKeyEnabled $AppName)
	$script:CheckboxShortcutStartmenu = New-Object System.Windows.Forms.CheckBox; $script:CheckboxShortcutStartmenu.Text = (T 'box.shortcut_startmenu'); $script:CheckboxShortcutStartmenu.AutoSize = $true; $script:CheckboxShortcutStartmenu.Anchor = 'Top, Left'; $script:CheckboxShortcutStartmenu.Checked = (Shortcut-Exists 'StartMenu' $AppName)
	$script:CheckboxShortcutDesktop = New-Object System.Windows.Forms.CheckBox; $script:CheckboxShortcutDesktop.Text = (T 'box.shortcut_desktop'); $script:CheckboxShortcutDesktop.AutoSize = $true; $script:CheckboxShortcutDesktop.Anchor = 'Top, Left'; $script:CheckboxShortcutDesktop.Checked = (Shortcut-Exists 'Desktop' $AppName)
	[void]$checkPanel.Controls.Add($script:CheckboxAutostart, 0, 0)
	[void]$checkPanel.Controls.Add($script:CheckboxShortcutStartmenu, 1, 0)
	[void]$checkPanel.Controls.Add($script:CheckboxShortcutDesktop, 2, 0)

	# Two rows of two, as they were: install/uninstall beside the config export,
	# the config import beside the portable export.
	$btnRow1 = New-Object System.Windows.Forms.TableLayoutPanel
	$btnRow2 = New-Object System.Windows.Forms.TableLayoutPanel
	foreach ($panel in @($btnRow1, $btnRow2)) {
		$panel.Dock = [System.Windows.Forms.DockStyle]::Fill; $panel.Height = $script:ButtonXH + 2
		$panel.RowCount = 1; $panel.ColumnCount = 3; $panel.GrowStyle = 'FixedSize'; $panel.AutoSize = $false
		$panel.Margin = New-Object System.Windows.Forms.Padding(0, 6, 0, 0)
		$panel.ColumnStyles.Clear()
		[void]$panel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
		[void]$panel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 10)))
		[void]$panel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
	}
	$script:ButtonInstall = New-Object System.Windows.Forms.Button; $script:ButtonInstall.Text = (T 'button.install2appdata')
	$script:ButtonUninstall = New-Object System.Windows.Forms.Button; $script:ButtonUninstall.Text = (T 'button.uninstall')
	$script:ButtonExportConfig = New-Object System.Windows.Forms.Button; $script:ButtonExportConfig.Text = (T 'button.export_config')
	$script:ButtonImportConfig = New-Object System.Windows.Forms.Button; $script:ButtonImportConfig.Text = (T 'button.import_config')
	$script:ButtonExportToPortable = New-Object System.Windows.Forms.Button; $script:ButtonExportToPortable.Text = (T 'button.export2portable')
	foreach ($btn in @($script:ButtonInstall, $script:ButtonUninstall, $script:ButtonExportConfig, $script:ButtonImportConfig, $script:ButtonExportToPortable)) {
		$btn.Dock = [System.Windows.Forms.DockStyle]::Fill; $btn.Height = $script:ButtonXH
	}
	[void]$btnRow1.Controls.Add($script:ButtonInstall, 0, 0); [void]$btnRow1.Controls.Add($script:ButtonUninstall, 0, 0); [void]$btnRow1.Controls.Add($script:ButtonExportConfig, 2, 0)
	[void]$btnRow2.Controls.Add($script:ButtonImportConfig, 0, 0); [void]$btnRow2.Controls.Add($script:ButtonExportToPortable, 2, 0)
	# A portable copy has no place to start from and nothing to uninstall, it is
	# already what an export to portable would produce, and it keeps no password it
	# could hand out again. What it does offer is the way into the install folder,
	# and a language file goes into an installation, not into a folder that travels.
	if ($PortableMode) {
		$script:CheckboxAutostart.Enabled = $false; $script:CheckboxShortcutStartmenu.Enabled = $false; $script:CheckboxShortcutDesktop.Enabled = $false
		$script:ButtonInstall.Visible = $true; $script:ButtonUninstall.Visible = $false
		$script:ButtonExportConfig.Visible = $false; $script:ButtonExportToPortable.Visible = $false
		$script:ButtonLanguageImport.Visible = $false
	}
	else {
		$script:ButtonInstall.Visible = $false; $script:ButtonUninstall.Visible = $true
		$script:ButtonExportConfig.Visible = $true; $script:ButtonExportToPortable.Visible = $true
		$script:ButtonLanguageImport.Visible = $true
	}

	$closePanel = New-Object System.Windows.Forms.FlowLayoutPanel
	$closePanel.AutoSize = $true; $closePanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$closePanel.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft
	$closePanel.WrapContents = $false
	$closePanel.Anchor = 'Top, Right'
	$closePanel.Margin = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)
	$script:ButtonClose1 = New-Object System.Windows.Forms.Button
	$script:ButtonClose1.Text = (T 'button.close')
	$script:ButtonClose1.AutoSize = $true; $script:ButtonClose1.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowOnly
	$script:ButtonClose1.Height = $script:ButtonXH
	$script:ButtonClose1.MaximumSize = New-Object System.Drawing.Size(0, $script:ButtonClose1.Height)
	$script:ButtonClose1.MinimumSize = New-Object System.Drawing.Size($script:ButtonMinW, 0)
	$script:ButtonClose1.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)
	[void]$closePanel.Controls.Add($script:ButtonClose1)
	$f.CancelButton = $script:ButtonClose1

	# Guard to suppress the change handler during programmatic combo updates
	$script:IsLangComboInternalUpdate = $false
	# Helper to rebuild language list (available language packs)
	$script:RefreshLangList = {
		$langs = Get-AvailableLanguages
		$script:IsLangComboInternalUpdate = $true
		try {
			$script:ComboBoxLanguage.Items.Clear()
			[void]$script:ComboBoxLanguage.Items.Add('Auto')
			foreach ($l in $langs) { [void]$script:ComboBoxLanguage.Items.Add($l) }
			# Select current preference
			$pref = $State.LangPref
			$script:ComboBoxLanguage.SelectedItem = if (-not [string]::IsNullOrWhiteSpace($pref) -and $script:ComboBoxLanguage.Items.Contains($pref)) { $pref } else { 'Auto' }
		} finally {
			$script:IsLangComboInternalUpdate = $false
		}
	}
	# Put the new language on every control this window owns -- all three tabs, since
	# the language is picked on this one. The tray menus write their own labels when
	# they open, so they need nothing from here.
	$script:ApplyLanguageNow = {
		$setTxt = { param($ctrl, $newText); if ($ctrl -and ($ctrl.PSObject.Properties.Name -contains 'Text')) { $ctrl.Text = $newText } }
		$setTip = { param($ctrl, $key); if ($ctrl -and ($ctrl -is [System.Windows.Forms.Control])) { $script:Tip.SetToolTip($ctrl, (T $key)) } }
		& $setTxt $f (T 'title.settings_dialog' @{ app = $AppName })
		& $setTxt $script:TabShares (T 'tab.shares')
		& $setTxt $script:TabTuning (T 'tab.webclient_tuning')
		& $setTxt $script:TabCache (T 'tab.webdav_cache')
		# Shares tab
		& $setTxt $script:ButtonShareAdd ("{0} {1}" -f (T 'button.add'), [char]0x25BE)
		& $setTxt $script:ButtonShareEdit (T 'button.edit')
		& $setTxt $script:ButtonShareDuplicate (T 'button.duplicate')
		& $setTxt $script:ButtonShareRemove (T 'button.remove')
		& $setTxt $script:ButtonShareConnect (T 'menu.connect')
		& $setTxt $script:ButtonShareDisconnect (T 'menu.disconnect')
		& $setTxt $script:ButtonShareOpen (T 'button.open')
		& $script:SizeShareButtons
		& $setTxt $script:LabelCheckInterval (T 'label.checkinterval')
		& $setTxt $script:LabelLanguage (T 'label.language')
		& $setTxt $script:ButtonLanguageImport (T 'button.install_language')
		& $setTxt $script:CheckboxAutostart (T 'box.autostart')
		& $setTxt $script:CheckboxShortcutStartmenu (T 'box.shortcut_startmenu')
		& $setTxt $script:CheckboxShortcutDesktop (T 'box.shortcut_desktop')
		& $setTxt $script:CheckboxTrayIcons (T 'box.tray_icons')
		if ($PortableMode) { & $setTxt $script:LabelMode (T 'mode.portable') } else { & $setTxt $script:LabelMode (T 'mode.installed') }
		& $setTxt $script:ButtonInstall (T 'button.install2appdata')
		& $setTxt $script:ButtonUninstall (T 'button.uninstall')
		& $setTxt $script:ButtonExportConfig (T 'button.export_config')
		& $setTxt $script:ButtonImportConfig (T 'button.import_config')
		& $setTxt $script:ButtonExportToPortable (T 'button.export2portable')
		& $setTxt $script:ButtonClose1 (T 'button.close')
		if ($script:ShareListView -and -not $script:ShareListView.IsDisposed) {
			$cols = $script:ShareListView.Columns
			if ($cols.Count -ge 4) { $cols[0].Text = (T 'label.name'); $cols[1].Text = (T 'label.server'); $cols[2].Text = (T 'label.drive'); $cols[3].Text = (T 'label.status') }
			Update-ListViewColumns $script:ShareListView
		}
		# WebClient tuning tab labels/buttons
		& $setTxt $script:LabelBasicAuthLevel (T 'label.basic_auth_level')
		& $setTxt $script:LabelFilesPerFolder (T 'label.file_attributes_limit')
		& $setTxt $script:LabelFileSizeLimit (T 'label.file_size_limit')
		& $setTxt $script:LabelLocalServerTimeout (T 'label.local_server_timeout')
		& $setTxt $script:LabelInternetServerTimeout (T 'label.internet_server_timeout')
		& $setTxt $script:LabelSendReceiveTimeout (T 'label.send_receive_timeout')
		& $setTxt $script:LabelServerNotFoundCacheLifeTime (T 'label.server_not_found_cache_lifetime')
		& $setTxt $script:LabelServiceStatus (T 'label.service_status')
		& $setTxt $script:LabelServiceStartType (T 'label.service_starttype')
		& $setTxt $script:ButtonServiceTriggerInfo (T 'button.triggerinfo')
		& $setTxt $script:ButtonServiceStart (T 'button.start_service')
		& $setTxt $script:ButtonServiceRestart (T 'button.restart_service')
		& $setTxt $script:ButtonApplyAsAdmin (T 'button.uac_apply_changes')
		& $setTxt $script:ButtonClose2 (T 'button.close')
		# WebDAV cache tab labels/buttons
		& $setTxt $script:CacheWatcherStartButton (T 'button.cache_watcher_start')
		& $setTxt $script:CacheWatcherStopButton (T 'button.cache_watcher_stop')
		& $setTxt $script:CacheWatcherLiveCheckbox (T 'box.cache_live_update')
		& $setTxt $script:ButtonCacheRefresh (T 'button.refresh')
		& $setTxt $script:CacheClearOnExitCheckbox (T 'box.cache_clear_on_exit')
		& $setTxt $script:ButtonCacheDeleteAll (T 'button.clear_cache')
		if ($script:CacheListView -and -not $script:CacheListView.IsDisposed) {
			$cols = $script:CacheListView.Columns
			if ($cols.Count -ge 4) { $cols[0].Text = (T 'column.cache_name'); $cols[1].Text = (T 'column.cache_size'); $cols[2].Text = (T 'column.cache_modified'); $cols[3].Text = (T 'column.cache_type') }
		}
		# force-refresh all tooltips to avoid stale cached strings
		$script:Tip.RemoveAll()
		& $setTip $script:ComboBoxBasicAuthLevel 'tip.basic_auth'
		& $setTip $script:ButtonLocalServerTimeoutHelp 'tip.local_server_timeout_help'
		& $setTip $script:ButtonInternetServerTimeoutHelp 'tip.internet_server_timeout_help'
		& $setTip $script:ButtonSendReceiveTimeoutHelp 'tip.send_receive_timeout_help'
		& $setTip $script:ButtonServerNotFoundCacheLifeTimeHelp 'tip.server_not_found_cache_lifetime_help'
		# --- Refresh i18n text in combo boxes ---
		# BasicAuthLevel combo: rebuild items with new translations, keep selection
		if ($script:ComboBoxBasicAuthLevel -is [System.Windows.Forms.ComboBox] -and -not $script:ComboBoxBasicAuthLevel.IsDisposed) {
			$oldIdx = $script:ComboBoxBasicAuthLevel.SelectedIndex; $script:BalGuard = $true
			try {
				$script:ComboBoxBasicAuthLevel.Items.Clear()
				[void]$script:ComboBoxBasicAuthLevel.Items.Add((T 'combo.basic_auth_level_0'))
				[void]$script:ComboBoxBasicAuthLevel.Items.Add((T 'combo.basic_auth_level_1'))
				[void]$script:ComboBoxBasicAuthLevel.Items.Add((T 'combo.basic_auth_level_2'))
				if ($oldIdx -ge 0 -and $oldIdx -lt $script:ComboBoxBasicAuthLevel.Items.Count) { $script:ComboBoxBasicAuthLevel.SelectedIndex = $oldIdx }
			}
			finally { $script:BalGuard = $false }
		}
		# WebClient service start type combo: rebuild items with new translations, keep selection
		if ($script:ComboServiceStartType -is [System.Windows.Forms.ComboBox] -and -not $script:ComboServiceStartType.IsDisposed) {
			$oldIdx = $script:ComboServiceStartType.SelectedIndex
			try {
				$script:ComboServiceStartType.Items.Clear()
				[void]$script:ComboServiceStartType.Items.Add((T 'combo.webclient_start_automatic'))
				[void]$script:ComboServiceStartType.Items.Add((T 'combo.webclient_start_manual'))
				[void]$script:ComboServiceStartType.Items.Add((T 'combo.webclient_start_disabled'))
				if ($oldIdx -ge 0 -and $oldIdx -lt $script:ComboServiceStartType.Items.Count) { $script:ComboServiceStartType.SelectedIndex = $oldIdx }
			} catch {}
		}
		# Ensure Apply button dirty state reflects the new texts / selections
		if ($script:UpdateWebClientApplyButton -is [scriptblock]) { & $script:UpdateWebClientApplyButton }
		# re-apply dynamic WebClient status tooltip
		$lastState = $null
		if ($script:LabelServiceStatus -and $script:LabelServiceStatus.Tag) { $lastState = [string]$script:LabelServiceStatus.Tag.State }
		if ($script:SetWebClientStatusLabel -is [scriptblock] -and -not [string]::IsNullOrWhiteSpace($lastState)) { & $script:SetWebClientStatusLabel $lastState }
		# re-render the zone label in the new language
		if ($script:LabelActiveScope) { try { & $script:UpdateActiveScopeLabel $script:LabelActiveScope } catch { $script:LabelActiveScope.Visible = $false } }
	}
	# Click handler for language import
	$script:ButtonLanguageImport.Add_Click({
			try {
				$dlg = New-Object System.Windows.Forms.OpenFileDialog
				$dlg.Title = (T 'title.install_language')
				$dlg.Filter = ('i18n JSON ({0}.*.json) | {0}.*.json|JSON (*.json)|*.json' -f (Get-I18nBaseName))
				$dlg.InitialDirectory = [Environment]::GetFolderPath('Desktop')
				if ($dlg.ShowDialog() -ne 'OK') { return }
				# Copy chosen i18n file next to the script, where Resolve-I18nFilePath looks
				$destDir = Join-Path $HereDir 'i18n'
				if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
				$bn = [System.IO.Path]::GetFileName($dlg.FileName)
				Copy-Item -LiteralPath $dlg.FileName -Destination (Join-Path $destDir $bn) -Force
				# Refresh combo now that a new language might be available
				& $script:RefreshLangList
				try { Show-InfoT 'message.lang_imported' @{ path = $bn } } catch {}
			} catch { Show-ErrorT 'message.import_failed' @{ err = $_.Exception.Message } }
		})
	# The same way the tray menu sets it: configuration and tray tooltip in one place.
	$script:ComboBoxLanguage.add_SelectedIndexChanged({
			if ($script:IsLangComboInternalUpdate) { return }
			$sel = [string]$script:ComboBoxLanguage.SelectedItem
			Set-UiLanguage $(if ($sel -and $sel -ne 'Auto') { $sel } else { '' })
			& $script:ApplyLanguageNow
		})

	# The list decides two widths, and neither of them is known before it has one:
	# its own columns, and the mode line below it, which sits in a row that runs on
	# under the buttons beside the list and may not follow it that far.
	$lv.Add_SizeChanged({
			Update-ListViewColumns $script:ShareListView
			if ($script:LabelMode -and -not $script:LabelMode.IsDisposed) {
				$script:LabelMode.MaximumSize = New-Object System.Drawing.Size($script:ShareListView.Width, 0)
			}
		})

	# The handlers read the selected row straight from the list: writing the id into
	# a variable of the enclosing function is not possible from inside a handler.
	$lv.Add_SelectedIndexChanged({
			$sel = ($script:ShareListView.SelectedItems.Count -gt 0)
			$script:ButtonShareEdit.Enabled = $sel; $script:ButtonShareRemove.Enabled = $sel
			$script:ButtonShareDuplicate.Enabled = $sel
			$script:ButtonShareConnect.Enabled = $sel; $script:ButtonShareDisconnect.Enabled = $sel
			# Explorer needs a drive that answers, which the tray menu reads from the last
			# poll for the same reason -- see the Opening handler in New-MountTray.
			$live = $false
			if ($sel) { $rec = $script:Trays[[string]$script:ShareListView.SelectedItems[0].Tag]; $live = [bool]($rec -and $rec.Status -eq 'online') }
			$script:ButtonShareOpen.Enabled = $live
		})
	$script:ButtonShareAdd.Add_Click({ Show-AddMenu -Under $this -OnAdded { Update-ShareListView $script:ShareListView } })
	$script:ButtonShareEdit.Add_Click({
			if ($script:ShareListView.SelectedItems.Count -eq 0) { return }
			Update-ShareById ([string]$script:ShareListView.SelectedItems[0].Tag); Update-ShareListView $script:ShareListView
		})
	$script:ButtonShareDuplicate.Add_Click({
			if ($script:ShareListView.SelectedItems.Count -eq 0) { return }
			Copy-ShareById ([string]$script:ShareListView.SelectedItems[0].Tag); Update-ShareListView $script:ShareListView
		})
	$script:ButtonShareRemove.Add_Click({
			if ($script:ShareListView.SelectedItems.Count -eq 0) { return }
			Remove-ShareById ([string]$script:ShareListView.SelectedItems[0].Tag); Update-ShareListView $script:ShareListView
		})
	$script:ButtonShareConnect.Add_Click({
			if ($script:ShareListView.SelectedItems.Count -eq 0) { return }
			Connect-MountById ([string]$script:ShareListView.SelectedItems[0].Tag); Update-ShareListView $script:ShareListView
		})
	$script:ButtonShareDisconnect.Add_Click({
			if ($script:ShareListView.SelectedItems.Count -eq 0) { return }
			Disconnect-MountById ([string]$script:ShareListView.SelectedItems[0].Tag); Update-ShareListView $script:ShareListView
		})
	$script:ButtonShareOpen.Add_Click({
			if ($script:ShareListView.SelectedItems.Count -eq 0) { return }
			Open-MountInExplorer ([string]$script:ShareListView.SelectedItems[0].Tag)
		})
	$lv.Add_DoubleClick({
			if ($script:ShareListView.SelectedItems.Count -eq 0) { return }
			Update-ShareById ([string]$script:ShareListView.SelectedItems[0].Tag); Update-ShareListView $script:ShareListView
		})
	# A checkbox here is about the installation, not about the program that happens
	# to show it. On a failure the box goes back to where it was, so it never claims
	# something that did not happen.
	$script:CheckboxAutostart.Add_Click({
			if ($PortableMode) { return }
			try {
				Set-StartupRunKey $this.Checked $AppName $InstallBin
			}
			catch { try { $this.Checked = -not $this.Checked } catch {}; try { Show-ErrorT 'message.operation_failed' @{ err = $_.Exception.Message } } catch {} }
		})
	$script:CheckboxShortcutStartmenu.Add_Click({
			if ($PortableMode) { return }
			try {
				Ensure-Shortcut 'StartMenu' $this.Checked $AppName $InstallBin $AppNameShort
			}
			catch { try { $this.Checked = -not $this.Checked } catch {}; try { Show-ErrorT 'message.operation_failed' @{ err = $_.Exception.Message } } catch {} }
		})
	$script:CheckboxShortcutDesktop.Add_Click({
			if ($PortableMode) { return }
			try {
				Ensure-Shortcut 'Desktop' $this.Checked $AppName $InstallBin $AppNameShort
			}
			catch { try { $this.Checked = -not $this.Checked } catch {}; try { Show-ErrorT 'message.operation_failed' @{ err = $_.Exception.Message } } catch {} }
		})
	# In force at once, like the interval and the language above: the icons are there
	# either way, only their visibility follows the box -- see Update-TrayIconVisibility.
	$script:CheckboxTrayIcons.Add_Click({
			$State.TrayIcons = [bool]$this.Checked
			Save-Config
			try { Update-TrayIconVisibility } catch {}
		})
	$script:ButtonInstall.Add_Click({ Install-App })
	$script:ButtonUninstall.Add_Click({ Uninstall-App })
	$script:ButtonExportConfig.Add_Click({ Export-AppConfig })
	$script:ButtonImportConfig.Add_Click({ Import-AppConfig })
	$script:ButtonExportToPortable.Add_Click({ Export-AppToPortable })
	$script:ButtonClose1.Add_Click({ $f.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $f.Close() })

	[void]$footerPanel.Controls.Add($modePanel, 0, 0)
	[void]$footerPanel.Controls.Add($globalsPanel, 0, 1)
	[void]$footerPanel.Controls.Add($checkPanel, 0, 2)
	[void]$footerPanel.Controls.Add($btnRow1, 0, 3)
	[void]$footerPanel.Controls.Add($btnRow2, 0, 4)
	[void]$footerPanel.Controls.Add($closePanel, 0, 5)
	[void]$mainPanel.Controls.Add($lv, 0, 0)
	[void]$mainPanel.Controls.Add($sidePanel, 1, 0)
	[void]$mainPanel.Controls.Add($footerPanel, 0, 1)
	$mainPanel.SetColumnSpan($footerPanel, 2)
	[void]$HostTab.Controls.Add($mainPanel)

	# Now that the controls exist, fill the language list
	& $script:RefreshLangList
	# Not the share list: every row of it asks a server and reads a drive, and
	# until that is through there is nothing of this window on screen at all.
	# Show-SettingsDialog fills it once the window is up; this says so until then.
	[void]$lv.Items.Add((New-Object System.Windows.Forms.ListViewItem((T 'label.loading'))))
	Update-ListViewColumns $lv
}