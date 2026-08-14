# i18n: custom MessageBox helper (localized text)
function Show-CustomMsgBoxT([string]$Key, [hashtable]$Vars = $null, [string]$Mode = 'OK', [string]$Icon = 'None', [string]$Caption = $AppName, [switch]$Uac) {
	<#	[string]$Key -> i18n key for body text, [hashtable]$Vars -> placeholder vars for T(), [string]$Mode -> 'OK' | 'YesNo' | 'YesNoCancel', [string]$Icon -> 'Information' | 'Warning' | 'Error' | 'Question' | 'None' #>
	# play system sound (mirror MessageBox)
	switch ($Icon) { 'Information' { [System.Media.SystemSounds]::Asterisk.Play() }; 'Warning' { [System.Media.SystemSounds]::Exclamation.Play() }; 'Error' { [System.Media.SystemSounds]::Hand.Play() }; 'Question' { [System.Media.SystemSounds]::Question.Play() }; default {} }
	# Resolve translated body text
	$bodyText = T $Key $Vars
	# Define buttons (order in array is right-to-left visual order, see FlowDirection below)
	switch ($Mode) {
		'OK' { $btnDefs = @( @{ Text = T 'button.ok'; Result = [System.Windows.Forms.DialogResult]::OK; Default = $true; Cancel = $true } ) }
		# FlowDirection = RightToLeft, so first in list ends up rightmost. We add No first, then Yes -> visually "Yes No"
		'YesNo' { $btnDefs = @( @{ Text = T 'button.no'; Result = [System.Windows.Forms.DialogResult]::No; Default = $false; Cancel = $true }, @{ Text = T 'button.yes'; Result = [System.Windows.Forms.DialogResult]::Yes; Default = $true; Cancel = $false } ) }
		# Will render "Yes No Cancel"
		'YesNoCancel' { $btnDefs = @( @{ Text = T 'button.cancel'; Result = [System.Windows.Forms.DialogResult]::Cancel; Default = $false; Cancel = $true }, @{ Text = T 'button.no'; Result = [System.Windows.Forms.DialogResult]::No; Default = $false; Cancel = $false }, @{ Text = T 'button.yes'; Result = [System.Windows.Forms.DialogResult]::Yes; Default = $true; Cancel = $false } ) }
		default { $btnDefs = @( @{ Text = T 'button.ok'; Result = [System.Windows.Forms.DialogResult]::OK; Default = $true; Cancel = $true } ) }
	}
	# Pick icon
	$icoObj = $null
	switch ($Icon) { 'Information' { $icoObj = [System.Drawing.SystemIcons]::Information }; 'Warning' { $icoObj = [System.Drawing.SystemIcons]::Warning }; 'Error' { $icoObj = [System.Drawing.SystemIcons]::Error }; 'Question' { $icoObj = [System.Drawing.SystemIcons]::Question }; default { $icoObj = $null } }
	# ---- Form base ----
	$frm = New-Object System.Windows.Forms.Form
	Apply-BrandIconToForm $frm
	Hook-FormScreen $frm
	$frm.Text = $Caption; $frm.MinimizeBox = $false; $frm.MaximizeBox = $false; $frm.ShowInTaskbar = $false; $frm.TopMost = $true; $frm.AutoSize = $true
	$frm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog; $frm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen; $frm.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	# Main panel (2 rows: content + buttons)
	$mainPanel = New-Object System.Windows.Forms.TableLayoutPanel; $mainPanel.ColumnCount = 1; $mainPanel.RowCount = 2; $mainPanel.AutoSize = $true; $mainPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink; $mainPanel.Dock = [System.Windows.Forms.DockStyle]::Fill; $mainPanel.Padding = New-Object System.Windows.Forms.Padding(12, 12, 12, 12); $mainPanel.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::AddRows
	# Upper row: icon + text side by side
	$contentPanel = New-Object System.Windows.Forms.TableLayoutPanel; $contentPanel.ColumnCount = 2; $contentPanel.RowCount = 1; $contentPanel.AutoSize = $true; $contentPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink; $contentPanel.Dock = [System.Windows.Forms.DockStyle]::Fill; $contentPanel.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::AddColumns
	$pic = New-Object System.Windows.Forms.PictureBox; $pic.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::CenterImage; $pic.Margin = New-Object System.Windows.Forms.Padding(0, 0, 12, 0); $pic.MinimumSize = New-Object System.Drawing.Size(32, 32)
	if ($icoObj) { $pic.Image = $icoObj.ToBitmap() } else { $pic.Width = 1; $pic.Height = 1; $pic.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0) } # no icon -> collapse spacing
	$lbl = New-Object System.Windows.Forms.Label; $lbl.Text = $bodyText; $lbl.AutoSize = $true; $lbl.MaximumSize = New-Object System.Drawing.Size(360, 0) # wrap text at ~360px
	[void]$contentPanel.Controls.Add($pic, 0, 0); [void]$contentPanel.Controls.Add($lbl, 1, 0)
	# Lower row: buttons, right aligned
	$buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel; $buttonPanel.AutoSize = $true; $buttonPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink; $buttonPanel.Dock = [System.Windows.Forms.DockStyle]::Fill; $buttonPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft; $buttonPanel.Padding = New-Object System.Windows.Forms.Padding(0, 12, 0, 0)
	$defaultBtn = $null; $cancelBtn = $null
	$btnMinW = if ($script:ButtonMinW -is [int] -and $script:ButtonMinW -gt 0) { $script:ButtonMinW } else { 80 }
	foreach ($bdef in $btnDefs) {
		$btn = New-Object System.Windows.Forms.Button
		$btn.AutoSize = $true; $btn.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowOnly
		$shieldThis = $Uac -and $bdef.Default -and ( ($bdef.Result -eq [System.Windows.Forms.DialogResult]::OK) -or ($bdef.Result -eq [System.Windows.Forms.DialogResult]::Yes) )
		$btn.Height = $script:ButtonXH
		$btn.MaximumSize = New-Object System.Drawing.Size(0, $btn.Height)
		$btn.Margin = New-Object System.Windows.Forms.Padding(6, 0, 0, 0)
		$btn.Text = $bdef.Text; $btn.DialogResult = $bdef.Result; $btn.MinimumSize = New-Object System.Drawing.Size($script:ButtonMinW, 0)
		if ($bdef.Default) { $defaultBtn = $btn }; if ($bdef.Cancel) { $cancelBtn = $btn }; if ($shieldThis) { Enable-FlatUacShield $btn }
		[void]$buttonPanel.Controls.Add($btn)
	}
	if ($defaultBtn) { $frm.AcceptButton = $defaultBtn }; if ($cancelBtn) { $frm.CancelButton = $cancelBtn }
	# Compose final layout
	[void]$mainPanel.Controls.Add($contentPanel, 0, 0); [void]$mainPanel.Controls.Add($buttonPanel, 0, 1); [void]$frm.Controls.Add($mainPanel)
	# Modal show and return DialogResult
	$dlgResult = $frm.ShowDialog()
	if (-not $dlgResult -or $dlgResult -eq [System.Windows.Forms.DialogResult]::None) { if ($cancelBtn) { $dlgResult = $cancelBtn.DialogResult } else { $dlgResult = [System.Windows.Forms.DialogResult]::None } }
	return $dlgResult
}
