# Asks for the password of one share. Returns Pass and Save, or $null when the
# dialog was cancelled -- an empty Pass is an answer, $null is the absence of one.
# The password is handed back to the caller; whether it is written anywhere is
# what Save says, and Ensure-MountPassword is where that happens.
function Show-SharePasswordPrompt {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Entry )
	$vars = @{ share = $Entry.Label; server = $Entry.Server; drive = $Entry.Drive }
	$bodyText = if ([string]::IsNullOrWhiteSpace($Entry.Label)) { T 'text.share_password_for' $vars } else { T 'text.share_password_for_named' $vars }

	$frm = New-Object System.Windows.Forms.Form
	Apply-BrandIconToForm $frm
	Hook-FormScreen $frm
	$frm.Text = (T 'title.share_password' @{ app = $AppName })
	$frm.MinimizeBox = $false; $frm.MaximizeBox = $false; $frm.ShowInTaskbar = $false; $frm.TopMost = $true; $frm.AutoSize = $true
	$frm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$frm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
	$frm.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink

	$mainPanel = New-Object System.Windows.Forms.TableLayoutPanel
	$mainPanel.ColumnCount = 1; $mainPanel.RowCount = 4; $mainPanel.AutoSize = $true
	$mainPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$mainPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
	$mainPanel.Padding = New-Object System.Windows.Forms.Padding(12, 12, 12, 12)
	$mainPanel.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::AddRows

	$lblBody = New-Object System.Windows.Forms.Label
	$lblBody.Text = $bodyText; $lblBody.AutoSize = $true
	$lblBody.MaximumSize = New-Object System.Drawing.Size(460, 0)

	# Label and field side by side, so the field grows with the dialog
	$inputPanel = New-Object System.Windows.Forms.TableLayoutPanel
	$inputPanel.ColumnCount = 2; $inputPanel.RowCount = 1; $inputPanel.AutoSize = $true
	$inputPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$inputPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
	$inputPanel.Padding = New-Object System.Windows.Forms.Padding(0, 12, 0, 0)
	$lblPass = New-Object System.Windows.Forms.Label
	$lblPass.Text = (T 'label.share_password'); $lblPass.AutoSize = $true
	$lblPass.Anchor = [System.Windows.Forms.AnchorStyles]::Left
	$lblPass.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
	$txtPass = New-Object System.Windows.Forms.TextBox
	$txtPass.UseSystemPasswordChar = $true; $txtPass.Width = 240
	$txtPass.Anchor = ([System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)
	[void]$inputPanel.Controls.Add($lblPass, 0, 0); [void]$inputPanel.Controls.Add($txtPass, 1, 0)

	$chkSave = New-Object System.Windows.Forms.CheckBox
	$chkSave.Text = (T 'box.save_password'); $chkSave.AutoSize = $true
	$chkSave.Anchor = [System.Windows.Forms.AnchorStyles]::Left
	$chkSave.Margin = New-Object System.Windows.Forms.Padding(0, 8, 0, 0)

	$buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
	$buttonPanel.AutoSize = $true; $buttonPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$buttonPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
	$buttonPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft
	$buttonPanel.Padding = New-Object System.Windows.Forms.Padding(0, 12, 0, 0)
	$btnCancel = New-Object System.Windows.Forms.Button
	$btnCancel.Text = (T 'button.cancel'); $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
	$btnOk = New-Object System.Windows.Forms.Button
	$btnOk.Text = (T 'button.ok'); $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
	foreach ($btn in @($btnCancel, $btnOk)) {
		$btn.AutoSize = $true; $btn.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowOnly
		$btn.Height = $script:ButtonXH
		$btn.MaximumSize = New-Object System.Drawing.Size(0, $btn.Height)
		$btn.MinimumSize = New-Object System.Drawing.Size($script:ButtonMinW, 0)
		$btn.Margin = New-Object System.Windows.Forms.Padding(6, 0, 0, 0)
		[void]$buttonPanel.Controls.Add($btn)
	}
	$frm.AcceptButton = $btnOk; $frm.CancelButton = $btnCancel

	[void]$mainPanel.Controls.Add($lblBody, 0, 0)
	[void]$mainPanel.Controls.Add($inputPanel, 0, 1)
	[void]$mainPanel.Controls.Add($chkSave, 0, 2)
	[void]$mainPanel.Controls.Add($buttonPanel, 0, 3)
	[void]$frm.Controls.Add($mainPanel)
	$frm.Add_Shown({ $frm.Activate(); $txtPass.Focus() })

	try {
		if ($frm.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
		return [pscustomobject]@{ Pass = [string]$txtPass.Text; Save = [bool]$chkSave.Checked }
	} finally { $frm.Dispose() }
}
