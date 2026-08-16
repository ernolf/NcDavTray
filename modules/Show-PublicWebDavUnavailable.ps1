# Says that the server, not the link, is what stands in the way, and points at the
# long version of it: which setting has to change, and who can change it. That
# explanation lives in the wiki, where it is written once instead of in every
# language pack, and where it can be corrected without a release.
function Show-PublicWebDavUnavailable {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Server )

	$vars = @{ server = $Server }
	$url = '{0}/wiki/Share-links' -f $ProjectUrl
	[System.Media.SystemSounds]::Exclamation.Play()

	$frm = New-Object System.Windows.Forms.Form
	Apply-BrandIconToForm $frm
	Hook-FormScreen $frm
	$frm.Text = $AppName
	$frm.MinimizeBox = $false; $frm.MaximizeBox = $false; $frm.ShowInTaskbar = $false; $frm.TopMost = $true; $frm.AutoSize = $true
	$frm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$frm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
	$frm.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink

	$mainPanel = New-Object System.Windows.Forms.TableLayoutPanel
	$mainPanel.ColumnCount = 1; $mainPanel.RowCount = 3; $mainPanel.AutoSize = $true
	$mainPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$mainPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
	$mainPanel.Padding = New-Object System.Windows.Forms.Padding(12, 12, 12, 12)
	$mainPanel.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::AddRows

	# Icon and text side by side, in the proportions of a message box
	$contentPanel = New-Object System.Windows.Forms.TableLayoutPanel
	$contentPanel.ColumnCount = 2; $contentPanel.RowCount = 1; $contentPanel.AutoSize = $true
	$contentPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$contentPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
	$pic = New-Object System.Windows.Forms.PictureBox
	$pic.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::CenterImage
	$pic.Margin = New-Object System.Windows.Forms.Padding(0, 0, 12, 0)
	$pic.MinimumSize = New-Object System.Drawing.Size(32, 32)
	$pic.Image = [System.Drawing.SystemIcons]::Warning.ToBitmap()
	$lbl = New-Object System.Windows.Forms.Label
	$lbl.Text = (T 'message.public_webdav_unavailable' $vars); $lbl.AutoSize = $true
	$lbl.MaximumSize = New-Object System.Drawing.Size(360, 0)
	[void]$contentPanel.Controls.Add($pic, 0, 0); [void]$contentPanel.Controls.Add($lbl, 1, 0)

	# Indented past the icon, so it reads as a continuation of the text
	$lnkMore = New-Object System.Windows.Forms.LinkLabel
	$lnkMore.Text = (T 'link.more_info'); $lnkMore.AutoSize = $true
	$lnkMore.Margin = New-Object System.Windows.Forms.Padding(44, 8, 0, 0)
	$lnkMore.Add_LinkClicked({ param($s, $e); try { $psi = New-Object System.Diagnostics.ProcessStartInfo; $psi.FileName = $url; $psi.UseShellExecute = $true; [System.Diagnostics.Process]::Start($psi) | Out-Null } catch {} })

	$buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
	$buttonPanel.AutoSize = $true; $buttonPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$buttonPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
	$buttonPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft
	$buttonPanel.Padding = New-Object System.Windows.Forms.Padding(0, 12, 0, 0)
	$btnOk = New-Object System.Windows.Forms.Button
	$btnOk.Text = (T 'button.ok'); $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
	$btnOk.AutoSize = $true; $btnOk.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowOnly
	$btnOk.Height = $script:ButtonXH
	$btnOk.MaximumSize = New-Object System.Drawing.Size(0, $btnOk.Height)
	$btnOk.MinimumSize = New-Object System.Drawing.Size($script:ButtonMinW, 0)
	$btnOk.Margin = New-Object System.Windows.Forms.Padding(6, 0, 0, 0)
	[void]$buttonPanel.Controls.Add($btnOk)
	$frm.AcceptButton = $btnOk; $frm.CancelButton = $btnOk

	[void]$mainPanel.Controls.Add($contentPanel, 0, 0)
	[void]$mainPanel.Controls.Add($lnkMore, 0, 1)
	[void]$mainPanel.Controls.Add($buttonPanel, 0, 2)
	[void]$frm.Controls.Add($mainPanel)

	try { [void]$frm.ShowDialog() } finally { $frm.Dispose() }
}