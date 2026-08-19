# Asks for a public link and turns it into a new mount entry, or returns $null if
# the dialog was cancelled. The link is the only thing the user has to supply:
# server and token are read out of it, and the drive letter is preselected from
# what is free. The entry is returned, not stored -- saving it is the caller's.
function Show-AddShareDialog {
	[CmdletBinding()] param( [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Reserved )

	$frm = New-Object System.Windows.Forms.Form
	Apply-BrandIconToForm $frm
	Hook-FormScreen $frm
	$frm.Text = (T 'title.add_share' @{ app = $AppName })
	$frm.MinimizeBox = $false; $frm.MaximizeBox = $false; $frm.ShowInTaskbar = $false; $frm.TopMost = $true; $frm.AutoSize = $true
	$frm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$frm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
	$frm.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink

	$mainPanel = New-Object System.Windows.Forms.TableLayoutPanel
	$mainPanel.ColumnCount = 2; $mainPanel.RowCount = 7; $mainPanel.AutoSize = $true
	$mainPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$mainPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
	$mainPanel.Padding = New-Object System.Windows.Forms.Padding(12, 12, 12, 12)
	$mainPanel.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::AddRows

	$lblLink = New-Object System.Windows.Forms.Label
	$lblLink.Text = (T 'label.share_link'); $lblLink.AutoSize = $true
	$lblLink.Anchor = [System.Windows.Forms.AnchorStyles]::Left
	$lblLink.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
	$txtLink = New-Object System.Windows.Forms.TextBox

	# The link is checked when the user asks for it, not when the field loses focus:
	# one request, and an answer that is worth reading.
	$btnCheck = New-Object System.Windows.Forms.Button
	$btnCheck.Text = (T 'button.check'); $btnCheck.AutoSize = $true
	$btnCheck.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$btnCheck.MaximumSize = New-Object System.Drawing.Size(0, $txtLink.PreferredHeight)
	$btnCheck.Margin = New-Object System.Windows.Forms.Padding(4, 0, 0, 0)

	# Drawn, not written: the check mark is in none of the fonts this dialog uses,
	# and picking one for a single character is a guess about what is installed.
	$lblTick = New-Object System.Windows.Forms.Label
	$lblTick.AutoSize = $false
	$lblTick.Size = New-Object System.Drawing.Size(20, $txtLink.PreferredHeight)
	$lblTick.Margin = New-Object System.Windows.Forms.Padding(2, 0, 0, 0)
	$lblTick.Visible = $false
	$lblTick.Add_Paint({
			param($sender, $e)
			$e.Graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
			$pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::ForestGreen), ([single]2.4)
			try {
				$w = [single]$sender.ClientSize.Width; $h = [single]$sender.ClientSize.Height
				$e.Graphics.DrawLines($pen, @(
						(New-Object System.Drawing.PointF(($w * 0.16), ($h * 0.52))),
						(New-Object System.Drawing.PointF(($w * 0.40), ($h * 0.76))),
						(New-Object System.Drawing.PointF(($w * 0.84), ($h * 0.24)))))
			} finally { $pen.Dispose() }
		})

	# What the button and the tick take is taken off the box, so the row is as wide
	# as the field was on its own.
	$txtLink.Width = 340 - $btnCheck.PreferredSize.Width - $lblTick.Width - 6
	$txtLink.Margin = New-Object System.Windows.Forms.Padding(0)
	$linkRow = New-Object System.Windows.Forms.FlowLayoutPanel
	$linkRow.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
	$linkRow.WrapContents = $false; $linkRow.AutoSize = $true
	$linkRow.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$linkRow.Margin = New-Object System.Windows.Forms.Padding(0)
	[void]$linkRow.Controls.Add($txtLink)
	[void]$linkRow.Controls.Add($btnCheck)
	[void]$linkRow.Controls.Add($lblTick)

	$lblHint = New-Object System.Windows.Forms.Label
	$lblHint.Text = (T 'hint.share_link' @{ check = (T 'button.check') }); $lblHint.AutoSize = $true
	$lblHint.ForeColor = [System.Drawing.SystemColors]::GrayText
	$lblHint.MaximumSize = New-Object System.Drawing.Size(340, 0)
	$lblHint.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 8)

	# Hidden until the server says the share wants a password. There is nothing to
	# explain about it: a public share either has one or it has not, and the one it
	# has was handed out with the link.
	$lblPassCap = New-Object System.Windows.Forms.Label
	$lblPassCap.Text = (T 'label.share_password'); $lblPassCap.AutoSize = $true
	$lblPassCap.Anchor = [System.Windows.Forms.AnchorStyles]::Left
	$lblPassCap.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
	$lblPassCap.Visible = $false
	$txtPass = New-Object System.Windows.Forms.TextBox
	$txtPass.Width = $txtLink.Width; $txtPass.UseSystemPasswordChar = $true
	$txtPass.Margin = New-Object System.Windows.Forms.Padding(0)
	$txtPass.Visible = $false
	# The row the check button moves into, built like the one it comes from.
	$passRow = New-Object System.Windows.Forms.FlowLayoutPanel
	$passRow.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
	$passRow.WrapContents = $false; $passRow.AutoSize = $true
	$passRow.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$passRow.Margin = New-Object System.Windows.Forms.Padding(0)
	$passRow.Visible = $false
	[void]$passRow.Controls.Add($txtPass)
	$chkSave = New-Object System.Windows.Forms.CheckBox
	$chkSave.Text = (T 'box.save_password'); $chkSave.AutoSize = $true
	$chkSave.Anchor = [System.Windows.Forms.AnchorStyles]::Left
	$chkSave.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 8)
	$chkSave.Visible = $false

	$lblDrive = New-Object System.Windows.Forms.Label
	$lblDrive.Text = (T 'label.drive'); $lblDrive.AutoSize = $true
	$lblDrive.Anchor = [System.Windows.Forms.AnchorStyles]::Left
	$lblDrive.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
	$cmbDrive = New-Object System.Windows.Forms.ComboBox
	$cmbDrive.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
	$cmbDrive.Width = 70
	$cmbDrive.Anchor = [System.Windows.Forms.AnchorStyles]::Left
	# Every letter, coloured by what it is: the ones already taken stay visible in
	# red, and the picker will not settle on one of them.
	Initialize-DriveLetterPicker -ComboBox $cmbDrive
	Update-DriveLetterPicker -ComboBox $cmbDrive -Reserved $Reserved -Prefer 'Highest'

	$lblName = New-Object System.Windows.Forms.Label
	$lblName.Text = (T 'label.display_name'); $lblName.AutoSize = $true
	$lblName.Anchor = [System.Windows.Forms.AnchorStyles]::Left
	$lblName.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
	$txtName = New-Object System.Windows.Forms.TextBox
	$txtName.Anchor = ([System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)

	$buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
	$buttonPanel.AutoSize = $true; $buttonPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$buttonPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
	$buttonPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft
	$buttonPanel.Padding = New-Object System.Windows.Forms.Padding(0, 12, 0, 0)
	$btnCancel = New-Object System.Windows.Forms.Button
	$btnCancel.Text = (T 'button.cancel'); $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
	$btnOk = New-Object System.Windows.Forms.Button
	# No DialogResult on OK: an unusable link has to keep the dialog open
	$btnOk.Text = (T 'button.ok')
	foreach ($btn in @($btnCancel, $btnOk)) {
		$btn.AutoSize = $true; $btn.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowOnly
		$btn.Height = $script:ButtonXH
		$btn.MaximumSize = New-Object System.Drawing.Size(0, $btn.Height)
		$btn.MinimumSize = New-Object System.Drawing.Size($script:ButtonMinW, 0)
		$btn.Margin = New-Object System.Windows.Forms.Padding(6, 0, 0, 0)
		[void]$buttonPanel.Controls.Add($btn)
	}
	$frm.AcceptButton = $btnOk; $frm.CancelButton = $btnCancel

	# The check button sits with the field that is waiting to be checked, and once a
	# password is what the server wants, that is the password field.
	$showPass = {
		param([bool]$On)
		$row = if ($On) { $passRow } else { $linkRow }
		if ($btnCheck.Parent -ne $row) { [void]$row.Controls.Add($btnCheck); [void]$row.Controls.Add($lblTick) }
		$lblPassCap.Visible = $On; $txtPass.Visible = $On; $chkSave.Visible = $On; $passRow.Visible = $On
	}

	# The one request the dialog is built around: whether this link, together with
	# whatever stands in the password box, gets a mount. Whatever it finds it says --
	# a button called check that answers nothing is worse than no button. The parsed
	# link travels in the form's Tag, which is also what says the check went through:
	# an assignment to a variable would create one in this block's own scope.
	$check = {
		$frm.Tag = $null; $lblTick.Visible = $false
		$p = ConvertFrom-ShareLink $txtLink.Text
		if (-not $p) { Show-WarnT 'message.share_link_invalid'; [void]$txtLink.Focus(); return }
		$state = 'unreachable'; $shareName = ''
		$frm.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
		try { $state = Test-ShareAccess -Server $p.Server -Token $p.Token -Password $txtPass.Text -Name ([ref]$shareName) }
		catch {}
		finally { $frm.Cursor = [System.Windows.Forms.Cursors]::Default }
		# The name the server has for the share saves the user from repeating what the
		# link already knows, and it is only ever a suggestion -- what stands in the
		# field when the dialog closes is what counts.
		if ([string]::IsNullOrWhiteSpace($txtName.Text) -and -not [string]::IsNullOrWhiteSpace($shareName)) { $txtName.Text = $shareName }
		# 403 is the same answer for a password that is missing and one that is wrong,
		# so which of the two it was is read off the field, not off the server.
		if ($state -eq 'password') {
			& $showPass $true
			if ([string]::IsNullOrWhiteSpace($txtPass.Text)) { Show-WarnT 'message.share_password_required' @{ check = (T 'button.check') } }
			else { Show-WarnT 'message.share_link_or_password_wrong' }
			[void]$txtPass.Focus(); return
		}
		# shareinfo says 404 both to a token that does not exist and, whatever the
		# token, to a server that hands out no public shares over WebDAV. Only then is
		# the share page worth a second request: it answers for a good token even where
		# shareinfo has stopped doing so.
		if ($state -eq 'notfound') {
			$page = 'unreachable'
			$frm.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
			try { $page = Test-SharePage -Server $p.Server -Token $p.Token }
			catch {}
			finally { $frm.Cursor = [System.Windows.Forms.Cursors]::Default }
			if ($page -eq 'ok') { Show-PublicWebDavUnavailable -Server $p.Server; return }
			Show-WarnT 'message.share_link_unknown'; [void]$txtLink.Focus(); return
		}
		# A server that does not answer at all says nothing about the link, so it does
		# not hold the dialog. The tick stays off all the same: nothing was confirmed.
		if ($state -ne 'ok') { Show-WarnT 'message.share_server_unreachable' @{ server = $p.Server }; $frm.Tag = $p; return }
		if ([string]::IsNullOrEmpty($txtPass.Text)) { & $showPass $false }
		$lblTick.Visible = $true; $frm.Tag = $p
	}
	$btnCheck.Add_Click($check)
	# Anything typed after a check makes its answer stale, tick and all.
	$txtLink.Add_TextChanged({ $frm.Tag = $null; $lblTick.Visible = $false })
	$txtPass.Add_TextChanged({ $frm.Tag = $null; $lblTick.Visible = $false })

	$btnOk.Add_Click({
			if ([string]::IsNullOrWhiteSpace($cmbDrive.Text)) { Show-WarnT 'message.no_free_drive_letter'; return }
			# Nothing is added that has not been through the check; OK on an unchecked
			# link just runs it first.
			if (-not $frm.Tag) { & $check }
			if (-not $frm.Tag) { return }
			$frm.DialogResult = [System.Windows.Forms.DialogResult]::OK
			$frm.Close()
		})

	[void]$mainPanel.Controls.Add($lblLink, 0, 0); [void]$mainPanel.Controls.Add($linkRow, 1, 0)
	[void]$mainPanel.Controls.Add($lblHint, 1, 1)
	[void]$mainPanel.Controls.Add($lblPassCap, 0, 2); [void]$mainPanel.Controls.Add($passRow, 1, 2)
	[void]$mainPanel.Controls.Add($chkSave, 1, 3)
	[void]$mainPanel.Controls.Add($lblDrive, 0, 4); [void]$mainPanel.Controls.Add($cmbDrive, 1, 4)
	[void]$mainPanel.Controls.Add($lblName, 0, 5); [void]$mainPanel.Controls.Add($txtName, 1, 5)
	[void]$mainPanel.Controls.Add($buttonPanel, 1, 6)
	[void]$frm.Controls.Add($mainPanel)
	$frm.Add_Shown({ $frm.Activate(); $txtLink.Focus() })

	try {
		if ($frm.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
		$parsed = $frm.Tag
		if (-not $parsed) { return $null }
		# Without a name Explorer labels the drive with the share token and the whole
		# UNC path. The server's name for it has been filled in by the time the dialog
		# closes; where the server named nothing, the token has to do: it is at least
		# what tells two shares on one server apart.
		$label = $txtName.Text.Trim()
		if ([string]::IsNullOrWhiteSpace($label)) { $label = $parsed.Token }
		# A protected share only mounts over the legacy endpoint for now.
		# Ensure-MountPassword settles that on the first connect, but only for an entry
		# that arrives without a password in hand -- and the one below arrives with it.
		$kind = if ([string]::IsNullOrEmpty($txtPass.Text)) { 'share' } else { 'share-legacy' }
		$entry = New-MountEntry -Server $parsed.Server -Token $parsed.Token -Drive $cmbDrive.Text -Label $label -Kind $kind
		# The password was accepted a moment ago, so the first connect has no reason to
		# ask for it again. Whether it outlives the session is what the box says.
		if (-not [string]::IsNullOrEmpty($txtPass.Text)) {
			(Get-MountRuntime $entry.Id).Pass = [string]$txtPass.Text
			if ($chkSave.Checked) { Set-AccountPassword -Server $entry.Server -User (Get-MountSecretName $entry) -Plain $txtPass.Text }
		}
		return $entry
	} finally { $frm.Dispose() }
}
