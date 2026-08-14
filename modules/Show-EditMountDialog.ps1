# Edits the parts of a mount that do not say what it is, and returns the changed
# entry or $null when the dialog was cancelled. What identifies the mount is shown
# and not offered for editing: the server together with the token of a share or
# the user of an account. A different one of those is a different mount, and the
# way to it is to add one.
# The returned object is a copy, so a cancelled dialog leaves the configuration
# untouched even after the user typed in it. The password is the exception and is
# written the moment it is given: it does not belong to this mount but to the
# server/user pair behind it, and is therefore none of the returned entry's
# business.
function Show-EditMountDialog {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][psobject]$Entry,
		[Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Reserved
	)

	# One window per entry. A modal dialog does not stop the tray menus, so without
	# this a second right click would open the same mount again, and whichever
	# window was saved last would silently undo the other.
	if ($script:MountDialogs.ContainsKey($Entry.Id)) {
		$open = $script:MountDialogs[$Entry.Id]
		try {
			if ($open -and -not $open.IsDisposed) {
				$open.WindowState = [System.Windows.Forms.FormWindowState]::Normal
				$open.Activate(); $open.BringToFront()
			}
		} catch {}
		return $null
	}

	$isAccount = ($Entry.Kind -eq 'account')

	$frm = New-Object System.Windows.Forms.Form
	Apply-BrandIconToForm $frm
	Hook-FormScreen $frm
	$frm.Text = if ($isAccount) { (T 'title.edit_account' @{ app = $AppName }) } else { (T 'title.edit_share' @{ app = $AppName }) }
	$frm.MinimizeBox = $false; $frm.MaximizeBox = $false; $frm.ShowInTaskbar = $false; $frm.TopMost = $true; $frm.AutoSize = $true
	$frm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$frm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
	$frm.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink

	$mainPanel = New-Object System.Windows.Forms.TableLayoutPanel
	$mainPanel.ColumnCount = 2; $mainPanel.RowCount = 5; $mainPanel.AutoSize = $true
	$mainPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$mainPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
	$mainPanel.Padding = New-Object System.Windows.Forms.Padding(12, 12, 12, 12)
	$mainPanel.GrowStyle = [System.Windows.Forms.TableLayoutPanelGrowStyle]::AddRows

	$lblServerCap = New-Object System.Windows.Forms.Label
	$lblServerCap.Text = (T 'label.server'); $lblServerCap.AutoSize = $true
	$lblServerCap.Anchor = [System.Windows.Forms.AnchorStyles]::Left
	$lblServerCap.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 6)
	$lblServer = New-Object System.Windows.Forms.Label
	$lblServer.Text = [string]$Entry.Server; $lblServer.AutoSize = $true
	$lblServer.Anchor = [System.Windows.Forms.AnchorStyles]::Left
	$lblServer.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)

	# Only an account has a login worth showing: a share is reached by its token,
	# and a token is an address, not a name anybody would recognize on sight.
	$lblUserCap = New-Object System.Windows.Forms.Label
	$lblUserCap.Text = (T 'label.user'); $lblUserCap.AutoSize = $true
	$lblUserCap.Anchor = [System.Windows.Forms.AnchorStyles]::Left
	$lblUserCap.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 6)
	$lblUser = New-Object System.Windows.Forms.Label
	$lblUser.Text = [string]$Entry.User; $lblUser.AutoSize = $true
	$lblUser.Anchor = [System.Windows.Forms.AnchorStyles]::Left
	$lblUser.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)

	# An account always signs in with one. A share only has a password where the
	# server asks for one, and where the server cannot be asked, one already stored
	# is answer enough.
	$wantPass = $isAccount
	if (-not $isAccount) {
		$wantPass = -not [string]::IsNullOrEmpty((Get-AccountSecret -Server $Entry.Server -User (Get-MountSecretName $Entry)))
		if (-not $wantPass) {
			try { $wantPass = ((Test-ShareAccess -Server $Entry.Server -Token $Entry.Token) -eq 'password') } catch {}
		}
	}

	# The password, on the same terms as NcDavTray's own settings page: either it is
	# stored, and then the field says so and the button clears it, or it is not, and
	# then it can be typed and encrypted.
	if ($wantPass) {
		$lblPassCap = New-Object System.Windows.Forms.Label
		$lblPassCap.Text = if ($isAccount) { T 'app_password' } else { T 'label.share_password' }
		$lblPassCap.AutoSize = $true
		$lblPassCap.Anchor = [System.Windows.Forms.AnchorStyles]::Left
		$lblPassCap.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 6)
		$passPanel = New-Object System.Windows.Forms.FlowLayoutPanel
		$passPanel.AutoSize = $true; $passPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
		$passPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
		$passPanel.WrapContents = $false
		$passPanel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)
		$txtPass = New-Object System.Windows.Forms.TextBox
		# The field alone is as wide as the ones below it, and the button comes on top of
		# that: the note that stands in for a stored password is a sentence, not dots,
		# and a field it does not fit into says only half of it.
		$txtPass.Width = 260; $txtPass.UseSystemPasswordChar = $true
		$txtPass.Margin = New-Object System.Windows.Forms.Padding(0, 0, 6, 0)
		$btnPass = New-Object System.Windows.Forms.Button
		$btnPass.Width = $script:ButtonMinW; $btnPass.Height = $script:ButtonH
		$btnPass.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)
		[void]$passPanel.Controls.Add($txtPass); [void]$passPanel.Controls.Add($btnPass)
		# The stored blob is asked for again after every change instead of remembered,
		# so a window left standing while another one of the same pair was used still
		# shows what is actually there.
		$passState = @{ Enc = '' }
		$refreshPass = {
			$passState.Enc = Get-AccountSecret -Server $Entry.Server -User (Get-MountSecretName $Entry)
			if ([string]::IsNullOrEmpty($passState.Enc)) {
				if ($txtPass.Tag -eq 'info') { $txtPass.Text = '' }
				$txtPass.Tag = $null; $txtPass.ReadOnly = $false; $txtPass.UseSystemPasswordChar = $true
				$txtPass.ForeColor = [System.Drawing.SystemColors]::WindowText
				$btnPass.Text = (T 'button.encrypt')
			} else {
				$txtPass.Tag = 'info'; $txtPass.ReadOnly = $true; $txtPass.UseSystemPasswordChar = $false
				$txtPass.ForeColor = [System.Drawing.SystemColors]::GrayText
				$txtPass.Text = (T 'password.encrypted_dpapi')
				$btnPass.Text = (T 'button.clear')
			}
		}
		& $refreshPass
		$btnPass.Add_Click({
			if (-not [string]::IsNullOrEmpty($passState.Enc)) {
				if ((Ask-YesNoQuestT 'prompt.clear_stored_password') -ne [System.Windows.Forms.DialogResult]::Yes) { return }
				Set-AccountPassword -Server $Entry.Server -User (Get-MountSecretName $Entry) -Plain ''
			} elseif ([string]::IsNullOrWhiteSpace($txtPass.Text)) {
				Show-InfoT $(if ($isAccount) { 'message.enter_password_first' } else { 'message.enter_share_password_first' }); return
			} else {
				try { Set-AccountPassword -Server $Entry.Server -User (Get-MountSecretName $Entry) -Plain $txtPass.Text }
				catch { Show-ErrorT 'message.store_password_failed' @{ err = $_.Exception.Message }; return }
			}
			& $refreshPass
		})
	}

	$lblName = New-Object System.Windows.Forms.Label
	$lblName.Text = (T 'label.display_name'); $lblName.AutoSize = $true
	$lblName.Anchor = [System.Windows.Forms.AnchorStyles]::Left
	$lblName.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
	$txtName = New-Object System.Windows.Forms.TextBox
	$txtName.Width = 260; $txtName.Text = [string]$Entry.Label
	$txtName.Anchor = ([System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)

	$lblDrive = New-Object System.Windows.Forms.Label
	$lblDrive.Text = (T 'label.drive'); $lblDrive.AutoSize = $true
	$lblDrive.Anchor = [System.Windows.Forms.AnchorStyles]::Left
	$lblDrive.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
	$cmbDrive = New-Object System.Windows.Forms.ComboBox
	$cmbDrive.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
	$cmbDrive.Width = 70
	$cmbDrive.Anchor = [System.Windows.Forms.AnchorStyles]::Left
	# Every letter, coloured by what it is. The one the entry already holds counts
	# as its own -- leaving the drive as it is must always be possible.
	Initialize-DriveLetterPicker -ComboBox $cmbDrive
	Update-DriveLetterPicker -ComboBox $cmbDrive -Current ([string]$Entry.Drive) -Reserved $Reserved -Prefer 'Highest'

	$lblSub = New-Object System.Windows.Forms.Label
	$lblSub.Text = (T 'label.subfolder'); $lblSub.AutoSize = $true
	$lblSub.Anchor = [System.Windows.Forms.AnchorStyles]::Left
	$lblSub.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
	$txtSub = New-Object System.Windows.Forms.TextBox
	$txtSub.Width = 260; $txtSub.Text = [string]$Entry.SubPath
	$txtSub.Anchor = ([System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)

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

	$row = 0
	[void]$mainPanel.Controls.Add($lblServerCap, 0, $row); [void]$mainPanel.Controls.Add($lblServer, 1, $row); $row++
	if ($isAccount) { [void]$mainPanel.Controls.Add($lblUserCap, 0, $row); [void]$mainPanel.Controls.Add($lblUser, 1, $row); $row++ }
	if ($wantPass) { [void]$mainPanel.Controls.Add($lblPassCap, 0, $row); [void]$mainPanel.Controls.Add($passPanel, 1, $row); $row++ }
	[void]$mainPanel.Controls.Add($lblName, 0, $row); [void]$mainPanel.Controls.Add($txtName, 1, $row); $row++
	[void]$mainPanel.Controls.Add($lblDrive, 0, $row); [void]$mainPanel.Controls.Add($cmbDrive, 1, $row); $row++
	[void]$mainPanel.Controls.Add($lblSub, 0, $row); [void]$mainPanel.Controls.Add($txtSub, 1, $row); $row++
	[void]$mainPanel.Controls.Add($buttonPanel, 1, $row)
	[void]$frm.Controls.Add($mainPanel)
	$frm.Add_Shown({ $frm.Activate(); $txtName.Focus() })

	$script:MountDialogs[$Entry.Id] = $frm
	try {
		if ($frm.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
		# A password typed and left standing is meant as much as one that was encrypted
		# with the button, so saving the mount saves it too.
		if ($wantPass -and $txtPass.Text -and ($txtPass.Tag -ne 'info')) {
			try { Set-AccountPassword -Server $Entry.Server -User (Get-MountSecretName $Entry) -Plain $txtPass.Text }
			catch { Show-ErrorT 'message.store_password_failed' @{ err = $_.Exception.Message } }
		}
		# An emptied name means the mount's own name is wanted back: for an account
		# that is who it signs in as, for a share the name the server gives out, and
		# where the server gives none the token stands in -- the same rule the add
		# dialog follows.
		$label = $txtName.Text.Trim()
		if ([string]::IsNullOrWhiteSpace($label) -and $isAccount) { $label = ('{0}@{1}' -f $Entry.User, $Entry.Server) }
		if ([string]::IsNullOrWhiteSpace($label)) {
			$shareName = ''
			try { [void](Test-ShareAccess -Server $Entry.Server -Token $Entry.Token -Password (Unprotect-MountSecret -Entry $Entry) -Name ([ref]$shareName)) } catch {}
			$label = $shareName
		}
		if ([string]::IsNullOrWhiteSpace($label)) { $label = $Entry.Token }
		return (New-MountEntry -Id $Entry.Id -Server $Entry.Server -Kind $Entry.Kind -User $Entry.User -Token $Entry.Token `
				-SubPath (Normalize-SubPath $txtSub.Text) -Drive $cmbDrive.Text -Label $label `
				-ExplicitPort:([bool]$Entry.ExplicitPort) -Enabled:([bool]$Entry.Enabled))
	} finally {
		[void]$script:MountDialogs.Remove($Entry.Id)
		$frm.Dispose()
	}
}