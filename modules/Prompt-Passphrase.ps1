# Asks for the passphrase, optionally twice. Returns what was typed, or $null
# when the window was cancelled -- the caller decides what a cancel means, which
# is not the same answer at startup as it is when a password is being stored.
function Prompt-Passphrase {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Title, [switch]$Confirm )
	$f = New-Object System.Windows.Forms.Form; Apply-BrandIconToForm $f; Hook-FormDpi $f; Hook-FormScreen $f
	$f.Text = $Title; $f.StartPosition = 'CenterScreen'; $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false; $f.TopMost = $true
	$h = 160; if ($Confirm) { $h = 210 }
	$f.Width = 420; $f.Height = $h; $f.KeyPreview = $true
	$lbl = New-Object System.Windows.Forms.Label; $lbl.Text = (T 'label.passphrase_enter'); $lbl.AutoSize = $true; $lbl.Left = 12; $lbl.Top = 18
	$txt = New-Object System.Windows.Forms.TextBox; $txt.Left = 160; $txt.Top = 16; $txt.Width = 230; $txt.UseSystemPasswordChar = $true
	$lbl2 = $null; $txt2 = $null
	if ($Confirm) {
		$lbl2 = New-Object System.Windows.Forms.Label; $lbl2.Text = (T 'label.passphrase_confirm'); $lbl2.AutoSize = $true; $lbl2.Left = 12; $lbl2.Top = 56
		$txt2 = New-Object System.Windows.Forms.TextBox; $txt2.Left = 160; $txt2.Top = 54; $txt2.Width = 230; $txt2.UseSystemPasswordChar = $true
	}
	$ok = New-Object System.Windows.Forms.Button; $ok.Text = (T 'button.ok'); $ok.Width = 100; $ok.Left = $f.ClientSize.Width - 216; $ok.Top = $f.ClientSize.Height - 40; $ok.Height = $script:ButtonXH; $ok.Anchor = 'Bottom, Right'
	$ok.Add_Click({ if ($Confirm -and ($txt.Text -ne $txt2.Text)) { Show-WarnT 'message.passphrase_mismatch'; return }; $f.DialogResult = [System.Windows.Forms.DialogResult]::OK; $f.Close() })
	$ca = New-Object System.Windows.Forms.Button; $ca.Text = (T 'button.cancel'); $ca.Width = 100; $ca.Left = $f.ClientSize.Width - 108; $ca.Top = $f.ClientSize.Height - 40; $ca.Height = $script:ButtonXH; $ca.Anchor = 'Bottom, Right'
	$ca.Add_Click({ $f.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $f.Close() })
	# Tab order runs field -> field -> OK -> Cancel.
	$txt.TabIndex = 0
	if ($Confirm) { $txt2.TabIndex = 1; $ok.TabIndex = 2; $ca.TabIndex = 3 } else { $ok.TabIndex = 1; $ca.TabIndex = 2 }
	$f.AcceptButton = $ok; $f.CancelButton = $ca
	$f.Add_KeyDown({ param($s, $e); if ($e.KeyCode -eq 'Enter') { $ok.PerformClick() } elseif ($e.KeyCode -eq 'Escape') { $ca.PerformClick() } })
	$f.Controls.AddRange(@($lbl, $txt, $ok, $ca))
	if ($Confirm) { $f.Controls.AddRange(@($lbl2, $txt2)) }
	$null = $txt.Focus()
	$res = $f.ShowDialog()
	if ($res -eq [System.Windows.Forms.DialogResult]::OK) { return $txt.Text }
	return $null
}