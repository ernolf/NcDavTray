# Modal Nextcloud folder picker. Returns: normalized subpath like "A/B/C", or '' for root, or $null on Cancel.
function Show-NcFolderPicker {
	[CmdletBinding()] param( [Parameter(Mandatory)][AllowEmptyString()][string]$Server, [Parameter(Mandatory)][AllowEmptyString()][string]$User, [Parameter(Mandatory)][AllowEmptyString()][string]$Pass, [AllowEmptyString()][string]$SubPath )
	# Pre-flight: need server/user/password to query OCS
	if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($User)) { return $null }
	if ([string]::IsNullOrWhiteSpace($Pass)) { return $null }
	# Shared state (ref) so event handlers mutate the SAME value
	$curPathRef = [ref](Normalize-SubPath $SubPath)
	$getCP = { $curPathRef.Value }; $setCP = { param($p) $curPathRef.Value = (Normalize-SubPath $p) }
	# The account being browsed, captured for the handlers below
	$acct = @{ Server = $Server; User = $User; Pass = $Pass }
	# --- UI ---
	$f = New-Object System.Windows.Forms.Form; Apply-BrandIconToForm $f; Hook-FormDpi $f; Hook-FormScreen $f
	$f.Text = (T 'title.folderpicker' @{ app = $AppName }); $f.StartPosition = 'CenterScreen'; $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false; $f.TopMost = $true; $f.Width = 520; $f.Height = 430; $f.KeyPreview = $true
	$lblCur = New-Object System.Windows.Forms.Label; $lblCur.Left = 12; $lblCur.Top = 12; $lblCur.AutoSize = $true
	$lb = New-Object System.Windows.Forms.ListBox; $lb.Left = 12; $lb.Top = 36; $lb.Width = $f.ClientSize.Width - 24; $lb.Height = 300; $lb.Anchor = 'Top, Left, Right'
	$btnUp = New-Object System.Windows.Forms.Button; $btnUp.Text = (T 'button.up'); $btnUp.Left = 12; $btnUp.Top = 346; $btnUp.Width = 70; $btnUp.Height = $script:ButtonH
	$btnOpen = New-Object System.Windows.Forms.Button; $btnOpen.Text = (T 'button.open'); $btnOpen.Left = $btnUp.Left + $btnUp.Width + 8; $btnOpen.Top = 346; $btnOpen.Width = 80; $btnOpen.Height = $script:ButtonH
	$btnSelect = New-Object System.Windows.Forms.Button; $btnSelect.Text = (T 'button.select'); $btnSelect.Width = 100; $btnSelect.Left = $f.ClientSize.Width - 220; $btnSelect.Top = 346; $btnSelect.Height = $script:ButtonH; $btnSelect.Anchor = 'Bottom, Right'
	$btnCancel = New-Object System.Windows.Forms.Button; $btnCancel.Text = (T 'button.cancel'); $btnCancel.Width = 100; $btnCancel.Left = $f.ClientSize.Width - 110; $btnCancel.Top = 346; $btnCancel.Height = $script:ButtonH; $btnCancel.Anchor = 'Bottom, Right'
	# Refresh list and header for the current path
	$refresh = {
		$p = & $getCP
		$lblCur.Text = if ([string]::IsNullOrWhiteSpace($p)) { (T 'label.folderpath') } else { (T 'label.folderpath') + $p }
		$lb.Items.Clear(); $children = Get-NcFolderChildren -Server $acct.Server -User $acct.User -Pass $acct.Pass -ParentPath $p
		if ($children -and $children.Count -gt 0) { foreach ($n in $children) { [void]$lb.Items.Add([string]$n) } }
		$btnUp.Enabled = (-not [string]::IsNullOrWhiteSpace($p))
	}
	# Navigate into selected child
	$openSelected = { $sel = [string]$lb.SelectedItem; if ([string]::IsNullOrWhiteSpace($sel)) { return }; $newPath = Join-SubPath (& $getCP) $sel; & $setCP $newPath; & $refresh }
	# Up one level
	$btnUp.Add_Click({ $p = & $getCP; if ([string]::IsNullOrWhiteSpace($p)) { return }; $parts = ($p -split '/') | Where-Object { $_ -ne '' }; $newP = if ($parts.Count -le 1) { '' } else { ($parts[0..($parts.Count-2)] -join '/') }; & $setCP $newP; & $refresh })
	# Open/double-click
	$btnOpen.Add_Click({ & $openSelected }); $lb.Add_DoubleClick({ & $openSelected })
	# Select: return either current folder or current/selected-child
	$btnSelect.Add_Click({ $sel = [string]$lb.SelectedItem; $chosen = if ([string]::IsNullOrWhiteSpace($sel)) { (& $getCP) } else { Join-SubPath (& $getCP) $sel }; $f.Tag = $chosen; $f.DialogResult = [System.Windows.Forms.DialogResult]::OK; $f.Close() })
	# Cancel
	$btnCancel.Add_Click({ $f.Tag = $null; $f.DialogResult = 'Cancel'; $f.Close() })
	# Enter/Esc behavior
	$f.AcceptButton = $btnSelect; $f.CancelButton = $btnCancel
	$f.Add_KeyDown({ param($s, $e); if ($e.KeyCode -eq 'Enter') { $btnSelect.PerformClick() } elseif ($e.KeyCode -eq 'Escape') { $btnCancel.PerformClick() } })
	$f.Controls.AddRange(@($lblCur, $lb, $btnUp, $btnOpen, $btnSelect, $btnCancel))
	& $refresh
	$res = $f.ShowDialog()
	if ($res -eq [System.Windows.Forms.DialogResult]::OK) { return [string]$f.Tag }
	return $null
}
