# Turns a ComboBox into the drive letter picker: every letter
# from D: to Z:, coloured by what it is -- free, taken by something else, or the
# one this mount already holds -- and a selection that refuses to settle on a
# letter somebody else occupies. Filling it is Update-DriveLetterPicker's job;
# this installs the drawing and the guard, once per box.
# The picker's state travels in the box's Tag, so one dialog can carry more than
# one of them. Only the deferred correction goes through the script scope: a
# delegate the message loop calls later sees neither the locals nor the
# parameters of the call that created it.
function Initialize-DriveLetterPicker {
	[CmdletBinding()] param( [Parameter(Mandatory)][System.Windows.Forms.ComboBox]$ComboBox, [scriptblock]$OnChanged = $null )
	$ComboBox.DrawMode = 'OwnerDrawFixed'; $ComboBox.ItemHeight = $ComboBox.Font.Height + 4
	$ComboBox.Tag = @{ Statuses = @{}; Current = ''; Reserved = @(); Prev = $null; OnChanged = $OnChanged }
	# Guard: prevent re-entrancy while the selection is corrected programmatically
	$script:DriveSelBusy = $false
	# The box and the letter the deferred correction works on -- see below
	$script:DriveSelBox = $null
	$script:DriveSelFallback = $null
	$ComboBox.add_DrawItem({
		param($s, $e)
		if ($e.Index -lt 0) { return }
		$d = [string]$s.Items[$e.Index]
		$st = if ($s.Tag.Statuses.ContainsKey($d)) { $s.Tag.Statuses[$d] } else { 'free' }
		switch ($st) { 'free' { $bgColor = [System.Drawing.Color]::PaleGreen }; 'used' { $bgColor = [System.Drawing.Color]::LightCoral }; 'current' { $bgColor = [System.Drawing.Color]::Khaki }; default { $bgColor = [System.Drawing.Color]::White } }
		if (($e.State -band [System.Windows.Forms.DrawItemState]::Selected) -ne 0) { $e.Graphics.FillRectangle([System.Drawing.SystemBrushes]::Highlight, $e.Bounds); $fg = [System.Drawing.SystemBrushes]::HighlightText }
		else { $bg = New-Object System.Drawing.SolidBrush($bgColor); $e.Graphics.FillRectangle($bg, $e.Bounds); $bg.Dispose(); $fg = [System.Drawing.Brushes]::Black }
		$e.Graphics.DrawString($d, $e.Font, $fg, $e.Bounds.X+2, $e.Bounds.Y+2); $e.DrawFocusRectangle()
	})
	# Deliberately no GetNewClosure: inside one, $script: addresses the closure's
	# own module scope, and everything handed over below would read as empty.
	$ComboBox.add_SelectionChangeCommitted({
		param($s, $e)
		if ($script:DriveSelBusy) { return } # Ignore if we're already fixing selection programmatically
		$new = [string]$s.SelectedItem
		if (-not $new) { return }
		# what is taken right now, not what was taken when the list was built
		$usedNow = @(Get-PSDrive -PSProvider FileSystem | Select-Object -Expand Name | ForEach-Object { '{0}:' -f $_ })
		$cur = [string]$s.Tag.Current
		# the letter this mount already holds is its own, however taken it looks
		$isOurCurrent = ($cur -and ($new -ieq $cur))
		if (-not $isOurCurrent -and (($usedNow -contains $new) -or (@($s.Tag.Reserved) -contains $new))) {
			Show-WarnT 'message.drive_letter_used' @{ drive = $new }
			# Decide fallback target (the letter this mount holds, the previous valid one, or the first free)
			$target = $null
			if ($cur -and $s.Items.Contains($cur)) { $target = $cur }
			elseif ($s.Tag.Prev -and $s.Items.Contains([string]$s.Tag.Prev)) { $target = [string]$s.Tag.Prev }
			if (-not $target) { $firstFree = ($s.Items | Where-Object { -not (($usedNow -contains [string]$_) -or (@($s.Tag.Reserved) -contains [string]$_)) } | Select-Object -First 1); if ($firstFree) { $target = [string]$firstFree } }
			# Set selection asynchronously to avoid re-entrancy during the setter
			$script:DriveSelBusy = $true
			# A delegate the message loop calls later sees neither the locals nor the
			# parameters of the call it was created in, so the box and the letter to
			# fall back to are handed over through the script scope.
			$script:DriveSelBox = $s
			$script:DriveSelFallback = $target
			$s.BeginInvoke([Action]{ try { if ($script:DriveSelFallback) { $script:DriveSelBox.SelectedItem = $script:DriveSelFallback } else { $script:DriveSelBox.SelectedIndex = -1 } } finally { $script:DriveSelBusy = $false } }) | Out-Null
			return
		}
		$s.Tag.Prev = $new # Accept user choice
		if ($s.Tag.OnChanged -is [scriptblock]) { & $s.Tag.OnChanged }
	})
	# Also react when selection actually changes (keyboard, programmatic dropdown close, etc.)
	$ComboBox.add_SelectedIndexChanged({
		param($s, $e)
		if ($script:DriveSelBusy) { return } # ignore while we revert programmatically
		if ($s.Tag.OnChanged -is [scriptblock]) { & $s.Tag.OnChanged }
	})
}