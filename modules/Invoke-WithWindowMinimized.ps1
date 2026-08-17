# Runs something that opens a window of its own, with the window it was started
# from out of the way. These windows are fixed dialogs: while a child is up, the
# one behind it cannot be moved, and where it sits is where the browser login or
# the next dialog has to happen.
# Minimized and not hidden: hiding a form ends the ShowDialog it is running in.
# Whatever the body opens must not be owned by the minimized window either --
# owned windows follow their owner into the minimize.
function Invoke-WithWindowMinimized {
	[CmdletBinding()] param( [System.Windows.Forms.Form]$Window, [Parameter(Mandatory)][scriptblock]$Body )
	$restore = $false
	if ($Window -and (-not $Window.IsDisposed) -and $Window.Visible -and $Window.WindowState -ne [System.Windows.Forms.FormWindowState]::Minimized) {
		# A minimized window has next to no client area, and everything that is laid
		# out to what the window gives it is laid out to that: the tab control, the
		# table inside it, the list that takes the row the footer leaves. Coming back
		# does not undo it -- the window returns at its old size with the arrangement
		# of one that had none. So the layout is held for as long as the window is
		# down and run once afterwards, at the size it is meant for.
		try {
			$Window.SuspendLayout()
			$Window.WindowState = [System.Windows.Forms.FormWindowState]::Minimized
			$restore = $true
		} catch { try { $Window.ResumeLayout($false) } catch {} }
	}
	try { & $Body }
	finally {
		if ($restore -and (-not $Window.IsDisposed)) {
			try {
				$Window.WindowState = [System.Windows.Forms.FormWindowState]::Normal
				$Window.ResumeLayout($true)
				$Window.Activate()
			} catch {}
		}
	}
}
