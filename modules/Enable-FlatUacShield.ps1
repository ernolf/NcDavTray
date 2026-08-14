# Always show a small UAC shield bitmap; no OS overlay used
function Enable-FlatUacShield([System.Windows.Forms.Button]$btn) {
	try {
		if (-not $btn -or $btn.IsDisposed) { return }
		# Ensure handle exists
		$null = $btn.Handle
		# Import SendMessage once (local helper type)
		if (-not ('Ndt_Native' -as [type])) {
			Add-Type -Namespace Ndt -Name Native -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
public static extern System.IntPtr SendMessage(System.IntPtr hWnd, uint Msg, System.IntPtr wParam, System.IntPtr lParam);
"@
		}
		# Use OS-drawn UAC shield via BCM_SETSHIELD so look is consistent everywhere
		$btn.FlatStyle = [System.Windows.Forms.FlatStyle]::System
		[Ndt.Native]::SendMessage($btn.Handle, 0x160C, [IntPtr]0, [IntPtr]1) | Out-Null
		$btn.Padding = New-Object System.Windows.Forms.Padding(16, 0, 16, 0)
	} catch {}
}
