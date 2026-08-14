# Set once: desired shield size in pixels (e.g., 32 or 36)
$script:UAC_SHIELD_PX = 30
function Enable-UacShield([System.Windows.Forms.Button]$btn) {
	try {
		if (-not $btn -or $btn.IsDisposed) { return }
		$null = $btn.Handle
		# Disable OS overlay so custom size is used
		if (-not ('Ndt_Native' -as [type])) {
			Add-Type -Namespace Ndt -Name Native -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
public static extern System.IntPtr SendMessage(System.IntPtr hWnd, uint Msg, System.IntPtr wParam, System.IntPtr lParam);
"@
		}
		[Ndt.Native]::SendMessage($btn.Handle,0x160C,[IntPtr]0,[IntPtr]0) | Out-Null # BCM_SETSHIELD FALSE
		$px = [math]::Max(8,[int]$script:UAC_SHIELD_PX)
		try { if ($btn.Image) { $btn.Image.Dispose() } } catch {}
		$ico = [System.Drawing.SystemIcons]::Shield
		$bmp = New-Object System.Drawing.Bitmap $px,$px
		$g = [System.Drawing.Graphics]::FromImage($bmp)
		$g.InterpolationMode = 'HighQualityBicubic'
		$g.SmoothingMode = 'HighQuality'
		$g.PixelOffsetMode = 'HighQuality'
		$g.Clear([System.Drawing.Color]::Transparent)
		$g.DrawImage($ico.ToBitmap(),0,0,$px,$px)
		$g.Dispose()
		$btn.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
		$btn.Image = $bmp
		$btn.ImageAlign = [System.Drawing.ContentAlignment]::MiddleLeft
		$btn.TextImageRelation = [System.Windows.Forms.TextImageRelation]::ImageBeforeText
		if ($btn.Padding.Left -lt 6) { $btn.Padding = New-Object System.Windows.Forms.Padding(16,0,16,0) }
	} catch {}
}
