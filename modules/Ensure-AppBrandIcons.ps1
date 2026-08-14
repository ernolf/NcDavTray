# create (once) and cache icon + bitmap for reuse
function Ensure-AppBrandIcons {
	if ($script:AppIcon -and -not $script:AppIcon.IsDisposed) { return } # already initialized
	try { $bytes = Get-EmbeddedIconBytes; $ms = New-Object System.IO.MemoryStream(, $bytes); $ico = New-Object System.Drawing.Icon $ms; $script:AppIcon = $ico; $ms.Dispose() } catch { $script:AppIcon = $null }
}
