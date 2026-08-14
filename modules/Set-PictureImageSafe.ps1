# Always assign a clone to the PictureBox to avoid disposing shared/global bitmaps.
function Set-PictureImageSafe([System.Windows.Forms.PictureBox]$pb, [System.Drawing.Image]$img) { try { if (-not $pb) { return }; if ($null -eq $img) { $pb.Image = $null; return }; $null = $img.Width; $pb.Image = $img.Clone() } catch { try { $pb.Image = $null } catch {} } }
