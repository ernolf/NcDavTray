# Dispose current clone and clear the PictureBox
function Clear-PictureImage([System.Windows.Forms.PictureBox]$pb) { try { if ($pb -and $pb.Image) { $pb.Image.Dispose(); $pb.Image = $null } } catch {} }
