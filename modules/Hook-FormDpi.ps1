function Hook-FormDpi([System.Windows.Forms.Form]$f) { if (-not $f) { return }; $f.AutoScaleMode = 'Dpi' }
