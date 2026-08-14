# How the program starts without a console window flashing up: a
# one-line VBS beside the script, run by wscript. It is rewritten only when its
# content would change, so an update of the script it starts leaves it alone.
function Get-LauncherFor([string]$scriptPath) {
	$vbsFile = [System.IO.Path]::ChangeExtension($scriptPath, 'vbs')
	$line = 'CreateObject("Wscript.Shell").Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File ""' + $scriptPath + '""", 0, False'
	if (-not (Test-Path $vbsFile) -or (Get-Content -Raw -Path $vbsFile -ErrorAction SilentlyContinue) -ne $line) { Set-Content -Path $vbsFile -Value $line -Encoding ASCII }
	return @("$env:SystemRoot\System32\wscript.exe", "`"$vbsFile`"")
}