# Simple OK/Warning message using a localized string
function global:Show-WarnT([string]$Key, [hashtable]$Vars = $null) { [void](Show-CustomMsgBoxT -Key $Key -Vars $Vars -Mode 'OK' -Icon 'Warning' -Caption $AppName) }
