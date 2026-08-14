# Simple OK/Error message using a localized string
function global:Show-ErrorT([string]$Key, [hashtable]$Vars = $null) { [void](Show-CustomMsgBoxT -Key $Key -Vars $Vars -Mode 'OK' -Icon 'Error' -Caption $AppName) }
