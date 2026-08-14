# Simple OK/Information message using a localized string
function global:Show-InfoT([string]$Key, [hashtable]$Vars = $null) { [void](Show-CustomMsgBoxT -Key $Key -Vars $Vars -Mode 'OK' -Icon 'Information' -Caption $AppName) }
