# Yes/No question (Warning icon); returns DialogResult
function global:Ask-YesNoWarnT([string]$Key, [hashtable]$Vars = $null, [switch]$Uac) { return Show-CustomMsgBoxT -Key $Key -Vars $Vars -Mode 'YesNo' -Icon 'Warning' -Caption $AppName -Uac:$Uac }
