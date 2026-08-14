# Yes/No question (Information icon); returns DialogResult
function global:Ask-YesNoInfoT([string]$Key, [hashtable]$Vars = $null) { return Show-CustomMsgBoxT -Key $Key -Vars $Vars -Mode 'YesNo' -Icon 'Information' -Caption $AppName }
