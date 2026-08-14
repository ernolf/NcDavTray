# Yes/No/Cancel question (Question icon); returns DialogResult
function global:Ask-YesNoCancelQuestT([string]$Key, [hashtable]$Vars = $null) { return Show-CustomMsgBoxT -Key $Key -Vars $Vars -Mode 'YesNoCancel' -Icon 'Question' -Caption $AppName }
