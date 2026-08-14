# Yes/No question (Question icon); returns DialogResult
function global:Ask-YesNoQuestT([string]$Key, [hashtable]$Vars = $null) { return Show-CustomMsgBoxT -Key $Key -Vars $Vars -Mode 'YesNo' -Icon 'Question' -Caption $AppName }
