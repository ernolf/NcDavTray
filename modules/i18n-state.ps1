# Internal i18n state
$script:I18N = @{
	Language = 'en' # resolved language (two-letter or custom)
	Fallback = @{} # hashtable of embedded EN
	Current = @{} # merged: Fallback + external overrides
	FilePath = $null # loaded file path (if any)
}
