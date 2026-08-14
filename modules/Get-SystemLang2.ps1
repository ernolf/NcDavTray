# Two-letter UI culture (e.g., 'de', 'en', 'fr')
function Get-SystemLang2{ try { return [System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName } catch { return 'en' } }
