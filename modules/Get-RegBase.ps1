# The registry key everything is kept under. It is the name the single account
# of the versions before 2.0.0 already lived under, so the mount list grows
# inside that key rather than beside it.
function Get-RegBase { return ("HKCU:\Software\{0}" -f $AppName) }