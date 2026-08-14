# One value per server/user pair, holding that pair's DPAPI blob. The password
# belongs to the pair and not to a mount: two mounts of the same account are one
# and the same login, and a password changed on one of them while the other kept
# the old one would only be found out when that other one stops working.
# Public shares keep theirs in the mount's own subkey. A share token is handed out
# once and used once by design, so there is no pair there to share anything with.
function Get-AccountsRegPath { return (Join-Path (Get-RegBase) 'Accounts') }