# One subkey per mount, named by the entry's Id. Values sit under this key and
# never at the top level: the flat values there belong to the single account of
# the versions before 2.0.0 and are left untouched, so a copy of an older build
# still finds its configuration after this one has run.
function Get-MountsRegPath { return (Join-Path (Get-RegBase) 'Mounts') }