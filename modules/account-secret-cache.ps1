# Where a portable copy holds its passwords while it runs. Installed copies never
# touch this: theirs live in the Accounts key. Keyed exactly like that key is, so
# both halves of Get-AccountSecret answer the same question the same way, and
# holding DPAPI blobs like it does, so every reader gets what it expects.
# Behind it is the secret file, which is where these survive the program -- see
# Save-PortableSecretStore for why the two are not stored the same way.
$script:AccountSecretCache = @{}
# Asked once per run and then in force for both directions: unlocking what the
# file holds and protecting what is added to it afterwards.
$script:SecretPassphrase = $null