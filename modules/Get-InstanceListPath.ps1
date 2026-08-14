function Get-InstanceListPath { $dir = Get-InstanceStateDir; return (Join-Path $dir 'instances.json') }
