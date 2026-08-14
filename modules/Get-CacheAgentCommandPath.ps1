function Get-CacheAgentCommandPath { $dir = Get-CacheAgentStateDir; return (Join-Path $dir 'command.json') }
