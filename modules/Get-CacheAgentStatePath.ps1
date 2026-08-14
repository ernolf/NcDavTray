function Get-CacheAgentStatePath { $dir = Get-CacheAgentStateDir; return (Join-Path $dir 'state.json') }
