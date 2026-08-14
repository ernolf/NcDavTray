function Request-CacheDeleteAll { $cmd = @{ Action = 'DeleteAll' }; return (Send-CacheAgentCommand -Command $cmd) }
