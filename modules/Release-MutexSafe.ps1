# Release + dispose helper (no-throw)
function Release-MutexSafe($m) { try { if ($m) { $m.ReleaseMutex() | Out-Null } } catch {}; try { if ($m) { $m.Dispose() } } catch {} }
