function Refresh-ShellIcons { try { [Nc.Shell]::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero) } catch {} }
