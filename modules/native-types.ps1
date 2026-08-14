# --- DPI: minimal (process-wide) ---
if (-not ("Nc.Dpi" -as [type])) {
	try {
		Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Nc {
	public static class Dpi {
		[DllImport("user32.dll", SetLastError = false)]
		static extern bool SetProcessDpiAwarenessContext(IntPtr value);
		[DllImport("shcore.dll", SetLastError = false)]
		static extern int SetProcessDpiAwareness(int value); // 0 = Unaware, 1 = System, 2 = PerMonitor
		[DllImport("user32.dll", SetLastError = false)]
		static extern bool SetProcessDPIAware();
		static readonly IntPtr PER_MONITOR_V2 = (IntPtr)(-4);
		public static void EnableBest() {
			try { if (SetProcessDpiAwarenessContext(PER_MONITOR_V2)) return; } catch {}
			try { if (SetProcessDpiAwareness(2) == 0) return; } catch {}
			try { SetProcessDPIAware(); } catch {}
		}
	}
}
'@
	} catch {}
}
[Nc.Dpi]::EnableBest() | Out-Null

Add-Type -AssemblyName System.Windows.Forms, System.Drawing

# --- Win32 WebDAV mapping via WNetAddConnection2 (no password in cmdline) ---
if (-not ("Nc.NetUse" -as [type])) {
	Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Nc {
	public static class NetUse {
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct NETRESOURCE {
			public uint dwScope;
			public uint dwType;
			public uint dwDisplayType;
			public uint dwUsage;
			public string lpLocalName;
			public string lpRemoteName;
			public string lpComment;
			public string lpProvider;
		}
		[DllImport("mpr.dll", CharSet = CharSet.Unicode)]
		public static extern int WNetAddConnection2(ref NETRESOURCE nr, string password, string username, uint flags);
		[DllImport("mpr.dll", CharSet = CharSet.Unicode)]
		public static extern int WNetCancelConnection2(string name, uint flags, bool force);
		public const uint RESOURCETYPE_DISK = 0x00000001;
		public const uint CONNECT_UPDATE_PROFILE = 0x00000001;
	}
}
'@
}

# Important: this must be called before the first WinForms window
# Call once per process:
# SetCompatibleTextRenderingDefault() must be invoked before any WinForms control/window
# is created (first IWin32Window) and only once.
# Re-running this script in the same PowerShell session throws a MethodInvocationException
# with an InvalidOperationException (via FullyQualifiedErrorId).
# This is why we use a one-time guard:
if (-not ("Nc.WinFormsOnce" -as [type])) {
	Add-Type -TypeDefinition @'
namespace Nc { public static class WinFormsOnce { public static bool Done; } }
'@
}
if (-not [Nc.WinFormsOnce]::Done) { [System.Windows.Forms.Application]::EnableVisualStyles(); try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch {}; [Nc.WinFormsOnce]::Done = $true }

# Shell refresh (one-time type)
if (-not ("Nc.Shell" -as [type])) {
	Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Nc {
	public static class Shell {
		[DllImport("shell32.dll")]
		public static extern void SHChangeNotify(uint wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);
		[DllImport("shell32.dll", CharSet = CharSet.Unicode)]
		public static extern void SHChangeNotify(uint wEventId, uint uFlags, string pszItem1, string pszItem2);
	}
}
'@
}

# P/Invoke: DestroyIcon from user32.dll to release HICON handles created by Bitmap.GetHicon().
# Why: Icon.FromHandle does NOT take ownership; without DestroyIcon, GDI handles leak over time.
# Used by: New-StatusIcon() and Save-IconFromBitmap() when cloning icons from HICON.
# Load once; guarded so re-running the script won't re-add the type.
if (-not ('Nc.Win32' -as [type])) {
	Add-Type -Namespace Nc -Name Win32 -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
public static extern bool DestroyIcon(System.IntPtr hIcon);
"@
}

# Where the shell drew a tray icon. Needed to put our own hover tip where Windows
# puts its own -- see Register-TrayHoverTip. The shell names an icon by the window
# it sends the icon's messages to plus that icon's id; WinForms keeps both to
# itself, so they are read off the NotifyIcon by reflection.
if (-not ('Nc.TrayIcon' -as [type])) {
	Add-Type -ReferencedAssemblies 'System.Windows.Forms', 'System.Drawing' -TypeDefinition @'
using System;
using System.Drawing;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;
namespace Nc {
	public static class TrayIcon {
		[StructLayout(LayoutKind.Sequential)]
		struct NOTIFYICONIDENTIFIER {
			public uint cbSize;
			public IntPtr hWnd;
			public uint uID;
			public Guid guidItem;
		}
		[StructLayout(LayoutKind.Sequential)]
		struct RECT { public int left, top, right, bottom; }
		[DllImport("shell32.dll", SetLastError = false)]
		static extern int Shell_NotifyIconGetRect(ref NOTIFYICONIDENTIFIER identifier, out RECT iconLocation);
		// Empty when the icon cannot be located, which leaves the caller to fall back
		// on the pointer. S_FALSE says the icon sits in the overflow flyout and the
		// rectangle is the button that opens it -- still where the user is pointing.
		public static Rectangle GetRect(NotifyIcon icon) {
			if (icon == null) return Rectangle.Empty;
			try {
				Type t = typeof(NotifyIcon);
				FieldInfo fw = t.GetField("window", BindingFlags.NonPublic | BindingFlags.Instance);
				FieldInfo fi = t.GetField("id", BindingFlags.NonPublic | BindingFlags.Instance);
				if (fw == null || fi == null) return Rectangle.Empty;
				NativeWindow w = fw.GetValue(icon) as NativeWindow;
				if (w == null || w.Handle == IntPtr.Zero) return Rectangle.Empty;
				NOTIFYICONIDENTIFIER nid = new NOTIFYICONIDENTIFIER();
				nid.cbSize = (uint)Marshal.SizeOf(typeof(NOTIFYICONIDENTIFIER));
				nid.hWnd = w.Handle;
				nid.uID = (uint)(int)fi.GetValue(icon);
				RECT r;
				if (Shell_NotifyIconGetRect(ref nid, out r) < 0) return Rectangle.Empty;
				return Rectangle.FromLTRB(r.left, r.top, r.right, r.bottom);
			} catch { return Rectangle.Empty; }
		}
	}
}
'@
}