# NcDavTray diagnostics

This folder contains tools to collect a text diagnostics report for NcDavTray / WebClient mapping problems on Windows.

## Files

* `NcDavTray_diag.ps1` – PowerShell diagnostics script.
* `Run_NcDavTray_diag.cmd` – helper to run the script with the built-in Windows PowerShell 5.1.

## How to run

1. Copy both files into any folder on the affected Windows machine (for example `C:\Users\<you>\Desktop\NcDavTrayDiag`).
2. Make sure **NcDavTray is running as you normally use it** (if possible).
3. Start `Run_NcDavTray_diag.cmd` (double-click).
4. Follow the prompts:

   * Select diagnostics profile (Local vs. Public issue / GitHub).
   * Select mode (installed vs. portable).
   * Optionally collect UI / font / DPI and HTTP reachability information.
5. When the script finishes it writes a file named like `NcDavTray_diag_YYYYMMDD_HHMMSS.txt` into the **same folder** where the scripts are located.

## When opening a GitHub issue

* Prefer the profile **"Public issue / GitHub"** so host names, users and labels are anonymized automatically.
* Open a new issue in the NcDavTray repository.
* Paste the **full contents** of the diagnostics `.txt` file directly into the issue description inside a fenced code block, for example:

  \`\`\`

  `<paste diagnostics output here>`

  \`\`\`

ernolf