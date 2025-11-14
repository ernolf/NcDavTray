<!-- Project header -->
<p>
  <img src="assets/logo-128.png" alt="NcDavTray logo" width="128" height="128" align="left">
  <h3>NcDavTray — Tiny Nextcloud WebDAV Tray for Windows</h3>
  <p>Windows WebDAV tray watcher + watchdog (PowerShell 5.1 + WinForms)</p>
  <p>
    <a href="https://github.com/ernolf/NcDavTray/releases"><img alt="Release" src="https://img.shields.io/github/v/release/ernolf/NcDavTray"></a>
    <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-GPL--3.0--or--later-blue"></a>
    <img alt="PowerShell 5.1" src="https://img.shields.io/badge/Windows%20PowerShell-5.1-blue">
  </p>
</p>
<hr>
<br clear="left">

Map your Nextcloud server to a real Windows drive letter (e.g. `Z:`) and keep it healthy. NcDavTray is a small, self‑contained tray app written in **Windows PowerShell 5.1 + WinForms and a small amount of embedded C# for DPI and shell notifications**. It runs without admin rights and supports both **Installed** and **Portable** modes.

---

## Features

* **One‑click drive mapping** to a persistent letter (your choice)
* **Auto‑reconnect & auto‑cleanup** if the server is offline or in maintenance mode, the letter changes its color
* **Optional subfolder mapping** (map any folder from within your nextcloud server)
* **Friendly Explorer appearance** (custom label & icon from your Nextcloud favicon)
* **Tray UI**: connect/disconnect (pause), status balloon, Settings, About, Exit
* **Two security models**:

  * **Installed**: credentials protected with Windows **DPAPI** (bound to your user profile)
  * **Portable**: credentials encrypted with **AES‑256 + PBKDF2** (passphrase you choose)
* **Watchdog** for clean unmount if the app (or USB stick in portable mode) disappears
* **Multi‑language (i18n)** with live switching and simple JSON language packs
* **WebClient tuning tab**: inspect and adjust the underlying Windows WebDAV redirector (WebClient) limits and timeouts with safe defaults, inline help texts and UAC-guarded “Apply changes” button.

---

## Requirements

* **Windows 10 / 11** with **Windows PowerShell 5.1** (the provided launcher starts PS 5.1 in STA automatically)
* **WebClient** service available & enabled (Windows WebDAV mini‑redirector)
* **Nextcloud** reachable via **HTTPS** (connection uses a **Nextcloud App Password**)

No administrator rights required.

---

## Install & Quick Start

1. **Download the latest ZIP** from this repository’s [Releases](https://github.com/ernolf/NcDavTray/releases) page.
2. **Extract** the ZIP to a folder **in your user profile**.
3. **Run** `installNcDavTray.cmd` and choose:

   * **1 — Installed mode**: copies the app into your profile (`%LOCALAPPDATA%\NcDavTray`), sets optional per‑user auto‑start (configurable in Settings), creates Start Menu/Desktop shortcuts, and safely stops + restarts any running instance while preserving your config.
   * **2 — Portable mode**: creates a self‑contained portable package in the selected folder. Launch it via the generated `Start NcDavTray.cmd`.

**First run:** open **Settings** from the tray, enter:

* **Server** (host only, e.g. `cloud.example.com`)
* **User** (Nextcloud user ID)
* **App password** (create in your Nextcloud profile → *Security*; the app uses this token for WebDAV)
* **Subfolder** (optional)
* **Drive letter** and **Display name** (optional)
* **Language** and **check interval**

Click **Save** → NcDavTray maps the drive, applies the icon/label, and keeps it online.

---

## Using the tray

* **Left‑click**: shows a short status balloon (server, drive, subpath, state)
* **Right‑click**: *Connect*, *Disconnect (pause)*, *Settings*, *About*, *Exit*

---

## Tuning the WebClient service

NcDavTray provides a **WebClient tuning** tab in the Settings dialog. It exposes the most relevant registry settings of the underlying Windows WebDAV redirector (WebClient) in a safe, documented way:

* Maximum number of files per folder (attribute cache size)
* Maximum file size (Max = 4 GB)
* Local / internet server timeouts
* Send/receive timeout
* "Server not found" cache lifetime

All values are shown with both their **current registry value** and a **readable explanation**, and each option has an inline help text.  
Reading the settings does **not** require admin rights; elevation (UAC) requires administrator permissions and is only requested when you click **“Apply changes”** which will write the new values back to the WebClient service.

---

## Security & Privacy

* **Password handling**

  * *Installed*: stored under your Windows account via **DPAPI**; never written in plain text or placed on the command line.
  * *Portable*: stored in `NcDavTray_secret.dat` encrypted with **AES‑256‑CBC**, key derived via **PBKDF2** (100k iterations) from your passphrase; decrypted only in memory.
* **Network scope:** NcDavTray only connects to **your** Nextcloud host for:
  * reachability/maintenance-mode check (`/status.php`)
  * **folder picker** via Nextcloud **OCS API** (listing/validation)
  * server favicon and user avatar
  * WebDAV operations required for mapping/unmapping

  **No telemetry or analytics. No third-party calls. No background update checks.**
* **Cleanup**: on disconnect/exit, the app unmounts the drive and removes cosmetic branding so Explorer doesn’t keep stale entries.

---

## Updating & Uninstall

* **Update (Installed)**: download the new ZIP and run `installNcDavTray.cmd` → choose **1**. The running instance is stopped and restarted automatically; your configuration is preserved.
* **Update (Portable)**: run `installNcDavTray.cmd` → choose **2** and point to your existing portable folder. Your `*_portable.json` and `*_secret.dat` are kept.
* **Uninstall (Installed)**: open **Settings → Uninstall**.
* **Uninstall (Portable)**: exit the app and delete the portable folder.

---
## Credits

- **Author & Maintainer:** [[ernolf] Raphael Gradenwitz](https://github.com/ernolf)
- **Acknowledgements:** Windows WebDAV mini-redirector, and the PowerShell & WinForms ecosystem.
