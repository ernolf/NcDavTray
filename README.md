<!--
SPDX-FileCopyrightText: 2025 [ernolf] Raphael Gradenwitz <raphael.gradenwitz@googlemail.com>
SPDX-License-Identifier: GPL-3.0-or-later
-->

<!-- Project header -->
<p>
  <img src="assets/logo-128.png" alt="NcDavTray logo" width="128" height="128" align="left">
  <h3>NcDavTray — Tiny Nextcloud WebDAV Tray for Windows</h3>
  <p>Windows WebDAV tray watcher + watchdog (PowerShell 5.1 + WinForms)</p>
  <p>
    <a href="https://api.reuse.software/info/github.com/ernolf/NcDavTray"><img alt="REUSE status" src="https://api.reuse.software/badge/github.com/ernolf/NcDavTray"></a>
    <a href="https://github.com/ernolf/NcDavTray/releases"><img alt="Release" src="https://img.shields.io/github/v/release/ernolf/NcDavTray"></a>
    <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-GPL--3.0--or--later-blue"></a>
    <img alt="PowerShell 5.1" src="https://img.shields.io/badge/Windows%20PowerShell-5.1-blue">
  </p>
</p>
<hr>
<br clear="left">

Map your Nextcloud to a real Windows drive letter and keep it healthy. NcDavTray is a small self-contained tray application: no runtime, nothing installed system-wide, and no administrator rights for its normal work. It runs **installed** or **portable**, and it holds as many mounts as you have drive letters — Nextcloud accounts and public share links side by side.

> **📖 The documentation lives in the [wiki](https://github.com/ernolf/NcDavTray/wiki).** This page is the short version.

## Features

* **Any number of mounts** in one tray application — accounts and public `/s/…` share links
* **Watchdog and auto-reconnect** — server offline or in maintenance, the drive is unmapped cleanly and remounted as soon as it is back
* **Automatic file locking for Office applications**, which the official Nextcloud Desktop Client cannot do — see **[File locking](https://github.com/ernolf/NcDavTray/wiki/File-locking)**
* **Subfolder mapping**, custom Explorer label and an icon taken from your Nextcloud favicon
* **Two security models** — DPAPI when installed, AES-256-CBC with PBKDF2 when portable
* **WebClient tuning** and a **WebDAV cache** view for the Windows redirector behind it all
* **Seven languages**, switched live without a restart
* **Optional update check**, off by default. No telemetry, no analytics, no third-party calls

## Requirements

* Windows 10 or 11 with **Windows PowerShell 5.1**
* The **WebClient** service, set to *Manual* or *Automatic*
* A Nextcloud reachable over **HTTPS**, and an **app password** for it

## Quick start

1. Download the ZIP from [Releases](https://github.com/ernolf/NcDavTray/releases) and unpack it inside your user profile.
2. Run `Installer.cmd` and pick **1** (installed) or **2** (portable).
3. Right-click the tray icon → **Add account…** or **Add share link…**, choose a drive letter, save.

Full walkthrough: **[Installation](https://github.com/ernolf/NcDavTray/wiki/Installation)** and **[Mounts](https://github.com/ernolf/NcDavTray/wiki/Mounts)**.

> **⚠️ Planning more than two mounts on one server?** Windows keeps one login per server identity and allows two identities per host. Read **[Server identities](https://github.com/ernolf/NcDavTray/wiki/Server-identities)** before you configure them.

## Documentation

| | |
|---|---|
| [Installation](https://github.com/ernolf/NcDavTray/wiki/Installation) | installed and portable, updating, uninstalling |
| [Mounts](https://github.com/ernolf/NcDavTray/wiki/Mounts) | the mount list, drive letters, subfolders, status vocabulary |
| [Share links](https://github.com/ernolf/NcDavTray/wiki/Share-links) | public links as a drive, and what to do when one refuses |
| [Server identities](https://github.com/ernolf/NcDavTray/wiki/Server-identities) | the Windows two-login limit and error 1219 |
| [The tray](https://github.com/ernolf/NcDavTray/wiki/The-tray) | icons, shapes, colours and every menu entry |
| [File locking](https://github.com/ernolf/NcDavTray/wiki/File-locking) | Office locking, `files_lock`, and the Desktop Client comparison |
| [WebClient service](https://github.com/ernolf/NcDavTray/wiki/WebClient-service) · [WebDAV cache](https://github.com/ernolf/NcDavTray/wiki/WebDAV-cache) | the Windows redirector: limits, timeouts, cache |
| [Security and privacy](https://github.com/ernolf/NcDavTray/wiki/Security-and-privacy) | where passwords live, which hosts are contacted |
| [Languages](https://github.com/ernolf/NcDavTray/wiki/Languages) · [Updates](https://github.com/ernolf/NcDavTray/wiki/Updates) | language packs, the update check |
| [Build from source](https://github.com/ernolf/NcDavTray/wiki/Build-from-source) | the module tree, `make.cmd`, and how a release is assembled |

Coming from version 1? See **[Differences between 1 and 2](https://github.com/ernolf/NcDavTray/wiki/Differences-between-1-and-2)**. The 1.x line ended with [v1.2.2](https://github.com/ernolf/NcDavTray/releases/tag/v1.2.2) and is documented in the README of that tag.

## Building

The repository holds sources; the script you run is assembled from them.

```
make.cmd            build and run the static checks
make.cmd dist       build and pack the release archive
```

Windows PowerShell 5.1 is the only prerequisite. Details in **[Build from source](https://github.com/ernolf/NcDavTray/wiki/Build-from-source)**.

## License and credits

GPL-3.0-or-later, see [LICENSE](LICENSE). The project is [REUSE](https://reuse.software/)-compliant.

* **Author & Maintainer:** [[ernolf] Raphael Gradenwitz](https://github.com/ernolf)
* **Acknowledgements:** Windows WebDAV mini-redirector (WebClient), the PowerShell & WinForms ecosystem, and the Nextcloud community.
