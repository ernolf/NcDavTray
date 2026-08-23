<!--
SPDX-FileCopyrightText: 2026 [ernolf] Raphael Gradenwitz <raphael.gradenwitz@googlemail.com>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Sections up to 1.2.2 were written after the fact, from the notes of the releases
they belong to — the project had no changelog while those were made.

## [2.1.0] - 2026-08-23

### Added

- A Nextcloud that is installed in a subdirectory of a domain rather than at its root, entered as `cloud.example.com/nextcloud`. The installation path is shown next to the host wherever a server appears, because Windows counts its two logins per host: two installations on the same host share that limit between them. Mounts of an installation at the domain root keep the account key they had and need no migration (#23)

[2.1.0]: https://github.com/ernolf/NcDavTray/releases/tag/v2.1.0

## [2.0.0] - 2026-08-18

### Added

- Several mounts side by side, each with its own drive letter, subfolder, label and state
- Public share links as a kind of mount: a link ending in `/s/<token>` becomes a drive letter without an account on that server
- **Log in with browser**, which obtains the app password over Login Flow v2 (`POST /index.php/login/v2`) and stores it, instead of it being created by hand under *Settings → Security → Devices & sessions* and typed in (#13)
- An account is settled on its user id after a browser login: Login Flow v2 hands back the login name that was typed, and a verified mail address is one of them, so the server is asked which account signed in. One account therefore never occupies two stored passwords, two WebDAV paths and two of the two logins Windows keeps per server (#15)
- **Duplicate…**, which clones a mount to reach a second folder of the same account under another letter
- A tray icon per mount, showing its state, and a switch to turn the per-mount icons off
- A check for a newer release from the About box, and optionally once at startup
- **Update now** in the About box, which installs that release: the downloaded copy writes over the running one and starts it again, and mounts, passwords, settings, shortcuts and autostart survive it. Language packs are merged rather than replaced, and nothing is written over before the download is verified against the size the release states (#17)
- A balloon a moment after every start, naming the version that is running — and the newer release in the same balloon when the startup check found one (#17)
- A status of its own for a mount Windows refuses because the server has no free login left, instead of reporting it as a failed mapping

### Changed

- **BREAKING** A configuration is a list of mounts, not the single account of 1.x. An existing setup is migrated on first start and nothing is lost, but a configuration written by 2.0 cannot be read by 1.x
- The documentation moved from the README into the [wiki](https://github.com/ernolf/NcDavTray/wiki), which holds far more of it than a README ever could: a page per subject, the error numbers and the Windows limits behind them, the WebClient service and its cache, and screenshots throughout. The README introduces the program and points there

### Fixed

- The **WebClient tuning** tab said which timeout applies by looking at the security zone of the server. The zone has no influence on it: the redirector uses the local timeout for a host name without a dot and the internet timeout for every other. The tab now says that, and leaves the local timeout field disabled while no mount names such a host (#11)
- The **WebClient tuning** tab waited for a server to answer before it opened (#11)

[2.0.0]: https://github.com/ernolf/NcDavTray/releases/tag/v2.0.0

## [1.2.2] - 2026-04-21

### Added

- Screenshots throughout the README: tray states, context menus, the tabs of the settings dialog, and Explorer with custom drive icons and labels

### Changed

- The embedded bitmap was replaced with a more compact variant, which takes about 43 KB off the script without changing anything on screen
- The README now describes automatic Office file locking correctly, with and without the `files_lock` app, including the bypass that happens when the same user opens the file twice

### Fixed

- The WebDAV cache tab silently ignored the first interaction with it
- The status label of the cache watcher was missing quotes in an i18n call
- `$args` in `Start-InstalledInstance` shadowed a PowerShell automatic variable
- A duplicate cleanup of the tab variables in the `FormClosed` handler
- An unnecessary `global:` qualifier on an internal function
- A redundant `UpdateSaveButton` call in the avatar `TextChanged` handler

[1.2.2]: https://github.com/ernolf/NcDavTray/releases/tag/v1.2.2

## [1.2.1] - 2025-12-07

### Added

- **Open in Explorer** in the tray menu, which opens the mapped drive without going looking for it

### Fixed

- Several small defects

[1.2.1]: https://github.com/ernolf/NcDavTray/releases/tag/v1.2.1

## [1.2.0] - 2025-11-26

### Added

- A **WebDAV cache** tab that lists what the Windows WebDAV cache currently holds, with name, size, modification time and entry type
- **Clear cache**, which wipes the cached files on demand
- **Clear cache on exit**, which lets the watcher wipe the cache when the last instance closes
- The watcher can be started and stopped from any instance, runs elevated when it has to, and is shared by every instance on the machine

[1.2.0]: https://github.com/ernolf/NcDavTray/releases/tag/v1.2.0

## [1.1.2] - 2025-11-25

### Changed

- Trailing whitespace removed across the script, and some internal reordering with no effect on behaviour

### Fixed

- The Nextcloud folder picker built malformed OCS URLs and could not descend into subfolders
- The watchdog is scoped to the PID of the script that started it, so several instances can run at once without interfering with each other
- The watchdog reloads its configuration before unmapping, and copes with a USB drive that is pulled out from under a portable copy

[1.1.2]: https://github.com/ernolf/NcDavTray/releases/tag/v1.1.2

## [1.1.1] - 2025-11-19

### Added

- An Italian translation
- A warning that points at the **WebClient tuning** tab when the service is disabled

### Changed

- A WebClient service set to *Disabled* is recognised as such, and the tray icon and status texts say so instead of reporting a mapping that failed for no visible reason

[1.1.1]: https://github.com/ernolf/NcDavTray/releases/tag/v1.1.1

## [1.1.0] - 2025-11-14

### Added

- A **WebClient tuning** tab for the limits and timeouts of the Windows WebDAV client, with a UAC-guarded *Apply changes*

### Changed

- The settings dialog is laid out in tabs
- Unsaved changes are tracked more reliably, in the settings and in the tuning values
- Labels, layout and tooltips throughout, with several small interface defects fixed along the way

[1.1.0]: https://github.com/ernolf/NcDavTray/releases/tag/v1.1.0

## [1.0.0] - 2025-11-01

### Added

- Maps Nextcloud WebDAV storage to a Windows drive letter
- Disconnects cleanly and reconnects by itself when the server comes back
- Installed and portable mode
- English built in, with German, Spanish, French, Dutch and Portuguese (Brazil) as language packs
- Needs no administrator rights

[1.0.0]: https://github.com/ernolf/NcDavTray/releases/tag/v1.0.0
