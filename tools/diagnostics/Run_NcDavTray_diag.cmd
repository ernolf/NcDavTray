:: NcDavTray diagnostics launcher (wrapper)

:: SPDX-FileCopyrightText: 2025 [ernolf] Raphael Gradenwitz <raphael.gradenwitz@googlemail.com>
:: SPDX-License-Identifier: GPL-3.0-or-later

@echo off

cd /d "%~dp0"

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File ".\NcDavTray_diag.ps1"

echo.
echo Diagnostics finished. Press any key to close this window.
pause >nul
