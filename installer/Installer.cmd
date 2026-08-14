:: SPDX-FileCopyrightText: 2025 [ernolf] Raphael Gradenwitz <raphael.gradenwitz@googlemail.com>
:: SPDX-License-Identifier: GPL-3.0-or-later
:: Bootstrap for NcDavTray: install or make portable here

@echo off
setlocal enableextensions

REM --- Move working directory to the folder of this installer (robust for double-click) ---
pushd "%~dp0" >nul 2>&1

REM --- Locate Windows PowerShell 5.1 (prefer system path; fallback to PATH) ---
set "_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%_PS%" (
	REM fallback: try powershell.exe via PATH (rare, but safe)
	set "_PS=powershell.exe"
	where powershell.exe >nul 2>&1
	if errorlevel 1 (
		echo Cannot find Windows PowerShell 5.1.
		echo Please ensure PowerShell 5.1 is installed and available.
		set "_RC=2" & goto :finish
	)
)

REM --- Ensure the PowerShell script sits next to this installer ---
set "_PS1=NDT.ps1"
if not exist "%_PS1%" (
	echo "%_PS1%" not found in: "%cd%"
	set "_RC=1" & goto :finish
)

:menu
echo ==============================================
echo   NcDavTray - Installer
echo ==============================================
echo   1) Install to AppData (installed mode)
echo   2) Portable (current folder by default or choose another)
echo   0) Exit
echo ==============================================
set "choice="
set /p choice="Select: "

if "%choice%"=="1" goto do_install
if "%choice%"=="2" goto do_portable
if "%choice%"=="0" goto end
echo Invalid choice.
echo.
goto menu

:do_install
"%_PS%" -NoProfile -ExecutionPolicy Bypass -STA -File "%_PS1%" -Action Install
goto end

:do_portable
REM Folder picker starts at the current script folder; choosing this folder => in-place launchers,
REM choosing another folder => full portable package in <AppName>Portable under that path.
"%_PS%" -NoProfile -ExecutionPolicy Bypass -STA -File "%_PS1%" -Action ExportPortable
goto end

REM --- Exit codes: 0 done or cancelled, 1 NDT.ps1 missing, 2 no PowerShell 5.1,
REM     anything else comes from NDT.ps1 itself ---
:end
set "_RC=%ERRORLEVEL%"

:finish
REM --- Leave the installer folder before anything else happens ---
REM A console keeps the directory it stands in open, and here that is the folder
REM the installer has just copied from -- the one the user deletes next. The exit
REM code is put aside above because popd and endlocal both overwrite it.
popd >nul 2>&1

REM A failure has to stay readable: on a double-click the window closes with it
if not "%_RC%"=="0" (
	echo.
	pause
)
endlocal & exit /b %_RC%
