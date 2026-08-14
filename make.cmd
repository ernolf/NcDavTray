:: SPDX-FileCopyrightText: 2026 [ernolf] Raphael Gradenwitz <raphael.gradenwitz@googlemail.com>
:: SPDX-License-Identifier: GPL-3.0-or-later
:: Build front end for NcDavTray. Every target lives here, so CI runs the same
:: commands a contributor runs. make.cmd help lists them.

@echo off
setlocal enableextensions

REM --- Move working directory to the repository root (robust for double-click) ---
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
		goto :end
	)
)

set "_PS1=make.ps1"
if not exist "%_PS1%" (
	echo "%_PS1%" not found in: "%cd%"
	goto :end
)

REM --- An action on the command line skips the menu, so CI and scripts can use
REM     the same entry point as a double-click does. A second argument is the
REM     directory i18n-merge reads from ---
set "_ARGS="
if not "%~1"=="" (
	set "_ACTION=%~1"
	set _ARGS=%2
	goto run
)
set "_INTERACTIVE=1"

:menu
echo ==============================================
echo   NcDavTray - Build
echo ==============================================
echo   1) Check     - build, then run the static checks
echo   2) Build     - assemble build\NcDavTray
echo   3) Dist      - build, then pack the release archive
echo   4) Clean     - delete build\
echo   5) i18n      - write build\i18n-todo\ for the translators
echo   6) i18n add  - read translated files back into i18n\
echo   7) i18n sort - rewrite the language packs in canonical form
echo   0) Exit
echo ==============================================
set "choice="
set /p choice="Select: "

if "%choice%"=="1" goto do_check
if "%choice%"=="2" goto do_build
if "%choice%"=="3" goto do_dist
if "%choice%"=="4" goto do_clean
if "%choice%"=="5" goto do_i18n
if "%choice%"=="6" goto do_i18n_merge
if "%choice%"=="7" goto do_i18n_normalize
if "%choice%"=="0" goto end
echo Invalid choice.
echo.
goto menu

:do_check
set "_ACTION=check"
goto run

:do_build
set "_ACTION=build"
goto run

:do_dist
set "_ACTION=dist"
goto run

:do_clean
set "_ACTION=clean"
goto run

:do_i18n
set "_ACTION=i18n"
goto run

:do_i18n_merge
set "_ACTION=i18n-merge"
set "dir="
set /p dir="Directory holding the translated files: "
if not defined dir goto menu
set _ARGS="%dir%"
goto run

:do_i18n_normalize
set "_ACTION=i18n-normalize"
goto run

:run
"%_PS%" -NoProfile -ExecutionPolicy Bypass -File "%_PS1%" %_ACTION% %_ARGS%

:end
REM pause resets ERRORLEVEL, so the result is kept before the window is held open
set "_RC=%ERRORLEVEL%"
if defined _INTERACTIVE pause
exit /b %_RC%
