@echo off
setlocal enabledelayedexpansion
title SOCeal - Project VALE
color 0B

echo.
echo  =====================================================
echo   SOCeal  ^|  Project VALE
echo   Vigilant . Automated . Local . Endpoint Protector
echo  =====================================================
echo.

:: --- Locate Python ---------------------------------------------------
set PYTHON=
for %%P in (python python3) do (
    if "!PYTHON!"=="" (
        where %%P >nul 2>&1
        if !errorlevel! == 0 set PYTHON=%%P
    )
)
if "%PYTHON%"=="" (
    echo  [ERROR] Python not found in PATH.
    echo  Install Python 3.9+ from https://python.org
    pause
    exit /b 1
)
echo  [OK] Python found: %PYTHON%

:: --- Locate project root (same dir as this .bat) --------------------
set ROOT=%~dp0
set MAIN=%ROOT%SOCEAL\src\main.py

if not exist "%MAIN%" (
    echo.
    echo  [ERROR] Cannot find: %MAIN%
    echo.
    echo  Expected layout after cloning:
    echo    SOCEAL-main\             ^<-- run RUNME.bat from HERE
    echo    SOCEAL-main\SOCEAL\src\main.py
    echo.
    echo  Make sure you are in the repo ROOT, not inside SOCEAL\
    echo.
    pause
    exit /b 1
)
echo  [OK] Entry point: %MAIN%

:: --- Install / verify dependencies ----------------------------------
echo.
echo  [..] Checking dependencies...

:: Run pip in a subprocess so its output NEVER touches cmd's parser.
:: Redirect both stdout and stderr to nul.
%PYTHON% -m pip install --quiet --upgrade pip >nul 2>nul
%PYTHON% -m pip install --quiet -r "%ROOT%requirements.txt" >nul 2>nul

:: Check errorlevel only AFTER pip has fully finished and output is gone.
if %errorlevel% neq 0 (
    echo  [WARN] Some packages may have failed. Continuing anyway...
    echo  Run manually: pip install -r requirements.txt
) else (
    echo  [OK] Dependencies ready.
)

:: --- Admin check -----------------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  [WARN] Not running as Administrator.
    echo  Active mode requires Admin for firewall and process kill.
    echo  Safe mode will still work fully.
    echo.
    timeout /t 3 /nobreak >nul
)

:: --- Mode selection --------------------------------------------------
echo.
echo  Select launch mode:
echo  [1] Safe Mode   - Monitor and detect only  (recommended)
echo  [2] Active Mode - Monitor + auto-block/kill (requires Admin)
echo  [3] Headless    - No browser, backend only
echo  [4] WebView     - Native app window (pywebview)
echo.
set /p CHOICE=  Enter choice [1-4] (default=1): 

if "%CHOICE%"=="2" (
    set ARGS=--active-mode
    echo  [>>] Starting in ACTIVE MODE...
) else if "%CHOICE%"=="3" (
    set ARGS=--safe-mode --no-ui
    echo  [>>] Starting HEADLESS...
) else if "%CHOICE%"=="4" (
    set ARGS=--safe-mode --webview
    echo  [>>] Starting with WebView window...
) else (
    set ARGS=--safe-mode
    echo  [>>] Starting in SAFE MODE...
)

echo.
echo  Dashboard: http://127.0.0.1:8081
echo  Press Ctrl+C in this window to stop SOCeal.
echo.

:: --- Launch ----------------------------------------------------------
cd /d "%ROOT%SOCEAL\src"
%PYTHON% "%MAIN%" %ARGS%

echo.
echo  SOCeal exited with code %errorlevel%.
pause
