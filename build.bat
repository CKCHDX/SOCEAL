@echo off
REM ============================================================
REM  SOCeal – Project VALE
REM  PyInstaller build script for Windows 10/11
REM  Run from repo root as: build.bat
REM ============================================================

echo.
echo  ===================================================
echo   SOCeal – Project VALE :: Build Script
echo  ===================================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.10+.
    pause
    exit /b 1
)

REM Check PyInstaller
pyinstaller --version >nul 2>&1
if errorlevel 1 (
    echo [INFO] PyInstaller not found. Installing...
    pip install pyinstaller
)

REM Install dependencies
echo [INFO] Installing dependencies...
pip install -r SOCEAL\requirements.txt

echo.
echo [INFO] Building SOCeal.exe ...
echo.

pyinstaller^
  --onefile^
  --windowed^
  --name SOCeal^
  --icon SOCEAL\src\ui\icon.ico 2>nul || set ICON_ERR=1^
  --add-data "SOCEAL\src\ui\SOCeal_dashboard.html;ui"^
  --add-data "SOCEAL\config\rules.json;config"^
  --add-data "SOCEAL\config\config.yaml;config"^
  --hidden-import win32evtlog^
  --hidden-import win32evtlogutil^
  --hidden-import win32con^
  --hidden-import pywintypes^
  --hidden-import psutil^
  --hidden-import watchdog.observers^
  --hidden-import watchdog.events^
  --hidden-import flask^
  --hidden-import yaml^
  SOCEAL\src\main.py

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed. Check output above.
    pause
    exit /b 1
)

echo.
echo  ===================================================
echo   Build complete!
echo   Output: dist\SOCeal.exe
echo.
echo   Run as Administrator for full functionality.
echo  ===================================================
echo.
pause
