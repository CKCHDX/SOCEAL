@echo off
title SOCeal - Project VALE
cd /d "%~dp0"

echo.
echo  SOCeal - Project VALE
echo  ======================
echo.

python --version
if errorlevel 1 (
    echo  ERROR: Python not found.
    pause
    exit /b 1
)

if not exist "data\logs" mkdir "data\logs"
if not exist "data\quarantine" mkdir "data\quarantine"

echo.
echo  Starting SOCeal...
echo  Dashboard: http://127.0.0.1:8081
echo  Press Ctrl+C to stop.
echo.

python src\main.py

echo.
echo  SOCeal stopped.
pause
