@echo off
echo ============================================
echo  SOCeal - Project VALE Build Script
echo ============================================
echo.

:: Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.9+.
    pause
    exit /b 1
)

:: Install dependencies
echo Installing dependencies...
pip install -r requirements.txt
pip install pyinstaller>=6.0

echo.
echo Building SOCeal.exe...
pyinstaller soceal.spec --clean --noconfirm

if errorlevel 1 (
    echo.
    echo BUILD FAILED. Check errors above.
    pause
    exit /b 1
)

:: Copy config files next to exe for user editing
echo.
echo Copying config files to dist...
if not exist "dist\config" mkdir "dist\config"
copy "config\config.yaml" "dist\config\config.yaml"
copy "config\rules.json" "dist\config\rules.json"

:: Create data directories
if not exist "dist\data\logs" mkdir "dist\data\logs"
if not exist "dist\data\quarantine" mkdir "dist\data\quarantine"

echo.
echo ============================================
echo  Build complete: dist\SOCeal.exe
echo  Config files:   dist\config\
echo  Data directory:  dist\data\
echo ============================================
echo.
echo Run with: dist\SOCeal.exe
echo   Options: --safe-mode, --active-mode, --webview, --no-ui
pause
