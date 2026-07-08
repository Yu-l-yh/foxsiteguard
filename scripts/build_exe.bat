@echo off
chcp 65001 >nul 2>&1
title FoxSiteGuard - Build EXE

echo ========================================
echo   Building FoxSiteGuard Launcher EXE
echo ========================================
echo.

cd /d "%~dp0.."

python -c "import PyInstaller" 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [*] Installing PyInstaller...
    pip install pyinstaller
)

echo [*] Building executable...
pyinstaller --onefile ^
    --name "FoxSiteGuard" ^
    --add-data "foxsiteguard;foxsiteguard" ^
    --hidden-import uvicorn.logging ^
    --hidden-import uvicorn.loops.auto ^
    --hidden-import uvicorn.protocols.http.auto ^
    foxsiteguard\launcher.py

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [OK] Build complete!
    echo EXE: dist\FoxSiteGuard.exe
) else (
    echo [ERROR] Build failed.
)

pause
