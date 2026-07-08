@echo off
chcp 65001 >nul 2>&1
title FoxSiteGuard - Backend Server

cd /d "%~dp0.."

echo ========================================
echo   FoxSiteGuard Server v2.0.0
echo   Press Ctrl+C to stop
echo ========================================
echo.

.venv\Scripts\python -m foxsiteguard.main

pause
