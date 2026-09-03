@echo off
setlocal enabledelayedexpansion
title SIH26145 - Stop All Services
color 0C

set "DISTRO=Ubuntu"

echo ===============================================================================
echo                Stopping All SIH26145 Pipeline Services
echo ===============================================================================
echo.

echo [*] Stopping ALL Python processes (ML Engine, Simulators)...
taskkill /F /IM python.exe >nul 2>&1
taskkill /F /IM python3.exe >nul 2>&1
echo     Done.

echo [*] Stopping ALL Node.js processes (Backend API, Vite Dashboard)...
taskkill /F /IM node.exe >nul 2>&1
echo     Done.

echo [*] Closing SIH26145 CMD terminal windows...
for /f "tokens=2 delims=," %%a in ('wmic process where "name='cmd.exe' and commandline like '%%SIH26145%%'" get processid /format:csv 2^>nul ^| findstr /v "ProcessId"') do (
    taskkill /F /PID %%a >nul 2>&1
)
echo     Done.

echo [*] Stopping WSL Ingestion processes (if running)...
wsl -d %DISTRO% -u root pkill -f "python3 main.py" >nul 2>&1
wsl -d %DISTRO% -u root pkill -f "zeek" >nul 2>&1
echo     Done.

echo.
echo ===============================================================================
echo [OK] All SIH26145 services stopped.
echo      Python, Node.js, CMD windows and WSL processes terminated.
echo ===============================================================================
echo.
timeout /t 3
