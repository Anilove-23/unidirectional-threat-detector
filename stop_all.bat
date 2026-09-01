@echo off
title SIH26145 - Stop All Services
color 0C

set "DISTRO=Ubuntu"

echo ===============================================================================
echo                Stopping All SIH26145 Pipeline Services
echo ===============================================================================
echo.

echo [*] Stopping Node.js processes (Backend API & React Dashboard)...
taskkill /F /IM node.exe >nul 2>&1

echo [*] Stopping Python processes (ML Engine & Attack Simulator)...
taskkill /F /FI "WINDOWTITLE eq SIH26145*" /IM python.exe >nul 2>&1

echo [*] Stopping WSL Ingestion processes...
wsl -d %DISTRO% -u root pkill -f "python3 main.py" >nul 2>&1
wsl -d %DISTRO% -u root pkill -f "zeek" >nul 2>&1

echo.
echo [OK] All services and windows stopped successfully.
echo.
timeout /t 3
