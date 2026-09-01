@echo off
setlocal enabledelayedexpansion
title SIH26145 - Threat Detection System Launcher
color 0B

set "PROJECT_ROOT=%~dp0"
set "DISTRO=Ubuntu"

:: Check if WSL is available
wsl --status >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] WSL is not detected or not enabled.
    echo     Please make sure WSL2 is installed and enabled.
    pause
    exit /b 1
)

:: Ensure WSL Redis is running
echo [*] Checking and starting Redis service in WSL (%DISTRO%)...
wsl -d %DISTRO% -u root service redis-server start >nul 2>&1
echo [OK] Redis is ready.

if "%~1"=="--all" goto :start_full
if "%~1"=="--sim" goto :start_sim
if "%~1"=="--stop" goto :stop_all

:menu
cls
echo ===============================================================================
echo                SIH26145 - UNIDIRECTIONAL THREAT DETECTOR
echo                   Multi-Layer AI Cyber Threat Detection
echo ===============================================================================
echo.
echo   [1] START FULL SYSTEM (WSL Sudo Ingestion + ML + Backend + Dashboard)
echo   [2] START SIMULATION PIPELINE (Simulated Attacks + ML + Backend + UI)
echo   [3] START INGESTION ONLY (WSL Sudo Interactive Menu)
echo   [4] RUN ATTACK TRAFFIC GENERATOR (simulate_pipeline.py)
echo   [5] STOP ALL RUNNING SERVICES
echo   [q] Exit
echo.
echo ===============================================================================
set /p choice="Enter choice [1-5/q]: "

if "%choice%"=="1" goto :start_full
if "%choice%"=="2" goto :start_sim
if "%choice%"=="3" goto :start_ingestion_only
if "%choice%"=="4" goto :run_traffic_gen
if "%choice%"=="5" goto :stop_all
if /i "%choice%"=="q" exit /b 0

echo Invalid choice. Please try again.
timeout /t 2 >nul
goto :menu


:start_full
cls
echo ===============================================================================
echo               Launching Full SIH26145 Pipeline Architecture
echo ===============================================================================
echo.

echo [1/4] Starting Ingestion Engine in WSL (with Sudo/Root privileges)...
start "SIH26145 - [1] Ingestion Layer (WSL Sudo)" cmd /k "title SIH26145 - [1] Ingestion Layer (WSL Sudo) && echo Starting Ingestion Engine in WSL root... && wsl -d %DISTRO% -u root --cd "%PROJECT_ROOT%ingestion" python3 main.py"
timeout /t 2 >nul

echo [2/4] Starting Person 2 ML Ensemble Live Engine...
start "SIH26145 - [2] ML Ensemble Engine" cmd /k "title SIH26145 - [2] ML Ensemble Engine && cd /d "%PROJECT_ROOT%ensemble_engine" && python scripts\live_ensemble.py"
timeout /t 2 >nul

echo [3/4] Starting Person 4 Express & WebSocket Backend (Port 4000)...
start "SIH26145 - [3] Backend API (Port 4000)" cmd /k "title SIH26145 - [3] Backend API (Port 4000) && cd /d "%PROJECT_ROOT%perosn4\backend" && npm start"
timeout /t 2 >nul

echo [4/4] Starting Frontend SOC React Dashboard (Port 5173)...
start "SIH26145 - [4] SOC React Dashboard (Port 5173)" cmd /k "title SIH26145 - [4] SOC React Dashboard (Port 5173) && cd /d "%PROJECT_ROOT%soc-dashboard" && npm run dev"

echo.
echo ===============================================================================
echo [SUCCESS] All 4 pipeline components have been launched in separate windows:
echo.
echo   * Ingestion Layer    : Running in WSL (%DISTRO%) as root (Eth/Loopback/PCAP)
echo   * ML Ensemble Engine : Subscribed to Redis 'flow.raw' -^> 'alert.new'
echo   * Backend API        : http://localhost:4000 (REST + WebSocket /ws/live)
echo   * SOC Dashboard      : http://localhost:5173 (React / Vite UI)
echo ===============================================================================
echo.
echo Press any key to return to main menu...
pause >nul
goto :menu


:start_sim
cls
echo ===============================================================================
echo               Launching Simulation Pipeline (With Continuous Traffic)
echo ===============================================================================
echo.

echo [1/4] Starting ML Ensemble Live Engine...
start "SIH26145 - [1] ML Ensemble Engine" cmd /k "title SIH26145 - [1] ML Ensemble Engine && cd /d "%PROJECT_ROOT%ensemble_engine" && python scripts\live_ensemble.py"
timeout /t 2 >nul

echo [2/4] Starting Person 4 Express & WebSocket Backend (Port 4000)...
start "SIH26145 - [2] Backend API (Port 4000)" cmd /k "title SIH26145 - [2] Backend API (Port 4000) && cd /d "%PROJECT_ROOT%perosn4\backend" && npm start"
timeout /t 2 >nul

echo [3/4] Starting Frontend SOC React Dashboard (Port 5173)...
start "SIH26145 - [3] SOC React Dashboard (Port 5173)" cmd /k "title SIH26145 - [3] SOC React Dashboard (Port 5173) && cd /d "%PROJECT_ROOT%soc-dashboard" && npm run dev"
timeout /t 2 >nul

echo [4/4] Starting Continuous Attack/Traffic Simulator (simulate_pipeline.py)...
start "SIH26145 - [4] Pipeline Traffic Simulator" cmd /k "title SIH26145 - [4] Pipeline Traffic Simulator && cd /d "%PROJECT_ROOT%" && python simulate_pipeline.py --continuous --interval 1.5"

echo.
echo ===============================================================================
echo [SUCCESS] Simulation pipeline running with continuous threat generation!
echo   * Dashboard: http://localhost:5173
echo   * Backend:   http://localhost:4000
echo ===============================================================================
echo.
pause
goto :menu


:start_ingestion_only
cls
echo Starting Ingestion Engine in WSL Sudo...
start "SIH26145 - Ingestion Layer (WSL Sudo)" cmd /k "title SIH26145 - Ingestion Layer (WSL Sudo) && wsl -d %DISTRO% -u root --cd "%PROJECT_ROOT%ingestion" python3 main.py"
goto :menu


:run_traffic_gen
cls
echo ===============================================================================
echo                   Threat Pipeline Attack Simulator
echo ===============================================================================
echo.
echo Scenarios available:
echo   [1] Continuous all attacks (C2, DDoS, PortScan, DNS Tunnel, DGA, Exfil)
echo   [2] Single C2 Beaconing flow
echo   [3] Single DDoS flood burst
echo   [4] Single Port Scan probe
echo   [5] Single DNS Tunneling payload
echo   [6] Single DGA Domain query
echo.
set /p scen_choice="Select scenario [1-6]: "
if "%scen_choice%"=="1" (
    start "SIH26145 - Traffic Generator (Continuous)" cmd /k "cd /d "%PROJECT_ROOT%" && python simulate_pipeline.py --continuous --interval 1.5"
) else if "%scen_choice%"=="2" (
    python "%PROJECT_ROOT%simulate_pipeline.py" --scenario c2
    pause
) else if "%scen_choice%"=="3" (
    python "%PROJECT_ROOT%simulate_pipeline.py" --scenario ddos
    pause
) else if "%scen_choice%"=="4" (
    python "%PROJECT_ROOT%simulate_pipeline.py" --scenario scan
    pause
) else if "%scen_choice%"=="5" (
    python "%PROJECT_ROOT%simulate_pipeline.py" --scenario dns
    pause
) else if "%scen_choice%"=="6" (
    python "%PROJECT_ROOT%simulate_pipeline.py" --scenario dga
    pause
)
goto :menu


:stop_all
cls
echo ===============================================================================
echo                       Stopping All Pipeline Services
echo ===============================================================================
echo.
echo [*] Terminating Node.js processes (Backend & Vite)...
taskkill /F /IM node.exe >nul 2>&1
echo [*] Terminating Python processes (ML engine & simulator)...
taskkill /F /FI "WINDOWTITLE eq SIH26145*" /IM python.exe >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq SIH26145*" /IM cmd.exe >nul 2>&1

echo [*] Stopping WSL Ingestion processes...
wsl -d %DISTRO% -u root pkill -f "python3 main.py" >nul 2>&1

echo [OK] All SIH26145 services stopped.
timeout /t 3 >nul
goto :menu
