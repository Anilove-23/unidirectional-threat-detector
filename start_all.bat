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
echo   [5] RUN CUSTOM ATTACK + NORMAL TRAFFIC (Choose Attack Type)
echo   [6] STOP ALL RUNNING SERVICES
echo   [q] Exit
echo.
echo ===============================================================================
set /p choice="Enter choice [1-6/q]: "

if "%choice%"=="1" goto :start_full
if "%choice%"=="2" goto :start_sim
if "%choice%"=="3" goto :start_ingestion_only
if "%choice%"=="4" goto :run_traffic_gen
if "%choice%"=="5" goto :run_custom_attack
if "%choice%"=="6" goto :stop_all
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


:run_custom_attack
cls
echo ===============================================================================
echo          Custom Attack + Normal Traffic Simulation
echo          Starts ML Engine, Backend, Dashboard + Two Traffic Terminals
echo ===============================================================================
echo.
echo Choose an attack type to simulate alongside normal benign traffic:
echo.
echo   [1] BOTNET C2 BEACONING     - Periodic small packets to external C2 server
echo   [2] VOLUMETRIC DDoS         - High-rate SYN flood bursts
echo   [3] PORT SCAN               - SYN probes across diverse destination ports
echo   [4] DNS TUNNELING           - Long DNS queries with high-entropy subdomains
echo   [5] DGA (Domain Generation) - Random high-entropy domain lookups
echo   [6] DATA EXFILTRATION       - Large outbound data transfers over TLS
echo   [7] ALL ATTACK TYPES        - Mix of all attack scenarios together
echo.
echo ===============================================================================
set /p atk_choice="Select attack type [1-7]: "

set "ATTACK_SCENARIO="
set "ATTACK_LABEL="

if "%atk_choice%"=="1" (
    set "ATTACK_SCENARIO=c2"
    set "ATTACK_LABEL=C2 Beaconing"
)
if "%atk_choice%"=="2" (
    set "ATTACK_SCENARIO=ddos"
    set "ATTACK_LABEL=Volumetric DDoS"
)
if "%atk_choice%"=="3" (
    set "ATTACK_SCENARIO=scan"
    set "ATTACK_LABEL=Port Scan"
)
if "%atk_choice%"=="4" (
    set "ATTACK_SCENARIO=dns"
    set "ATTACK_LABEL=DNS Tunneling"
)
if "%atk_choice%"=="5" (
    set "ATTACK_SCENARIO=dga"
    set "ATTACK_LABEL=DGA"
)
if "%atk_choice%"=="6" (
    set "ATTACK_SCENARIO=exfil"
    set "ATTACK_LABEL=Data Exfiltration"
)
if "%atk_choice%"=="7" (
    set "ATTACK_SCENARIO=all"
    set "ATTACK_LABEL=All Attacks"
)

if "%ATTACK_SCENARIO%"=="" (
    echo Invalid choice. Returning to menu...
    timeout /t 2 >nul
    goto :menu
)

echo.
echo [OK] Attack type selected: %ATTACK_LABEL%
echo.

set /p atk_interval="Enter attack flow interval in seconds (default 1.5, press Enter to accept): "
if "%atk_interval%"=="" set "atk_interval=1.5"

set /p ben_interval="Enter benign flow interval in seconds (default 2.0, press Enter to accept): "
if "%ben_interval%"=="" set "ben_interval=2.0"

echo.
echo [1/5] Starting ML Ensemble Live Engine...
start "SIH26145 - [1] ML Ensemble Engine" cmd /k "title SIH26145 - [1] ML Ensemble Engine && cd /d "%PROJECT_ROOT%ensemble_engine" && python scripts\live_ensemble.py"
timeout /t 2 >nul

echo [2/5] Starting Person 4 Express ^& WebSocket Backend (Port 4000)...
start "SIH26145 - [2] Backend API (Port 4000)" cmd /k "title SIH26145 - [2] Backend API (Port 4000) && cd /d "%PROJECT_ROOT%perosn4\backend" && npm start"
timeout /t 2 >nul

echo [3/5] Starting Frontend SOC React Dashboard (Port 5173)...
start "SIH26145 - [3] SOC React Dashboard (Port 5173)" cmd /k "title SIH26145 - [3] SOC React Dashboard (Port 5173) && cd /d "%PROJECT_ROOT%soc-dashboard" && npm run dev"
timeout /t 2 >nul

echo [4/5] Starting ATTACK traffic stream: %ATTACK_LABEL% (interval: %atk_interval%s)...
start "SIH26145 - [4] ATTACK: %ATTACK_LABEL%" cmd /k "title SIH26145 - [4] ATTACK: %ATTACK_LABEL% && cd /d "%PROJECT_ROOT%" && python simulate_pipeline.py --scenario %ATTACK_SCENARIO% --continuous --interval %atk_interval%"
timeout /t 1 >nul

echo [5/5] Starting NORMAL/BENIGN traffic stream (interval: %ben_interval%s)...
start "SIH26145 - [5] NORMAL Traffic (Benign)" cmd /k "title SIH26145 - [5] NORMAL Traffic (Benign) && cd /d "%PROJECT_ROOT%" && python simulate_pipeline.py --scenario benign --continuous --interval %ben_interval%"

echo.
echo ===============================================================================
echo [SUCCESS] Custom simulation launched with 5 components:
echo.
echo   * ML Ensemble Engine  : Subscribed to Redis flow.raw -^> alert.new
echo   * Backend API         : http://localhost:4000  (REST + WebSocket /ws)
echo   * SOC Dashboard       : http://localhost:5173  (React / Vite UI)
echo   * ATTACK Terminal     : Sending [%ATTACK_LABEL%] flows every %atk_interval%s
echo   * BENIGN Terminal     : Sending normal traffic every %ben_interval%s
echo ===============================================================================
echo.
echo Both attack and benign flows are being processed by the ML engine in real-time.
echo Watch the SOC Dashboard at http://localhost:5173 to see detections!
echo.
pause
goto :menu


:stop_all
cls
echo ===============================================================================
echo                       Stopping All Pipeline Services
echo ===============================================================================
echo.
echo [*] Stopping ALL Python processes (ML Engine, Simulators)...
taskkill /F /IM python.exe >nul 2>&1
taskkill /F /IM python3.exe >nul 2>&1
echo     Done.
echo [*] Stopping ALL Node.js processes (Backend, Dashboard)...
taskkill /F /IM node.exe >nul 2>&1
echo     Done.
echo [*] Closing SIH26145 CMD terminal windows...
for /f "tokens=2 delims=," %%a in ('wmic process where "name='cmd.exe' and commandline like '%%SIH26145%%'" get processid /format:csv 2^>nul ^| findstr /v "ProcessId"') do (
    taskkill /F /PID %%a >nul 2>&1
)
echo     Done.
echo [*] Stopping WSL Ingestion processes...
wsl -d %DISTRO% -u root pkill -f "python3 main.py" >nul 2>&1
wsl -d %DISTRO% -u root pkill -f "zeek" >nul 2>&1
echo     Done.
echo.
echo [OK] All SIH26145 services stopped.
timeout /t 3 >nul
goto :menu
