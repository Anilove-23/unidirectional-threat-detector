# SIH26145 - Threat Detection System PowerShell Launcher
param(
    [string]$Mode = ""
)

$PROJECT_ROOT = $PSScriptRoot
$DISTRO = "Ubuntu"

# Check WSL
try {
    wsl --status | Out-Null
} catch {
    Write-Host "[!] WSL is not detected or not enabled." -ForegroundColor Red
    exit 1
}

# Start Redis in WSL
Write-Host "[*] Checking and starting Redis service in WSL ($DISTRO)..." -ForegroundColor Cyan
wsl -d $DISTRO -u root service redis-server start | Out-Null
Write-Host "[OK] Redis is ready.`n" -ForegroundColor Green

function Show-Menu {
    Clear-Host
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host "                SIH26145 - UNIDIRECTIONAL THREAT DETECTOR                      " -ForegroundColor White
    Write-Host "                   Multi-Layer AI Cyber Threat Detection                       " -ForegroundColor DarkCyan
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] START FULL SYSTEM (WSL Sudo Ingestion + ML + Backend + Dashboard)" -ForegroundColor Yellow
    Write-Host "  [2] START SIMULATION PIPELINE (Simulated Attacks + ML + Backend + UI)" -ForegroundColor Yellow
    Write-Host "  [3] START INGESTION ONLY (WSL Sudo Interactive Menu)" -ForegroundColor Yellow
    Write-Host "  [4] RUN ATTACK TRAFFIC GENERATOR (simulate_pipeline.py)" -ForegroundColor Yellow
    Write-Host "  [5] STOP ALL RUNNING SERVICES" -ForegroundColor Red
    Write-Host "  [q] Exit" -ForegroundColor Gray
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Cyan
    $choice = Read-Host "Enter choice [1-5/q]"
    return $choice
}

function Start-Full {
    Clear-Host
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host "               Launching Full SIH26145 Pipeline Architecture                   " -ForegroundColor White
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "[1/4] Starting Ingestion Engine in WSL (with Sudo/Root privileges)..." -ForegroundColor Cyan
    Start-Process cmd -ArgumentList "/k", "title SIH26145 - [1] Ingestion Layer (WSL Sudo) && wsl -d $DISTRO -u root --cd `"$PROJECT_ROOT\ingestion`" python3 main.py"
    Start-Sleep -Seconds 2

    Write-Host "[2/4] Starting Person 2 ML Ensemble Live Engine..." -ForegroundColor Cyan
    Start-Process cmd -ArgumentList "/k", "title SIH26145 - [2] ML Ensemble Engine && cd /d `"$PROJECT_ROOT\ensemble_engine`" && python scripts\live_ensemble.py"
    Start-Sleep -Seconds 2

    Write-Host "[3/4] Starting Person 4 Express & WebSocket Backend (Port 4000)..." -ForegroundColor Cyan
    Start-Process cmd -ArgumentList "/k", "title SIH26145 - [3] Backend API (Port 4000) && cd /d `"$PROJECT_ROOT\perosn4\backend`" && npm start"
    Start-Sleep -Seconds 2

    Write-Host "[4/4] Starting Frontend SOC React Dashboard (Port 5173)..." -ForegroundColor Cyan
    Start-Process cmd -ArgumentList "/k", "title SIH26145 - [4] SOC React Dashboard (Port 5173) && cd /d `"$PROJECT_ROOT\soc-dashboard`" && npm run dev"

    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Green
    Write-Host "[SUCCESS] All 4 pipeline components have been launched in separate windows:" -ForegroundColor Green
    Write-Host "  * Ingestion Layer    : Running in WSL ($DISTRO) as root" -ForegroundColor White
    Write-Host "  * ML Ensemble Engine : Subscribed to Redis flow.raw -> alert.new" -ForegroundColor White
    Write-Host "  * Backend API        : http://localhost:4000 (REST + WebSocket /ws/live)" -ForegroundColor White
    Write-Host "  * SOC Dashboard      : http://localhost:5173 (React / Vite UI)" -ForegroundColor White
    Write-Host "===============================================================================" -ForegroundColor Green
    Write-Host ""
    Read-Host "Press Enter to return to main menu"
}

function Start-Sim {
    Clear-Host
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host "               Launching Simulation Pipeline (With Continuous Traffic)         " -ForegroundColor White
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "[1/4] Starting ML Ensemble Live Engine..." -ForegroundColor Cyan
    Start-Process cmd -ArgumentList "/k", "title SIH26145 - [1] ML Ensemble Engine && cd /d `"$PROJECT_ROOT\ensemble_engine`" && python scripts\live_ensemble.py"
    Start-Sleep -Seconds 2

    Write-Host "[2/4] Starting Person 4 Express & WebSocket Backend (Port 4000)..." -ForegroundColor Cyan
    Start-Process cmd -ArgumentList "/k", "title SIH26145 - [2] Backend API (Port 4000) && cd /d `"$PROJECT_ROOT\perosn4\backend`" && npm start"
    Start-Sleep -Seconds 2

    Write-Host "[3/4] Starting Frontend SOC React Dashboard (Port 5173)..." -ForegroundColor Cyan
    Start-Process cmd -ArgumentList "/k", "title SIH26145 - [3] SOC React Dashboard (Port 5173) && cd /d `"$PROJECT_ROOT\soc-dashboard`" && npm run dev"
    Start-Sleep -Seconds 2

    Write-Host "[4/4] Starting Continuous Attack Simulator..." -ForegroundColor Cyan
    Start-Process cmd -ArgumentList "/k", "title SIH26145 - [4] Pipeline Traffic Simulator && cd /d `"$PROJECT_ROOT`" && python simulate_pipeline.py --continuous --interval 1.5"

    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Green
    Write-Host "[SUCCESS] Simulation pipeline running with continuous threat generation!" -ForegroundColor Green
    Write-Host "  * Dashboard: http://localhost:5173" -ForegroundColor White
    Write-Host "  * Backend:   http://localhost:4000" -ForegroundColor White
    Write-Host "===============================================================================" -ForegroundColor Green
    Write-Host ""
    Read-Host "Press Enter to return to main menu"
}

function Stop-All {
    Clear-Host
    Write-Host "===============================================================================" -ForegroundColor Red
    Write-Host "                       Stopping All Pipeline Services                          " -ForegroundColor White
    Write-Host "===============================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "[*] Terminating Node.js processes..." -ForegroundColor Yellow
    taskkill /F /IM node.exe 2>$null | Out-Null
    Write-Host "[*] Terminating Python processes..." -ForegroundColor Yellow
    taskkill /F /FI "WINDOWTITLE eq SIH26145*" /IM python.exe 2>$null | Out-Null
    taskkill /F /FI "WINDOWTITLE eq SIH26145*" /IM cmd.exe 2>$null | Out-Null
    Write-Host "[*] Stopping WSL Ingestion processes..." -ForegroundColor Yellow
    wsl -d $DISTRO -u root pkill -f "python3 main.py" 2>$null | Out-Null
    wsl -d $DISTRO -u root pkill -f "zeek" 2>$null | Out-Null
    Write-Host "[OK] All SIH26145 services stopped." -ForegroundColor Green
    Start-Sleep -Seconds 2
}

if ($Mode -eq "--all" -or $Mode -eq "1") {
    Start-Full
    exit 0
} elseif ($Mode -eq "--sim" -or $Mode -eq "2") {
    Start-Sim
    exit 0
} elseif ($Mode -eq "--stop" -or $Mode -eq "5") {
    Stop-All
    exit 0
}

while ($true) {
    $c = Show-Menu
    switch ($c) {
        "1" { Start-Full }
        "2" { Start-Sim }
        "3" {
            Start-Process cmd -ArgumentList "/k", "title SIH26145 - Ingestion Layer (WSL Sudo) && wsl -d $DISTRO -u root --cd `"$PROJECT_ROOT\ingestion`" python3 main.py"
        }
        "4" {
            Write-Host "`nSelect scenario [1: all, 2: c2, 3: ddos, 4: scan, 5: dns, 6: dga]: " -ForegroundColor Yellow
            $s = Read-Host
            if ($s -eq "1") { Start-Process cmd -ArgumentList "/k", "cd /d `"$PROJECT_ROOT`" && python simulate_pipeline.py --continuous --interval 1.5" }
            elseif ($s -eq "2") { python "$PROJECT_ROOT\simulate_pipeline.py" --scenario c2 }
            elseif ($s -eq "3") { python "$PROJECT_ROOT\simulate_pipeline.py" --scenario ddos }
            elseif ($s -eq "4") { python "$PROJECT_ROOT\simulate_pipeline.py" --scenario scan }
            elseif ($s -eq "5") { python "$PROJECT_ROOT\simulate_pipeline.py" --scenario dns }
            elseif ($s -eq "6") { python "$PROJECT_ROOT\simulate_pipeline.py" --scenario dga }
            Read-Host "Press Enter to continue"
        }
        "5" { Stop-All }
        "q" { exit 0 }
    }
}
