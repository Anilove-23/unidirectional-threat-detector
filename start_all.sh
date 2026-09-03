#!/bin/bash
# SIH26145 - Threat Detection System Linux Launcher

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_ROOT/.venv_linux"

# Ensure Redis is running
if ! systemctl is-active --quiet redis && ! systemctl is-active --quiet redis-server; then
    echo -e "\033[31m[!] Redis is not running. Please start it using 'sudo systemctl start redis' or 'sudo service redis-server start'.\033[0m"
fi

function stop_all() {
    echo -e "\033[31m===============================================================================\033[0m"
    echo -e "\033[37m                       Stopping All Pipeline Services                          \033[0m"
    echo -e "\033[31m===============================================================================\033[0m"
    echo -e "\033[33m[*] Terminating Node.js processes...\033[0m"
    pkill -f "node.*perosn4/backend" 2>/dev/null
    pkill -f "vite.*soc-dashboard" 2>/dev/null
    echo -e "\033[33m[*] Terminating Python processes...\033[0m"
    pkill -f "python.*live_ensemble.py" 2>/dev/null
    pkill -f "python.*simulate_pipeline.py" 2>/dev/null
    echo -e "\033[33m[*] Stopping Ingestion processes...\033[0m"
    sudo pkill -f "python3 main.py" 2>/dev/null
    sudo pkill -f "zeek" 2>/dev/null
    echo -e "\033[32m[OK] All SIH26145 services stopped.\033[0m"
    sleep 2
}

function start_sim() {
    clear
    echo -e "\033[36m===============================================================================\033[0m"
    echo -e "\033[37m               Launching Simulation Pipeline (With Continuous Traffic)         \033[0m"
    echo -e "\033[36m===============================================================================\033[0m"
    echo ""

    echo -e "\033[36m[1/4] Starting ML Ensemble Live Engine...\033[0m"
    source "$VENV_DIR/bin/activate"
    cd "$PROJECT_ROOT/ensemble_engine" && python scripts/live_ensemble.py &
    sleep 2

    echo -e "\033[36m[2/4] Starting Person 4 Express & WebSocket Backend (Port 4000)...\033[0m"
    cd "$PROJECT_ROOT/perosn4/backend" && npm start &
    sleep 2

    echo -e "\033[36m[3/4] Starting Frontend SOC React Dashboard (Port 5173)...\033[0m"
    cd "$PROJECT_ROOT/soc-dashboard" && npm run dev &
    sleep 2

    echo -e "\033[36m[4/4] Starting Continuous Attack Simulator...\033[0m"
    source "$VENV_DIR/bin/activate"
    cd "$PROJECT_ROOT" && python simulate_pipeline.py --continuous --interval 1.5 &

    echo ""
    echo -e "\033[32m===============================================================================\033[0m"
    echo -e "\033[32m[SUCCESS] Simulation pipeline running with continuous threat generation!\033[0m"
    echo -e "\033[37m  * Dashboard: http://localhost:5173\033[0m"
    echo -e "\033[37m  * Backend:   http://localhost:4000\033[0m"
    echo -e "\033[37m  * Run option 5 from the menu to stop services when done.\033[0m"
    echo -e "\033[32m===============================================================================\033[0m"
    echo ""
    read -p "Press Enter to return to main menu"
}

function start_full() {
    clear
    echo -e "\033[36m===============================================================================\033[0m"
    echo -e "\033[37m               Launching Full SIH26145 Pipeline Architecture                   \033[0m"
    echo -e "\033[36m===============================================================================\033[0m"
    echo ""

    echo -e "\033[36m[1/4] Starting Ingestion Engine (with Sudo/Root privileges)...\033[0m"
    cd "$PROJECT_ROOT/ingestion" && sudo python3 main.py &
    sleep 2

    echo -e "\033[36m[2/4] Starting Person 2 ML Ensemble Live Engine...\033[0m"
    source "$VENV_DIR/bin/activate"
    cd "$PROJECT_ROOT/ensemble_engine" && python scripts/live_ensemble.py &
    sleep 2

    echo -e "\033[36m[3/4] Starting Person 4 Express & WebSocket Backend (Port 4000)...\033[0m"
    cd "$PROJECT_ROOT/perosn4/backend" && npm start &
    sleep 2

    echo -e "\033[36m[4/4] Starting Frontend SOC React Dashboard (Port 5173)...\033[0m"
    cd "$PROJECT_ROOT/soc-dashboard" && npm run dev &

    echo ""
    echo -e "\033[32m===============================================================================\033[0m"
    echo -e "\033[32m[SUCCESS] All 4 pipeline components have been launched in the background:\033[0m"
    echo -e "\033[37m  * Ingestion Layer    : Running as root\033[0m"
    echo -e "\033[37m  * ML Ensemble Engine : Subscribed to Redis flow.raw -> alert.new\033[0m"
    echo -e "\033[37m  * Backend API        : http://localhost:4000 (REST + WebSocket /ws/live)\033[0m"
    echo -e "\033[37m  * SOC Dashboard      : http://localhost:5173 (React / Vite UI)\033[0m"
    echo -e "\033[37m  * Run option 5 from the menu to stop services when done.\033[0m"
    echo -e "\033[32m===============================================================================\033[0m"
    echo ""
    read -p "Press Enter to return to main menu"
}

function show_menu() {
    clear
    echo -e "\033[36m===============================================================================\033[0m"
    echo -e "\033[37m                SIH26145 - UNIDIRECTIONAL THREAT DETECTOR                      \033[0m"
    echo -e "\033[36m                   Multi-Layer AI Cyber Threat Detection                       \033[0m"
    echo -e "\033[36m===============================================================================\033[0m"
    echo ""
    echo -e "\033[33m  [1] START FULL SYSTEM (Sudo Ingestion + ML + Backend + Dashboard)\033[0m"
    echo -e "\033[33m  [2] START SIMULATION PIPELINE (Simulated Attacks + ML + Backend + UI)\033[0m"
    echo -e "\033[33m  [3] START INGESTION ONLY (Sudo Interactive Menu)\033[0m"
    echo -e "\033[33m  [4] RUN ATTACK TRAFFIC GENERATOR (simulate_pipeline.py)\033[0m"
    echo -e "\033[31m  [5] STOP ALL RUNNING SERVICES\033[0m"
    echo -e "\033[90m  [q] Exit\033[0m"
    echo ""
    echo -e "\033[36m===============================================================================\033[0m"
    read -p "Enter choice [1-5/q]: " choice
    echo $choice
}

MODE=$1

if [ "$MODE" = "--all" ] || [ "$MODE" = "1" ]; then
    start_full
    exit 0
elif [ "$MODE" = "--sim" ] || [ "$MODE" = "2" ]; then
    start_sim
    exit 0
elif [ "$MODE" = "--stop" ] || [ "$MODE" = "5" ]; then
    stop_all
    exit 0
fi

while true; do
    c=$(show_menu)
    case $c in
        1)
            start_full
            ;;
        2)
            start_sim
            ;;
        3)
            cd "$PROJECT_ROOT/ingestion" && sudo python3 main.py
            ;;
        4)
            echo -e "\n\033[33mSelect scenario [1: all, 2: c2, 3: ddos, 4: scan, 5: dns, 6: dga]: \033[0m"
            read -r s
            source "$VENV_DIR/bin/activate"
            if [ "$s" = "1" ]; then
                cd "$PROJECT_ROOT" && python simulate_pipeline.py --continuous --interval 1.5
            elif [ "$s" = "2" ]; then
                python "$PROJECT_ROOT/simulate_pipeline.py" --scenario c2
            elif [ "$s" = "3" ]; then
                python "$PROJECT_ROOT/simulate_pipeline.py" --scenario ddos
            elif [ "$s" = "4" ]; then
                python "$PROJECT_ROOT/simulate_pipeline.py" --scenario scan
            elif [ "$s" = "5" ]; then
                python "$PROJECT_ROOT/simulate_pipeline.py" --scenario dns
            elif [ "$s" = "6" ]; then
                python "$PROJECT_ROOT/simulate_pipeline.py" --scenario dga
            fi
            read -p "Press Enter to continue"
            ;;
        5)
            stop_all
            ;;
        q|Q)
            exit 0
            ;;
        *)
            ;;
    esac
done
