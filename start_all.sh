#!/bin/bash
# SIH26145 - Threat Detection System Linux Launcher

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_ROOT/.venv_linux"

# Ensure Redis is running
if ! systemctl is-active --quiet redis && ! systemctl is-active --quiet redis-server; then
    echo -e "\033[31m[!] Redis is not running. Please start it using 'sudo systemctl start redis' or 'sudo service redis-server start'.\033[0m"
fi

function launch_terminal() {
    local title="$1"
    local cmd="$2"
    if command -v gnome-terminal &> /dev/null; then
        gnome-terminal --title="$title" -- bash -c "$cmd; exec bash" &
    elif command -v konsole &> /dev/null; then
        konsole --title "$title" -e bash -c "$cmd; exec bash" &
    elif command -v xfce4-terminal &> /dev/null; then
        xfce4-terminal --title="$title" -e "bash -c \"$cmd; exec bash\"" &
    elif command -v xterm &> /dev/null; then
        xterm -T "$title" -e bash -c "$cmd; exec bash" &
    else
        echo -e "\033[33m[!] No supported terminal emulator found (gnome-terminal, konsole, xfce4-terminal, xterm). Running in background...\033[0m"
        bash -c "$cmd" &
    fi
}

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
    launch_terminal "SIH26145 - [1] ML Ensemble Engine" "source \"$VENV_DIR/bin/activate\" && cd \"$PROJECT_ROOT/ensemble_engine\" && python scripts/live_ensemble.py"
    sleep 2

    echo -e "\033[36m[2/4] Starting Person 4 Express & WebSocket Backend (Port 4000)...\033[0m"
    launch_terminal "SIH26145 - [2] Backend API (Port 4000)" "cd \"$PROJECT_ROOT/perosn4/backend\" && npm start"
    sleep 2

    echo -e "\033[36m[3/4] Starting Frontend SOC React Dashboard (Port 5173)...\033[0m"
    launch_terminal "SIH26145 - [3] SOC React Dashboard (Port 5173)" "cd \"$PROJECT_ROOT/soc-dashboard\" && npm run dev"
    sleep 2

    echo -e "\033[36m[4/4] Starting Continuous Attack Simulator...\033[0m"
    launch_terminal "SIH26145 - [4] Pipeline Traffic Simulator" "source \"$VENV_DIR/bin/activate\" && cd \"$PROJECT_ROOT\" && python simulate_pipeline.py --continuous --interval 1.5"

    echo ""
    echo -e "\033[32m===============================================================================\033[0m"
    echo -e "\033[32m[SUCCESS] Simulation pipeline running with continuous threat generation!\033[0m"
    echo -e "\033[37m  * Dashboard: http://localhost:5173\033[0m"
    echo -e "\033[37m  * Backend:   http://localhost:4000\033[0m"
    echo -e "\033[37m  * Run option 6 from the menu to stop services when done.\033[0m"
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
    launch_terminal "SIH26145 - [1] Ingestion Layer (Sudo)" "cd \"$PROJECT_ROOT/ingestion\" && sudo python3 main.py"
    sleep 2

    echo -e "\033[36m[2/4] Starting Person 2 ML Ensemble Live Engine...\033[0m"
    launch_terminal "SIH26145 - [2] ML Ensemble Engine" "source \"$VENV_DIR/bin/activate\" && cd \"$PROJECT_ROOT/ensemble_engine\" && python scripts/live_ensemble.py"
    sleep 2

    echo -e "\033[36m[3/4] Starting Person 4 Express & WebSocket Backend (Port 4000)...\033[0m"
    launch_terminal "SIH26145 - [3] Backend API (Port 4000)" "cd \"$PROJECT_ROOT/perosn4/backend\" && npm start"
    sleep 2

    echo -e "\033[36m[4/4] Starting Frontend SOC React Dashboard (Port 5173)...\033[0m"
    launch_terminal "SIH26145 - [4] SOC React Dashboard (Port 5173)" "cd \"$PROJECT_ROOT/soc-dashboard\" && npm run dev"

    echo ""
    echo -e "\033[32m===============================================================================\033[0m"
    echo -e "\033[32m[SUCCESS] All 4 pipeline components have been launched in separate terminal windows:\033[0m"
    echo -e "\033[37m  * Ingestion Layer    : Running as root\033[0m"
    echo -e "\033[37m  * ML Ensemble Engine : Subscribed to Redis flow.raw -> alert.new\033[0m"
    echo -e "\033[37m  * Backend API        : http://localhost:4000 (REST + WebSocket /ws/live)\033[0m"
    echo -e "\033[37m  * SOC Dashboard      : http://localhost:5173 (React / Vite UI)\033[0m"
    echo -e "\033[37m  * Run option 6 from the menu to stop services when done.\033[0m"
    echo -e "\033[32m===============================================================================\033[0m"
    echo ""
    read -p "Press Enter to return to main menu"
}

function run_custom_attack() {
    clear
    echo -e "\033[36m===============================================================================\033[0m"
    echo -e "\033[37m          Custom Attack + Normal Traffic Simulation                            \033[0m"
    echo -e "\033[37m          Starts ML Engine, Backend, Dashboard + Two Traffic Terminals         \033[0m"
    echo -e "\033[36m===============================================================================\033[0m"
    echo ""
    echo -e "\033[33mChoose an attack type to simulate alongside normal benign traffic:\033[0m"
    echo ""
    echo -e "  [1] BOTNET C2 BEACONING     - Periodic small packets to external C2 server"
    echo -e "  [2] VOLUMETRIC DDoS         - High-rate SYN flood bursts"
    echo -e "  [3] PORT SCAN               - SYN probes across diverse destination ports"
    echo -e "  [4] DNS TUNNELING           - Long DNS queries with high-entropy subdomains"
    echo -e "  [5] DGA (Domain Generation) - Random high-entropy domain lookups"
    echo -e "  [6] DATA EXFILTRATION       - Large outbound data transfers over TLS"
    echo -e "  [7] ALL ATTACK TYPES        - Mix of all attack scenarios together"
    echo ""
    echo -e "\033[36m===============================================================================\033[0m"
    read -p "Select attack type [1-7]: " atk_choice

    ATTACK_SCENARIO=""
    ATTACK_LABEL=""

    case $atk_choice in
        1) ATTACK_SCENARIO="c2"; ATTACK_LABEL="C2 Beaconing" ;;
        2) ATTACK_SCENARIO="ddos"; ATTACK_LABEL="Volumetric DDoS" ;;
        3) ATTACK_SCENARIO="scan"; ATTACK_LABEL="Port Scan" ;;
        4) ATTACK_SCENARIO="dns"; ATTACK_LABEL="DNS Tunneling" ;;
        5) ATTACK_SCENARIO="dga"; ATTACK_LABEL="DGA" ;;
        6) ATTACK_SCENARIO="exfil"; ATTACK_LABEL="Data Exfiltration" ;;
        7) ATTACK_SCENARIO="all"; ATTACK_LABEL="All Attacks" ;;
        *) echo "Invalid choice. Returning to menu..."; sleep 2; return ;;
    esac

    echo ""
    echo -e "\033[32m[OK] Attack type selected: $ATTACK_LABEL\033[0m"
    echo ""

    read -p "Enter attack flow interval in seconds (default 1.5, press Enter to accept): " atk_interval
    if [ -z "$atk_interval" ]; then atk_interval="1.5"; fi

    read -p "Enter benign flow interval in seconds (default 2.0, press Enter to accept): " ben_interval
    if [ -z "$ben_interval" ]; then ben_interval="2.0"; fi

    echo ""
    echo -e "\033[36m[1/5] Starting ML Ensemble Live Engine...\033[0m"
    launch_terminal "SIH26145 - [1] ML Ensemble Engine" "source \"$VENV_DIR/bin/activate\" && cd \"$PROJECT_ROOT/ensemble_engine\" && python scripts/live_ensemble.py"
    sleep 2

    echo -e "\033[36m[2/5] Starting Person 4 Express & WebSocket Backend (Port 4000)...\033[0m"
    launch_terminal "SIH26145 - [2] Backend API (Port 4000)" "cd \"$PROJECT_ROOT/perosn4/backend\" && npm start"
    sleep 2

    echo -e "\033[36m[3/5] Starting Frontend SOC React Dashboard (Port 5173)...\033[0m"
    launch_terminal "SIH26145 - [3] SOC React Dashboard (Port 5173)" "cd \"$PROJECT_ROOT/soc-dashboard\" && npm run dev"
    sleep 2

    echo -e "\033[36m[4/5] Starting ATTACK traffic stream: $ATTACK_LABEL (interval: ${atk_interval}s)...\033[0m"
    launch_terminal "SIH26145 - [4] ATTACK: $ATTACK_LABEL" "source \"$VENV_DIR/bin/activate\" && cd \"$PROJECT_ROOT\" && python simulate_pipeline.py --scenario \"$ATTACK_SCENARIO\" --continuous --interval \"$atk_interval\""
    sleep 1

    echo -e "\033[36m[5/5] Starting NORMAL/BENIGN traffic stream (interval: ${ben_interval}s)...\033[0m"
    launch_terminal "SIH26145 - [5] NORMAL Traffic (Benign)" "source \"$VENV_DIR/bin/activate\" && cd \"$PROJECT_ROOT\" && python simulate_pipeline.py --scenario benign --continuous --interval \"$ben_interval\""

    echo ""
    echo -e "\033[32m===============================================================================\033[0m"
    echo -e "\033[32m[SUCCESS] Custom simulation launched with 5 components in separate terminal windows:\033[0m"
    echo ""
    echo -e "\033[37m  * ML Ensemble Engine  : Subscribed to Redis flow.raw -> alert.new\033[0m"
    echo -e "\033[37m  * Backend API         : http://localhost:4000  (REST + WebSocket /ws)\033[0m"
    echo -e "\033[37m  * SOC Dashboard       : http://localhost:5173  (React / Vite UI)\033[0m"
    echo -e "\033[37m  * ATTACK stream       : Sending [$ATTACK_LABEL] flows every ${atk_interval}s\033[0m"
    echo -e "\033[37m  * BENIGN stream       : Sending normal traffic every ${ben_interval}s\033[0m"
    echo -e "\033[37m  * Run option 6 from the menu to stop services when done.\033[0m"
    echo -e "\033[32m===============================================================================\033[0m"
    echo ""
    echo -e "\033[37mBoth attack and benign flows are being processed by the ML engine in real-time.\033[0m"
    echo -e "\033[37mWatch the SOC Dashboard at http://localhost:5173 to see detections!\033[0m"
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
    echo -e "\033[33m  [5] RUN CUSTOM ATTACK + NORMAL TRAFFIC (Choose Attack Type)\033[0m"
    echo -e "\033[31m  [6] STOP ALL RUNNING SERVICES\033[0m"
    echo -e "\033[90m  [q] Exit\033[0m"
    echo ""
    echo -e "\033[36m===============================================================================\033[0m"
}

MODE=$1

if [ "$MODE" = "--all" ] || [ "$MODE" = "1" ]; then
    start_full
    exit 0
elif [ "$MODE" = "--sim" ] || [ "$MODE" = "2" ]; then
    start_sim
    exit 0
elif [ "$MODE" = "--stop" ] || [ "$MODE" = "6" ]; then
    stop_all
    exit 0
fi

while true; do
    show_menu
    read -p "Enter choice [1-6/q]: " c
    case $c in
        1)
            start_full
            ;;
        2)
            start_sim
            ;;
        3)
            echo -e "\033[36mStarting Ingestion Engine in Sudo...\033[0m"
            launch_terminal "SIH26145 - Ingestion Layer (Sudo)" "cd \"$PROJECT_ROOT/ingestion\" && sudo python3 main.py"
            ;;
        4)
            echo -e "\n\033[33mSelect scenario [1: all, 2: c2, 3: ddos, 4: scan, 5: dns, 6: dga]: \033[0m"
            read -r s
            source "$VENV_DIR/bin/activate"
            if [ "$s" = "1" ]; then
                launch_terminal "SIH26145 - Traffic Generator (Continuous)" "source \"$VENV_DIR/bin/activate\" && cd \"$PROJECT_ROOT\" && python simulate_pipeline.py --continuous --interval 1.5"
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
            run_custom_attack
            ;;
        6)
            stop_all
            ;;
        q|Q)
            exit 0
            ;;
        *)
            ;;
    esac
done
