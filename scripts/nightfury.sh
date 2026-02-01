#!/bin/bash
#
# NightFury SHEBA Framework - v2.6 (2026 Edition)
# Master Control Script for WSL2 Kali Linux
#

set -e

# Configuration
NIGHTFURY_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${NIGHTFURY_HOME}/config/operators.yaml"
PYTHON_CMD="python3"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

print_banner() {
    echo -e "${BLUE}${BOLD}"
    cat << "EOF"
    ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗██╗   ██╗██████╗ ██╗   ██╗
    ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██║   ██║██╔══██╗╚██╗ ██╔╝
    ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ██║   ██║██████╔╝ ╚████╔╝ 
    ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██║   ██║██╔══██╗  ╚██╔╝  
    ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ╚██████╔╝██║  ██║   ██║   
    ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
EOF
    echo -e "                        Professional Red Team Operations Framework${NC}"
    echo -e "                                    Version 2.6 (SHEBA-Protected)\n"
}

# --- Core Commands ---

cmd_setup() {
    export PYTHONPATH="${NIGHTFURY_HOME}:${PYTHONPATH}"
    $PYTHON_CMD "${NIGHTFURY_HOME}/core/interactive_setup.py"
}

cmd_status() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${RED}[!] Framework not configured. Run './nightfury.sh setup' first.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] NightFury Framework Status:${NC}"
    $PYTHON_CMD -c "import yaml; c = yaml.safe_load(open('$CONFIG_FILE')); print(f'    Operator: {c.get(\"operator_name\")}\n    C2 Host: {c.get(\"c2_host\")}:{c.get(\"c2_port\")}\n    WSL Sync: {c.get(\"wsl_integration\")}')"
}

cmd_c2() {
    local action=$1
    if [[ "$action" == "start" ]]; then
        echo -e "${BLUE}[*] Starting NightFury C2 Server...${NC}"
        export PYTHONPATH="${NIGHTFURY_HOME}:${PYTHONPATH}"
        nohup $PYTHON_CMD "${NIGHTFURY_HOME}/core/c2_server.py" > "${NIGHTFURY_HOME}/logs/c2_server.log" 2>&1 &
        echo -e "${GREEN}[+] C2 Server running in background (PID: $!).${NC}"
    elif [[ "$action" == "stop" ]]; then
        echo -e "${YELLOW}[*] Stopping C2 Server...${NC}"
        pkill -f "core/c2_server.py" || true
        echo -e "${GREEN}[+] C2 Server stopped.${NC}"
    else
        echo -e "${RED}[!] Usage: ./nightfury.sh c2 [start|stop]${NC}"
    fi
}

cmd_payload() {
    local type=$1
    local url=$2
    if [[ -z "$type" || -z "$url" ]]; then
        echo -e "${RED}[!] Usage: ./nightfury.sh payload [web_beacon|dom_hijack|api_exfil] <c2_url>${NC}"
        return 1
    fi
    export PYTHONPATH="${NIGHTFURY_HOME}:${PYTHONPATH}"
    $PYTHON_CMD -c "from modules.exploit.jit_payload_gen import JITPayloadGenerator; gen = JITPayloadGenerator(); print(gen.build_payload('$type', c2_url='$url'))"
}

cmd_help() {
    print_banner
    echo -e "${BOLD}COMMANDS:${NC}"
    echo -e "  setup              Run the interactive setup wizard"
    echo -e "  status             Show framework and operator status"
    echo -e "  c2 [start|stop]    Manage the C2 collection server"
    echo -e "  payload <type> <uL> Generate a JIT-compiled payload"
    echo -e "  recon <domain>     Execute advanced OSINT & dorking"
    echo -e "  panic              Emergency cleanup and secure exit"
    echo -e ""
    echo -e "${BOLD}EXAMPLES:${NC}"
    echo -e "  ./nightfury.sh setup"
    echo -e "  ./nightfury.sh payload web_beacon http://10.0.0.5:8080/collect"
}

# --- Main ---

case "$1" in
    setup)   cmd_setup ;;
    status)  cmd_status ;;
    c2)      cmd_c2 "$2" ;;
    payload) cmd_payload "$2" "$3" ;;
    help|--help|-h|"") cmd_help ;;
    *)       echo -e "${RED}[!] Unknown command: $1${NC}"; cmd_help; exit 1 ;;
esac
