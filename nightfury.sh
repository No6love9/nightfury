#!/bin/bash

# NightFury Master Control Script
# Optimized for WSL2 Kali Linux

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

PROJECT_ROOT=$(pwd)
ENV_FILE="$PROJECT_ROOT/.env"
TEMPLATE_FILE="$PROJECT_ROOT/.env.template"

print_banner() {
    echo -e "${BLUE}"
    echo "    ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗██╗   ██╗██████╗ ██╗   ██╗"
    echo "    ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██║   ██║██╔══██╗╚██╗ ██╔╝"
    echo "    ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ██║   ██║██████╔╝ ╚████╔╝ "
    echo "    ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██║   ██║██╔══██╗  ╚██╔╝  "
    echo "    ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ╚██████╔╝██║  ██║   ██║   "
    echo "    ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   "
    echo -e "                                MASTER CONTROL${NC}"
}

check_env() {
    if [ ! -f "$ENV_FILE" ]; then
        echo -e "${YELLOW}[!] Environment file (.env) not found.${NC}"
        if [ -f "$TEMPLATE_FILE" ]; then
            echo -e "[*] Creating .env from template..."
            cp "$TEMPLATE_FILE" "$ENV_FILE"
            echo -e "${GREEN}[+] .env created. Please edit it with your credentials.${NC}"
            
            # Prompt for immediate setup
            read -p "Would you like to configure it now? (y/n): " setup_now
            if [[ $setup_now == "y" || $setup_now == "Y" ]]; then
                nano "$ENV_FILE"
            fi
        else
            echo -e "${RED}[-].env.template not found. Cannot auto-create .env.${NC}"
        fi
    fi
}

install_deps() {
    echo -e "${BLUE}[*] Checking dependencies...${NC}"
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo apt update && sudo apt install -y python3-pip python3-venv git curl
    fi
    pip3 install -r requirements.txt
    echo -e "${GREEN}[+] Dependencies installed.${NC}"
}

run_framework() {
    check_env
    python3 nf.py "$@"
}

case "$1" in
    setup)
        print_banner
        install_deps
        check_env
        python3 core/interactive_setup.py
        ;;
    run)
        shift
        run_framework "$@"
        ;;
    status)
        print_banner
        echo -e "${BLUE}--- System Status ---${NC}"
        python3 core/detection_engine.py
        ;;
    clean)
        echo -e "${YELLOW}[!] Initiating forensic cleanup...${NC}"
        python3 utils/forensic_cleaner.py -p
        ;;
    *)
        print_banner
        echo "Usage: ./nightfury.sh {setup|run|status|clean}"
        echo ""
        echo "Commands:"
        echo "  setup   - Install dependencies and configure framework"
        echo "  run     - Start the NightFury CLI"
        echo "  status  - Check system compatibility and environment"
        echo "  clean   - Perform forensic cleanup of operation artifacts"
        ;;
esac
