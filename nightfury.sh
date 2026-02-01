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
                                    Version 2.3 (Full-Scope)
EOF
}

print_info() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_error() { echo -e "${RED}[!]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

# Command: Status
cmd_status() {
    print_info "NightFury Framework Status"
    python3 "${NIGHTFURY_HOME}/core/detection_engine.py" -q | python3 -m json.tool
}

# Command: Injection Engine
cmd_inject() {
    local type="${1:-login_modal}"
    print_info "Generating Injection Payload: $type"
    export PYTHONPATH="${NIGHTFURY_HOME}:${PYTHONPATH}"
    python3 -c "from modules.exploit_pro.injection_engine import InjectionEngine; e = InjectionEngine(); print(e.get_injector_script('$type'))"
}

# Command: IODR Control
cmd_iodr() {
    local action="${1:-monitor}"
    print_info "IODR Action: $action"
    export PYTHONPATH="${NIGHTFURY_HOME}:${PYTHONPATH}"
    python3 -c "from core.iodr_system import IODRSystem; i = IODRSystem(); i.monitor_environment() if '$action' == 'monitor' else i.trigger_response('$action')"
}

# Command: Brute-force
cmd_brute() {
    local target="$1"
    if [[ -z "$target" ]]; then
        print_error "Usage: nightfury.sh brute <url>"
        return 1
    fi
    print_info "Starting Automated Brute-force on: $target"
    python3 "${NIGHTFURY_HOME}/modules/recon_pro/dir_brute.py" "$target"
}

# Command: RuneHall Plugin
cmd_runehall() {
    local subcmd="$1"
    shift
    export PYTHONPATH="${NIGHTFURY_HOME}:${PYTHONPATH}"
    case "$subcmd" in
        recon)
            print_info "Launching RuneHall Recon..."
            python3 -c "from modules.plugins.runehall_pro import RuneHallPlugin; p = RuneHallPlugin('${NIGHTFURY_CONFIG}/c2_runehall.yaml'); p.run_recon()"
            ;;
        kit)
            local lhost="${1:-127.0.0.1}"
            local lport="${2:-4444}"
            print_info "Generating RuneHall Attack Kit..."
            python3 -c "import json; from modules.plugins.runehall_pro import RuneHallPlugin; p = RuneHallPlugin('${NIGHTFURY_CONFIG}/c2_runehall.yaml'); print(json.dumps(p.generate_attack_kit('$lhost', $lport), indent=2))"
            ;;
        brute)
            print_info "RuneHall Directory Brute-force..."
            python3 "${NIGHTFURY_HOME}/modules/recon_pro/dir_brute.py" "https://runehall.com"
            python3 "${NIGHTFURY_HOME}/modules/recon_pro/dir_brute.py" "https://api.runehall.com"
            ;;
        *)
            print_error "Usage: nightfury.sh runehall [recon|kit|brute]"
            return 1
            ;;
    esac
}

# Command: Help
cmd_help() {
    cat << EOF
NightFury Full-Scope - Command Reference

CORE:
  status              Show framework status
  health              Run health check
  iodr [monitor|HIGH] IODR Detection & Response Control
  inject [type]       Generate Overlay/Chat Injection payloads
  brute <url>         Automated Directory Brute-forcing
  runehall <cmd>      RuneHall.com Specialized Plugin (recon|kit|brute)
  panic               Emergency cleanup and exit

EXAMPLES:
  nightfury.sh inject login_modal
  nightfury.sh brute https://runehall.com
  nightfury.sh iodr monitor
  nightfury.sh runehall brute
EOF
}

# Main command dispatcher
main() {
    mkdir -p "${NIGHTFURY_LOGS}" "${NIGHTFURY_DATA}/exports" "${NIGHTFURY_DATA}/reports"
    local command="${1:-help}"
    shift || true
    case "$command" in
        status) cmd_status "$@" ;;
        inject) cmd_inject "$@" ;;
        iodr) cmd_iodr "$@" ;;
        brute) cmd_brute "$@" ;;
        runehall) cmd_runehall "$@" ;;
        health) cmd_health "$@" ;;
        help|--help|-h) print_banner; cmd_help ;;
        *) print_error "Unknown command: $command"; exit 1 ;;
    esac
}

main "$@"
