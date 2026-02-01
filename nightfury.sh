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
                                    Version 2.1 (Compact)
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

# Command: DNS Bypass
cmd_bypass() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        print_error "Usage: nightfury.sh bypass <domain>"
        return 1
    fi
    print_info "Starting Cloudflare Bypass & DNS Deep-dive for: $domain"
    python3 "${NIGHTFURY_HOME}/modules/recon_pro/dns_bypass.py" "$domain"
}

# Command: XSS Generate
cmd_xss() {
    print_info "Generating Aggressive XSS Payloads..."
    python3 "${NIGHTFURY_HOME}/modules/exploit_pro/xss_generator.py"
}

# Command: BeEF Integration
cmd_beef() {
    local module="$1"
    if [[ -z "$module" ]]; then
        print_error "Usage: nightfury.sh beef <module>"
        echo "Available modules: pretty_theft, internal_ip, port_scanner, visited_domains"
        return 1
    fi
    print_info "Generating BeEF payload: $module"
    export PYTHONPATH="${NIGHTFURY_HOME}:${PYTHONPATH}"
    python3 -c "import sys; sys.path.append('${NIGHTFURY_HOME}'); from modules.beef_integration.beef_core import BeEFIntegration; b = BeEFIntegration(base_path='${NIGHTFURY_HOME}/modules/beef_integration/payloads'); print(b.get_payload('$module'))"
}

# Command: Health Check
cmd_health() {
    print_info "Running health check..."
    python3 "${NIGHTFURY_HOME}/core/detection_engine.py"
}

# Command: Help
cmd_help() {
    cat << EOF
NightFury Compact - Command Reference

CORE:
  status              Show framework status
  health              Run health check
  bypass <domain>     Cloudflare Bypass & DNS Deep-dive
  xss                 Generate aggressive XSS payloads
  beef <module>       Generate BeEF-integrated payloads
  panic               Emergency cleanup and exit

EXAMPLES:
  nightfury.sh bypass target.com
  nightfury.sh xss
  nightfury.sh beef pretty_theft
EOF
}

# Main command dispatcher
main() {
    mkdir -p "${NIGHTFURY_LOGS}" "${NIGHTFURY_DATA}/exports" "${NIGHTFURY_DATA}/reports"
    local command="${1:-help}"
    shift || true
    case "$command" in
        status) cmd_status "$@" ;;
        bypass) cmd_bypass "$@" ;;
        xss) cmd_xss "$@" ;;
        beef) cmd_beef "$@" ;;
        health) cmd_health "$@" ;;
        help|--help|-h) print_banner; cmd_help ;;
        *) print_error "Unknown command: $command"; exit 1 ;;
    esac
}

main "$@"
