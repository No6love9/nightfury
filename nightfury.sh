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
                                    Version 2.6 (SHEBA-Protected)
EOF
}

print_info() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_error() { echo -e "${RED}[!]${NC} $1"; }

# Authentication Check
check_auth() {
    local codeword="$1"
    export PYTHONPATH="${NIGHTFURY_HOME}:${PYTHONPATH}"
    python3 -c "from core.auth_manager import SHEBAAuthManager; auth = SHEBAAuthManager(); auth.enforce_access('$codeword')"
}

# Command: Scrape Users
cmd_scrape() {
    local domain="${1:-runehall.com}"
    local codeword="$2"
    check_auth "$codeword"
    
    print_info "Starting stealthy user scraping for $domain..."
    export PYTHONPATH="${NIGHTFURY_HOME}:${PYTHONPATH}"
    local output_file="${NIGHTFURY_DATA}/exports/scraped_users.json"
    python3 -c "from modules.recon_pro.user_scraper import UserScraper; s = UserScraper('$domain'); users = s.scrape_users(); import json; print(json.dumps(users, indent=2)); open('$output_file', 'w').write(json.dumps(users))"
    print_success "Users saved to: $output_file"
}

# Command: GitHub Export
cmd_export() {
    local file_path="$1"
    local codeword="$2"
    check_auth "$codeword"
    
    if [[ -z "$file_path" ]]; then
        print_error "Usage: nightfury.sh export <file_path> <codeword>"
        return 1
    fi
    
    print_info "Exporting $file_path to GitHub..."
    export PYTHONPATH="${NIGHTFURY_HOME}:${PYTHONPATH}"
    python3 -c "from utilities.github_exporter import GitHubExporter; e = GitHubExporter(); e.export_file('$file_path')"
}

# Command: Help
cmd_help() {
    cat << EOF
NightFury SHEBA-Protected - Command Reference

CORE:
  status <codeword>           Show framework status
  scrape <domain> <codeword>  Stealthy username scraping
  export <file> <codeword>    Automated GitHub export
  c2 [start|stop] <codeword>  Manage C2 Collection Server
  crackprep <cmd> <codeword>  Prepare data for password cracking
  runehall <cmd> <codeword>   RuneHall.com Specialized Plugin
  panic                       Emergency cleanup and exit

NOTE:
  All sensitive commands require the 'SHEBA' codeword for access.

EXAMPLES:
  nightfury.sh scrape runehall.com SHEBA
  nightfury.sh export data/exports/scraped_users.json SHEBA
EOF
}

# Main command dispatcher
main() {
    mkdir -p "${NIGHTFURY_LOGS}" "${NIGHTFURY_DATA}/exports" "${NIGHTFURY_DATA}/reports"
    local command="${1:-help}"
    shift || true
    case "$command" in
        scrape) cmd_scrape "$@" ;;
        export) cmd_export "$@" ;;
        c2|crackprep|runehall|status|health) 
            # These commands now require codeword as the last argument
            # For simplicity in this shell wrapper, we just pass all args
            # and let the python core handle the auth check.
            cmd_"$command" "$@" ;;
        help|--help|-h) print_banner; cmd_help ;;
        *) print_error "Unknown command: $command"; exit 1 ;;
    esac
}

main "$@"
