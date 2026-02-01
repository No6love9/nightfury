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
                                    Version 2.0
EOF
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Command: Status
cmd_status() {
    print_info "NightFury Framework Status"
    echo ""
    
    # Environment detection
    python3 "${NIGHTFURY_HOME}/core/detection_engine.py" -q | python3 -m json.tool
}

# Command: Web Interface
cmd_web() {
    print_info "Starting NightFury Web Interface..."
    
    # Check if already running
    if pgrep -f "nightfury.*server.py" > /dev/null; then
        print_warning "Web interface is already running"
        print_info "Access at: https://localhost:7443"
        return
    fi
    
    # Start web server
    cd "${NIGHTFURY_HOME}/web_interface"
    python3 server.py &
    
    sleep 2
    
    print_success "Web interface started"
    print_info "Access at: https://localhost:7443"
    print_info "Default credentials: admin / nightfury2024"
}

# Command: Stop
cmd_stop() {
    print_info "Stopping NightFury services..."
    
    pkill -f "nightfury.*server.py" 2>/dev/null || true
    
    print_success "All services stopped"
}

# Command: OSINT
cmd_osint() {
    local domain="$1"
    
    if [[ -z "$domain" ]]; then
        print_error "Usage: nightfury.sh osint <domain>"
        return 1
    fi
    
    print_info "Running OSINT reconnaissance on: $domain"
    
    # Google Dorking
    print_info "Generating Google Dorks..."
    python3 "${NIGHTFURY_HOME}/modules/osint_engine/google_dorking.py" \
        "$domain" \
        --report \
        --format json
    
    print_success "OSINT reconnaissance complete"
    print_info "Results saved to: ${NIGHTFURY_DATA}/exports/"
}

# Command: Dork
cmd_dork() {
    local domain="$1"
    shift
    
    if [[ -z "$domain" ]]; then
        print_error "Usage: nightfury.sh dork <domain> [options]"
        return 1
    fi
    
    python3 "${NIGHTFURY_HOME}/modules/osint_engine/google_dorking.py" \
        "$domain" \
        "$@"
}

# Command: Auth
cmd_auth() {
    local subcmd="$1"
    shift
    
    python3 "${NIGHTFURY_HOME}/core/auth_manager.py" "$subcmd" "$@"
}

# Command: Health Check
cmd_health() {
    print_info "Running comprehensive health check..."
    
    python3 "${NIGHTFURY_HOME}/core/detection_engine.py" \
        --output "${NIGHTFURY_LOGS}/health_check_$(date +%Y%m%d_%H%M%S).json"
    
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        print_success "Health check passed"
    else
        print_warning "Health check completed with warnings"
    fi
    
    return $exit_code
}

# Command: Logs
cmd_logs() {
    local log_type="${1:-all}"
    
    case "$log_type" in
        error|errors)
            tail -f "${NIGHTFURY_LOGS}/errors.log"
            ;;
        recovery)
            tail -f "${NIGHTFURY_LOGS}/recovery.log"
            ;;
        critical)
            tail -f "${NIGHTFURY_LOGS}/critical.log"
            ;;
        all|*)
            tail -f "${NIGHTFURY_LOGS}"/*.log
            ;;
    esac
}

# Command: Update
cmd_update() {
    print_info "Updating NightFury framework..."
    
    cd "${NIGHTFURY_HOME}"
    
    if [[ -d .git ]]; then
        git pull
        print_success "Framework updated"
    else
        print_warning "Not a git repository - manual update required"
    fi
}

# Command: Backup
cmd_backup() {
    local backup_file="${1:-nightfury_backup_$(date +%Y%m%d_%H%M%S).tar.gz}"
    
    print_info "Creating backup..."
    
    tar -czf "$backup_file" \
        -C "${NIGHTFURY_HOME}" \
        --exclude='logs/*' \
        --exclude='data/exports/*' \
        --exclude='.git' \
        config/ core/ modules/ web_interface/ utilities/ docs/
    
    print_success "Backup created: $backup_file"
}

# Command: Restore
cmd_restore() {
    local backup_file="$1"
    
    if [[ -z "$backup_file" ]] || [[ ! -f "$backup_file" ]]; then
        print_error "Usage: nightfury.sh restore <backup_file>"
        return 1
    fi
    
    print_warning "This will restore configuration from backup"
    read -p "Continue? [y/N] " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Restore cancelled"
        return 0
    fi
    
    print_info "Restoring from backup..."
    
    tar -xzf "$backup_file" -C "${NIGHTFURY_HOME}"
    
    print_success "Restore complete"
}

# Command: Clean
cmd_clean() {
    print_warning "This will remove logs and temporary files"
    read -p "Continue? [y/N] " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Clean cancelled"
        return 0
    fi
    
    print_info "Cleaning logs and temporary files..."
    
    rm -f "${NIGHTFURY_LOGS}"/*.log
    rm -f /tmp/nightfury_*
    
    print_success "Clean complete"
}

# Command: Help
cmd_help() {
    cat << EOF

NightFury Framework - Command Reference

Usage: nightfury.sh [command] [options]

CORE COMMANDS:
  status              Show framework status and environment info
  health              Run comprehensive health check
  web                 Start web interface (https://localhost:7443)
  stop                Stop all NightFury services

OSINT COMMANDS:
  osint <domain>      Run full OSINT reconnaissance
  dork <domain>       Generate Google Dorks for domain
                      Options: -c <categories> -f <format> -r (report)

AUTHENTICATION:
  auth login <user> <pass> [--codeword SHEBA]
  auth add <user> <pass> <role> --created-by <admin>
  auth list           List all operators
  auth passwd <user> <old> <new>
  auth disable <user>
  auth enable <user>

SYSTEM MANAGEMENT:
  logs [type]         Tail logs (error|recovery|critical|all)
  update              Update framework from repository
  backup [file]       Create configuration backup
  restore <file>      Restore from backup
  clean               Remove logs and temporary files

EXAMPLES:
  nightfury.sh status
  nightfury.sh osint example.com
  nightfury.sh dork example.com -c sensitive_files -r
  nightfury.sh auth login admin nightfury2024 --codeword SHEBA
  nightfury.sh web
  nightfury.sh logs error

For detailed documentation, see: ${NIGHTFURY_HOME}/docs/

EOF
}

# Main command dispatcher
main() {
    # Create necessary directories
    mkdir -p "${NIGHTFURY_LOGS}" "${NIGHTFURY_DATA}/exports" "${NIGHTFURY_DATA}/reports"
    
    local command="${1:-help}"
    shift || true
    
    case "$command" in
        status)
            cmd_status "$@"
            ;;
        web)
            cmd_web "$@"
            ;;
        stop)
            cmd_stop "$@"
            ;;
        osint)
            cmd_osint "$@"
            ;;
        dork)
            cmd_dork "$@"
            ;;
        auth)
            cmd_auth "$@"
            ;;
        health)
            cmd_health "$@"
            ;;
        logs)
            cmd_logs "$@"
            ;;
        update)
            cmd_update "$@"
            ;;
        backup)
            cmd_backup "$@"
            ;;
        restore)
            cmd_restore "$@"
            ;;
        clean)
            cmd_clean "$@"
            ;;
        help|--help|-h)
            print_banner
            cmd_help
            ;;
        *)
            print_error "Unknown command: $command"
            print_info "Run 'nightfury.sh help' for usage information"
            exit 1
            ;;
    esac
}

# Run main
main "$@"
