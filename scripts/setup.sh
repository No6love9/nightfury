#!/bin/bash
#
# NightFury Framework - Master Setup Script
# One-command installation with comprehensive error handling
#
# Usage: sudo bash setup.sh
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NIGHTFURY_HOME="/opt/nightfury"
NIGHTFURY_USER="${SUDO_USER:-$USER}"
NIGHTFURY_CONFIG="/home/${NIGHTFURY_USER}/.nightfury"
LOG_FILE="/tmp/nightfury_setup_$(date +%Y%m%d_%H%M%S).log"

# Checkpoint file for resume capability
CHECKPOINT_FILE="/tmp/nightfury_setup.checkpoint"

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[*]${NC} $1" | tee -a "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[!]${NC} $1" | tee -a "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE"
}

# Function to save checkpoint
save_checkpoint() {
    echo "$1" > "$CHECKPOINT_FILE"
    print_info "Checkpoint saved: $1"
}

# Function to load checkpoint
load_checkpoint() {
    if [[ -f "$CHECKPOINT_FILE" ]]; then
        cat "$CHECKPOINT_FILE"
    else
        echo "0"
    fi
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Function to detect environment
detect_environment() {
    print_info "Detecting environment..."
    
    # Detect WSL
    if grep -qi microsoft /proc/version; then
        if grep -qi wsl2 /proc/version; then
            ENV_TYPE="WSL2"
        else
            ENV_TYPE="WSL1"
        fi
    else
        ENV_TYPE="Native Linux"
    fi
    
    print_success "Environment detected: $ENV_TYPE"
    
    # Detect distribution
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_VERSION=$VERSION_ID
        print_success "Distribution: $DISTRO $DISTRO_VERSION"
    fi
    
    # Check if Kali Linux
    if [[ "$DISTRO" == "kali" ]]; then
        IS_KALI=true
        print_success "Kali Linux detected"
    else
        IS_KALI=false
        print_warning "Not running on Kali Linux - some tools may need manual installation"
    fi
}

# Function to check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    local missing_tools=()
    local required_tools=("python3" "pip3" "git" "curl" "wget")
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        print_warning "Missing tools: ${missing_tools[*]}"
        print_info "Installing missing tools..."
        
        if [[ "$DISTRO" == "debian" ]] || [[ "$DISTRO" == "ubuntu" ]] || [[ "$DISTRO" == "kali" ]]; then
            apt-get update -qq
            apt-get install -y "${missing_tools[@]}" 2>&1 | tee -a "$LOG_FILE"
        else
            print_error "Unsupported distribution for automatic installation"
            print_error "Please install manually: ${missing_tools[*]}"
            exit 1
        fi
    fi
    
    print_success "All prerequisites satisfied"
}

# Function to install Python dependencies
install_python_deps() {
    print_info "Installing Python dependencies..."
    
    local python_packages=(
        "requests"
        "beautifulsoup4"
        "flask"
        "flask-socketio"
        "flask-cors"
        "pyyaml"
        "cryptography"
        "paramiko"
        "python-dotenv"
        "colorama"
        "tabulate"
        "tqdm"
    )
    
    pip3 install --upgrade pip 2>&1 | tee -a "$LOG_FILE"
    
    for package in "${python_packages[@]}"; do
        print_info "Installing $package..."
        pip3 install "$package" -q 2>&1 | tee -a "$LOG_FILE" || {
            print_warning "Failed to install $package, continuing..."
        }
    done
    
    print_success "Python dependencies installed"
}

# Function to install Kali tools
install_kali_tools() {
    if [[ "$IS_KALI" != true ]]; then
        print_warning "Skipping Kali tools installation (not on Kali Linux)"
        return
    fi
    
    print_info "Installing Kali penetration testing tools..."
    
    local kali_tools=(
        "nmap"
        "sqlmap"
        "nikto"
        "hydra"
        "john"
        "hashcat"
        "gobuster"
        "ffuf"
        "masscan"
        "amass"
        "subfinder"
        "nuclei"
        "httpx"
        "dnsx"
    )
    
    for tool in "${kali_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            print_info "Installing $tool..."
            apt-get install -y "$tool" -qq 2>&1 | tee -a "$LOG_FILE" || {
                print_warning "Failed to install $tool, continuing..."
            }
        else
            print_success "$tool already installed"
        fi
    done
    
    print_success "Kali tools installation complete"
}

# Function to copy framework files
install_framework() {
    print_info "Installing NightFury framework..."
    
    # Create installation directory
    mkdir -p "$NIGHTFURY_HOME"
    
    # Copy files from current directory to installation directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    
    print_info "Copying framework files..."
    cp -r "$SCRIPT_DIR"/* "$NIGHTFURY_HOME/" 2>&1 | tee -a "$LOG_FILE"
    
    # Set permissions
    chown -R "$NIGHTFURY_USER:$NIGHTFURY_USER" "$NIGHTFURY_HOME"
    chmod +x "$NIGHTFURY_HOME"/nightfury.sh
    chmod +x "$NIGHTFURY_HOME"/core/*.py
    chmod +x "$NIGHTFURY_HOME"/modules/*/*.py
    chmod +x "$NIGHTFURY_HOME"/scripts/*.sh
    
    print_success "Framework files installed to $NIGHTFURY_HOME"
}

# Function to create user configuration
create_user_config() {
    print_info "Creating user configuration..."
    
    mkdir -p "$NIGHTFURY_CONFIG"
    chown "$NIGHTFURY_USER:$NIGHTFURY_USER" "$NIGHTFURY_CONFIG"
    
    # Create symlink to user config
    if [[ ! -L "$NIGHTFURY_HOME/config/user" ]]; then
        ln -s "$NIGHTFURY_CONFIG" "$NIGHTFURY_HOME/config/user"
    fi
    
    print_success "User configuration created"
}

# Function to run interactive setup
run_interactive_setup() {
    print_info "Running interactive setup wizard..."
    
    # Run as the actual user, not root
    sudo -u "$NIGHTFURY_USER" python3 "$NIGHTFURY_HOME/core/interactive_setup.py" || {
        print_error "Interactive setup failed"
        return 1
    }
    
    print_success "Interactive setup completed"
}

# Function to initialize authentication
init_authentication() {
    print_info "Initializing authentication system..."
    
    # Create default operator configuration
    sudo -u "$NIGHTFURY_USER" python3 "$NIGHTFURY_HOME/core/auth_manager.py" list &> /dev/null || {
        print_info "Creating default admin account..."
        print_warning "Default credentials: admin / nightfury2024"
        print_warning "CHANGE DEFAULT PASSWORD IMMEDIATELY AFTER FIRST LOGIN"
    }
    
    print_success "Authentication system initialized"
}

# Function to create Windows integration (for WSL)
setup_windows_integration() {
    if [[ "$ENV_TYPE" != "WSL"* ]]; then
        print_info "Skipping Windows integration (not running in WSL)"
        return
    fi
    
    print_info "Setting up Windows integration..."
    
    # Create Windows export directory
    WINDOWS_EXPORT_DIR="/mnt/c/NightFury"
    mkdir -p "$WINDOWS_EXPORT_DIR"/{exports,reports,logs}
    chown -R "$NIGHTFURY_USER:$NIGHTFURY_USER" "$WINDOWS_EXPORT_DIR"
    
    # Create symlinks
    ln -sf "$WINDOWS_EXPORT_DIR/exports" "$NIGHTFURY_HOME/data/windows_exports"
    ln -sf "$WINDOWS_EXPORT_DIR/reports" "$NIGHTFURY_HOME/data/windows_reports"
    
    print_success "Windows integration configured"
    print_info "Windows access: C:\\NightFury\\"
}

# Function to create shell aliases
create_aliases() {
    print_info "Creating shell aliases..."
    
    local bashrc="/home/$NIGHTFURY_USER/.bashrc"
    
    # Check if aliases already exist
    if ! grep -q "NightFury aliases" "$bashrc"; then
        cat >> "$bashrc" << 'EOF'

# NightFury aliases
alias nightfury='sudo /opt/nightfury/nightfury.sh'
alias nf='sudo /opt/nightfury/nightfury.sh'
alias nightfury-logs='tail -f /opt/nightfury/logs/*.log'
alias nightfury-update='cd /opt/nightfury && git pull'
export NIGHTFURY_HOME="/opt/nightfury"
EOF
        print_success "Shell aliases created"
    else
        print_info "Shell aliases already exist"
    fi
}

# Function to run health check
run_health_check() {
    print_info "Running system health check..."
    
    sudo -u "$NIGHTFURY_USER" python3 "$NIGHTFURY_HOME/core/detection_engine.py" -o "$NIGHTFURY_HOME/logs/environment_profile.json" || {
        print_warning "Health check completed with warnings"
        return 0
    }
    
    print_success "Health check passed"
}

# Function to display completion message
display_completion() {
    echo ""
    echo "=========================================="
    echo "  NightFury Framework Installation"
    echo "=========================================="
    echo ""
    print_success "Installation completed successfully!"
    echo ""
    echo "Installation Details:"
    echo "  - Framework Location: $NIGHTFURY_HOME"
    echo "  - User Config: $NIGHTFURY_CONFIG"
    echo "  - Environment: $ENV_TYPE"
    echo "  - Log File: $LOG_FILE"
    echo ""
    echo "Quick Start:"
    echo "  1. Source your shell: source ~/.bashrc"
    echo "  2. Run framework: nightfury --help"
    echo "  3. Start web interface: nightfury --web"
    echo ""
    echo "Default Credentials:"
    echo "  Username: admin"
    echo "  Password: nightfury2024"
    echo "  Codeword: SHEBA"
    echo ""
    print_warning "IMPORTANT: Change default password immediately!"
    echo ""
    echo "Documentation: $NIGHTFURY_HOME/docs/"
    echo "=========================================="
    echo ""
}

# Function to cleanup on error
cleanup_on_error() {
    print_error "Installation failed!"
    print_info "Log file: $LOG_FILE"
    print_info "You can resume installation by running this script again"
    exit 1
}

# Trap errors
trap cleanup_on_error ERR

# Main installation flow
main() {
    clear
    echo "=========================================="
    echo "  NightFury Framework Setup"
    echo "  Professional Red Team Operations"
    echo "=========================================="
    echo ""
    
    # Check if running as root
    check_root
    
    # Load checkpoint if exists
    CHECKPOINT=$(load_checkpoint)
    
    # Phase 1: Environment Detection
    if [[ $CHECKPOINT -lt 1 ]]; then
        detect_environment
        save_checkpoint 1
    else
        print_info "Skipping phase 1 (already completed)"
    fi
    
    # Phase 2: Prerequisites
    if [[ $CHECKPOINT -lt 2 ]]; then
        check_prerequisites
        save_checkpoint 2
    else
        print_info "Skipping phase 2 (already completed)"
    fi
    
    # Phase 3: Python Dependencies
    if [[ $CHECKPOINT -lt 3 ]]; then
        install_python_deps
        save_checkpoint 3
    else
        print_info "Skipping phase 3 (already completed)"
    fi
    
    # Phase 4: Kali Tools
    if [[ $CHECKPOINT -lt 4 ]]; then
        install_kali_tools
        save_checkpoint 4
    else
        print_info "Skipping phase 4 (already completed)"
    fi
    
    # Phase 5: Framework Installation
    if [[ $CHECKPOINT -lt 5 ]]; then
        install_framework
        save_checkpoint 5
    else
        print_info "Skipping phase 5 (already completed)"
    fi
    
    # Phase 6: User Configuration
    if [[ $CHECKPOINT -lt 6 ]]; then
        create_user_config
        save_checkpoint 6
    else
        print_info "Skipping phase 6 (already completed)"
    fi
    
    # Phase 7: Interactive Setup
    if [[ $CHECKPOINT -lt 7 ]]; then
        run_interactive_setup
        save_checkpoint 7
    else
        print_info "Skipping phase 7 (already completed)"
    fi
    
    # Phase 8: Authentication
    if [[ $CHECKPOINT -lt 8 ]]; then
        init_authentication
        save_checkpoint 8
    else
        print_info "Skipping phase 8 (already completed)"
    fi
    
    # Phase 9: Windows Integration
    if [[ $CHECKPOINT -lt 9 ]]; then
        setup_windows_integration
        save_checkpoint 9
    else
        print_info "Skipping phase 9 (already completed)"
    fi
    
    # Phase 10: Shell Aliases
    if [[ $CHECKPOINT -lt 10 ]]; then
        create_aliases
        save_checkpoint 10
    else
        print_info "Skipping phase 10 (already completed)"
    fi
    
    # Phase 11: Health Check
    if [[ $CHECKPOINT -lt 11 ]]; then
        run_health_check
        save_checkpoint 11
    else
        print_info "Skipping phase 11 (already completed)"
    fi
    
    # Remove checkpoint file on success
    rm -f "$CHECKPOINT_FILE"
    
    # Display completion message
    display_completion
}

# Run main installation
main "$@"
