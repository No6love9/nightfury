#!/bin/bash

################################################################################
# NightFury Framework v2.0 - Universal Setup Script (Linux/macOS)
# Automated installation, configuration, and verification
# Supports: Ubuntu, Debian, CentOS, macOS
################################################################################

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
FRAMEWORK_NAME="NightFury"
FRAMEWORK_VERSION="2.0"
VENV_NAME="nightfury_env"
REPO_URL="https://github.com/No6love9/nightfury.git"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Logging functions
log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_error() {
    echo -e "${RED}[X]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${CYAN}================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}================================${NC}"
    echo ""
}

# Banner
print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║          ${FRAMEWORK_NAME} Framework v${FRAMEWORK_VERSION} - Setup Wizard                    ║"
    echo "║                                                                ║"
    echo "║     Professional Penetration Testing Platform                 ║"
    echo "║     with Google Gemini AI Integration                         ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Detect OS
detect_os() {
    log_section "System Detection"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS_NAME=$NAME
            OS_VERSION=$VERSION_ID
        fi
        log_success "Detected: Linux ($OS_NAME $OS_VERSION)"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        OS_VERSION=$(sw_vers -productVersion)
        log_success "Detected: macOS ($OS_VERSION)"
    else
        log_error "Unsupported OS: $OSTYPE"
        exit 1
    fi
}

# Check Python installation
check_python() {
    log_section "Python Version Check"
    
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        log_info "Install Python 3 using:"
        if [[ "$OS" == "linux" ]]; then
            echo "  Ubuntu/Debian: sudo apt-get install python3 python3-pip python3-venv"
            echo "  CentOS/RHEL: sudo yum install python3 python3-pip"
        else
            echo "  macOS: brew install python3"
        fi
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
        log_error "Python 3.8+ required, found: $PYTHON_VERSION"
        exit 1
    fi
    
    log_success "Python $PYTHON_VERSION found"
}

# Install system dependencies
install_system_deps() {
    log_section "System Dependencies"
    
    if [[ "$OS" == "linux" ]]; then
        if command -v apt-get &> /dev/null; then
            log_info "Installing dependencies (Ubuntu/Debian)..."
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                python3-dev \
                python3-venv \
                libssl-dev \
                libffi-dev \
                libpq-dev \
                git \
                curl \
                wget
            log_success "System dependencies installed"
        elif command -v yum &> /dev/null; then
            log_info "Installing dependencies (CentOS/RHEL)..."
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y \
                python3-devel \
                openssl-devel \
                libffi-devel \
                postgresql-devel \
                git \
                curl \
                wget
            log_success "System dependencies installed"
        fi
    elif [[ "$OS" == "macos" ]]; then
        log_info "Installing dependencies (macOS)..."
        if ! command -v brew &> /dev/null; then
            log_warning "Homebrew not found, installing..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        brew install python3 openssl libffi git curl wget
        log_success "System dependencies installed"
    fi
}

# Create virtual environment
create_venv() {
    log_section "Virtual Environment Setup"
    
    if [ -d "$VENV_NAME" ]; then
        log_warning "Virtual environment already exists"
        read -p "Remove and recreate? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$VENV_NAME"
            log_info "Creating new virtual environment..."
            python3 -m venv "$VENV_NAME"
        fi
    else
        log_info "Creating virtual environment..."
        python3 -m venv "$VENV_NAME"
    fi
    
    log_success "Virtual environment created at: $VENV_NAME"
}

# Activate virtual environment
activate_venv() {
    log_info "Activating virtual environment..."
    source "$VENV_NAME/bin/activate"
    log_success "Virtual environment activated"
}

# Upgrade pip and setuptools
upgrade_pip() {
    log_section "Pip Upgrade"
    
    log_info "Upgrading pip, setuptools, and wheel..."
    python3 -m pip install --upgrade pip setuptools wheel
    log_success "Pip upgraded"
}

# Install Python dependencies
install_dependencies() {
    log_section "Python Dependencies Installation"
    
    if [ ! -f "requirements.txt" ]; then
        log_error "requirements.txt not found"
        exit 1
    fi
    
    log_info "Installing Python packages from requirements.txt..."
    pip install -r requirements.txt
    log_success "All dependencies installed"
}

# Create directories
create_directories() {
    log_section "Directory Structure"
    
    log_info "Creating directories..."
    mkdir -p nightfury_reports
    mkdir -p nightfury_logs
    mkdir -p nightfury_data
    log_success "Directories created"
}

# Create configuration file
create_config() {
    log_section "Configuration Setup"
    
    if [ -f "nightfury_config.json" ]; then
        log_warning "Configuration file already exists"
        return
    fi
    
    log_info "Creating configuration file..."
    cat > nightfury_config.json << 'EOF'
{
  "framework": {
    "version": "2.0",
    "mode": "balanced",
    "threads": 8,
    "timeout": 300,
    "max_retries": 3
  },
  "reporting": {
    "output_dir": "./nightfury_reports",
    "auto_save": true,
    "formats": ["html", "json", "csv"],
    "include_screenshots": true
  },
  "gui": {
    "theme": "dark",
    "window_width": 1600,
    "window_height": 950,
    "auto_save_interval": 300
  },
  "security": {
    "proxy_rotation": true,
    "evasion_enabled": true,
    "cache_enabled": true,
    "cache_size_mb": 1024,
    "ssl_verify": false
  },
  "logging": {
    "level": "INFO",
    "format": "json",
    "rotation": "10 MB",
    "retention": "30 days"
  },
  "ai": {
    "provider": "gemini",
    "auto_analysis": true,
    "confidence_threshold": 0.85
  }
}
EOF
    log_success "Configuration file created"
}

# Setup Gemini AI
setup_gemini() {
    log_section "Google Gemini AI Setup (Optional)"
    
    read -p "Do you want to set up Google Gemini AI? (y/n): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        log_info "Getting your Gemini API key:"
        echo "  1. Visit: https://aistudio.google.com/app/apikeys"
        echo "  2. Click 'Create API Key'"
        echo "  3. Copy your API key"
        echo ""
        
        read -p "Enter your Gemini API key (or press Enter to skip): " GEMINI_KEY
        
        if [ ! -z "$GEMINI_KEY" ]; then
            export GEMINI_API_KEY="$GEMINI_KEY"
            echo "export GEMINI_API_KEY='$GEMINI_KEY'" >> "$VENV_NAME/bin/activate"
            log_success "Gemini API key configured"
        else
            log_warning "Gemini API key skipped"
        fi
    fi
}

# Verify installation
verify_installation() {
    log_section "Installation Verification"
    
    if [ -f "verify_installation.py" ]; then
        log_info "Running installation verification..."
        python3 verify_installation.py
    else
        log_warning "verify_installation.py not found, skipping verification"
    fi
}

# Create startup script
create_startup_script() {
    log_section "Startup Script Creation"
    
    log_info "Creating startup script..."
    cat > start_nightfury.sh << 'EOF'
#!/bin/bash
source nightfury_env/bin/activate
python3 nightfury_gui_gemini.py
EOF
    chmod +x start_nightfury.sh
    log_success "Startup script created: start_nightfury.sh"
}

# Print post-installation info
print_post_install() {
    log_section "Installation Complete!"
    
    echo -e "${GREEN}NightFury Framework v${FRAMEWORK_VERSION} is ready to use!${NC}"
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Activate virtual environment:"
    echo "   ${CYAN}source $VENV_NAME/bin/activate${NC}"
    echo ""
    echo "2. Start GUI Dashboard:"
    echo "   ${CYAN}python3 nightfury_gui_gemini.py${NC}"
    echo ""
    echo "3. Or use quick commands:"
    echo "   ${CYAN}python3 runehall_quick_commands.py list${NC}"
    echo ""
    echo "4. Generate reports:"
    echo "   ${CYAN}python3 nightfury_reporting_engine.py${NC}"
    echo ""
    echo "Documentation:"
    echo "   - Quick Reference: RUNEHALL_QUICK_REFERENCE.md"
    echo "   - Gemini Setup: GEMINI_SETUP.md"
    echo "   - Installation: INSTALLATION_GUIDE.md"
    echo "   - Pentesting Guide: nightfury_pentesting_guide.md"
    echo ""
    echo "Repository: ${REPO_URL}"
    echo ""
}

# Main installation flow
main() {
    print_banner
    
    detect_os
    check_python
    install_system_deps
    create_venv
    activate_venv
    upgrade_pip
    install_dependencies
    create_directories
    create_config
    setup_gemini
    verify_installation
    create_startup_script
    print_post_install
    
    log_success "Setup completed successfully!"
}

# Run main function
main "$@"
