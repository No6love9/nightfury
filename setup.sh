#!/bin/bash

################################################################################
# NightFury Framework v2.0 - All-in-One Setup Script
# Automated installation and configuration for Linux/macOS
# Supports: Ubuntu, Debian, macOS, and other Linux distributions
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
FRAMEWORK_NAME="NightFury"
FRAMEWORK_VERSION="2.0"
VENV_NAME="nightfury_env"
PYTHON_MIN_VERSION="3.8"

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

################################################################################
# System Detection
################################################################################

detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS=$ID
            VER=$VERSION_ID
        else
            OS="linux"
            VER="unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        VER=$(sw_vers -productVersion)
    else
        OS="unknown"
        VER="unknown"
    fi
    
    echo "$OS"
}

################################################################################
# Prerequisite Checks
################################################################################

check_python() {
    print_info "Checking Python installation..."
    
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        print_info "Install Python 3 using:"
        if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
            echo "  sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-venv"
        elif [[ "$OS" == "macos" ]]; then
            echo "  brew install python3"
        fi
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    print_success "Python $PYTHON_VERSION found"
    
    # Version check
    if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"; then
        print_error "Python 3.8+ required (found $PYTHON_VERSION)"
        exit 1
    fi
}

check_git() {
    print_info "Checking Git installation..."
    
    if ! command -v git &> /dev/null; then
        print_warning "Git is not installed"
        print_info "Install Git using:"
        if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
            echo "  sudo apt-get install -y git"
        elif [[ "$OS" == "macos" ]]; then
            echo "  brew install git"
        fi
        print_info "Continuing without Git..."
    else
        GIT_VERSION=$(git --version)
        print_success "$GIT_VERSION"
    fi
}

install_system_dependencies() {
    print_info "Installing system dependencies..."
    
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        print_info "Detected Ubuntu/Debian system"
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            python3-dev \
            libssl-dev \
            libffi-dev \
            libpq-dev \
            git \
            curl \
            wget
        print_success "System dependencies installed"
    elif [[ "$OS" == "macos" ]]; then
        print_info "Detected macOS system"
        if ! command -v brew &> /dev/null; then
            print_info "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        brew install openssl libffi
        print_success "System dependencies installed"
    else
        print_warning "Unknown OS. Please install system dependencies manually."
    fi
}

################################################################################
# Virtual Environment Setup
################################################################################

setup_venv() {
    print_header "Setting up Virtual Environment"
    
    if [ -d "$VENV_NAME" ]; then
        print_warning "Virtual environment already exists"
        read -p "Remove and recreate? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$VENV_NAME"
            print_info "Creating new virtual environment..."
            python3 -m venv "$VENV_NAME"
        fi
    else
        print_info "Creating virtual environment..."
        python3 -m venv "$VENV_NAME"
    fi
    
    print_success "Virtual environment created"
    
    # Activate virtual environment
    print_info "Activating virtual environment..."
    source "$VENV_NAME/bin/activate"
    print_success "Virtual environment activated"
}

upgrade_pip() {
    print_info "Upgrading pip, setuptools, and wheel..."
    pip install --upgrade pip setuptools wheel
    print_success "pip upgraded"
}

################################################################################
# Dependencies Installation
################################################################################

install_requirements() {
    print_header "Installing Python Dependencies"
    
    if [ ! -f "requirements.txt" ]; then
        print_error "requirements.txt not found"
        exit 1
    fi
    
    print_info "Installing packages from requirements.txt..."
    pip install -r requirements.txt
    print_success "All dependencies installed"
}

################################################################################
# Verification
################################################################################

verify_installation() {
    print_header "Verifying Installation"
    
    if [ -f "verify_installation.py" ]; then
        print_info "Running installation verification..."
        python3 verify_installation.py
    else
        print_warning "verify_installation.py not found"
    fi
}

################################################################################
# Gemini AI Setup
################################################################################

setup_gemini() {
    print_header "Google Gemini AI Setup (Optional)"
    
    read -p "Do you want to set up Google Gemini AI? (y/n) " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Skipping Gemini AI setup"
        return
    fi
    
    print_info "Getting Gemini API key..."
    echo ""
    echo "1. Visit: https://aistudio.google.com/app/apikeys"
    echo "2. Click 'Create API Key'"
    echo "3. Copy your API key"
    echo ""
    
    read -p "Enter your Gemini API key (or press Enter to skip): " GEMINI_KEY
    
    if [ -z "$GEMINI_KEY" ]; then
        print_warning "Skipping Gemini AI configuration"
        return
    fi
    
    # Set environment variable
    export GEMINI_API_KEY="$GEMINI_KEY"
    
    # Add to shell profile
    if [[ "$OS" == "macos" ]]; then
        SHELL_PROFILE="$HOME/.zprofile"
    else
        SHELL_PROFILE="$HOME/.bashrc"
    fi
    
    if ! grep -q "GEMINI_API_KEY" "$SHELL_PROFILE"; then
        echo "export GEMINI_API_KEY='$GEMINI_KEY'" >> "$SHELL_PROFILE"
        print_success "Gemini API key saved to $SHELL_PROFILE"
    fi
    
    print_success "Gemini AI configured"
}

################################################################################
# Directory Setup
################################################################################

setup_directories() {
    print_header "Setting up Directories"
    
    mkdir -p nightfury_reports
    mkdir -p nightfury_logs
    mkdir -p nightfury_data
    
    chmod 755 nightfury_reports
    chmod 755 nightfury_logs
    chmod 755 nightfury_data
    
    print_success "Directories created"
}

################################################################################
# Configuration Files
################################################################################

create_config_files() {
    print_header "Creating Configuration Files"
    
    # Create nightfury_config.json
    if [ ! -f "nightfury_config.json" ]; then
        print_info "Creating nightfury_config.json..."
        cat > nightfury_config.json << 'EOF'
{
  "framework": {
    "version": "2.0",
    "mode": "balanced",
    "threads": 8,
    "timeout": 300
  },
  "reporting": {
    "output_dir": "./nightfury_reports",
    "auto_save": true,
    "formats": ["html", "json", "csv"]
  },
  "gui": {
    "theme": "dark",
    "window_width": 1600,
    "window_height": 950
  },
  "security": {
    "proxy_rotation": true,
    "evasion_enabled": true,
    "cache_enabled": true
  }
}
EOF
        print_success "nightfury_config.json created"
    fi
}

################################################################################
# Git Repository Setup
################################################################################

setup_git_repo() {
    print_header "Git Repository Setup (Optional)"
    
    if [ ! -d ".git" ]; then
        read -p "Initialize Git repository? (y/n) " -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_info "Initializing Git repository..."
            git init
            
            # Create .gitignore
            cat > .gitignore << 'EOF'
# Virtual Environment
nightfury_env/
venv/
env/

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# Environment variables
.env
.env.local
GEMINI_API_KEY

# Reports and logs
nightfury_reports/
nightfury_logs/
nightfury_data/

# OS
.DS_Store
Thumbs.db

# Sensitive
*.key
*.pem
*.cert
EOF
            print_success ".gitignore created"
            
            git add .
            git commit -m "Initial NightFury Framework v2.0 setup"
            print_success "Git repository initialized"
        fi
    fi
}

################################################################################
# Post-Installation
################################################################################

print_post_install_info() {
    print_header "Installation Complete!"
    
    echo ""
    echo -e "${GREEN}NightFury Framework v2.0 is ready to use!${NC}"
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Activate virtual environment:"
    echo "   ${BLUE}source $VENV_NAME/bin/activate${NC}"
    echo ""
    echo "2. Start GUI Dashboard:"
    echo "   ${BLUE}python3 nightfury_gui_gemini.py${NC}"
    echo ""
    echo "3. Or use quick commands:"
    echo "   ${BLUE}python3 runehall_quick_commands.py list${NC}"
    echo ""
    echo "4. Generate reports:"
    echo "   ${BLUE}python3 nightfury_reporting_engine.py${NC}"
    echo ""
    echo "Documentation:"
    echo "   - Quick Reference: RUNEHALL_QUICK_REFERENCE.md"
    echo "   - Gemini Setup: GEMINI_SETUP.md"
    echo "   - Installation: INSTALLATION_GUIDE.md"
    echo "   - Pentesting Guide: nightfury_pentesting_guide.md"
    echo ""
    echo "For more information, see README.md"
    echo ""
}

################################################################################
# Main Setup Flow
################################################################################

main() {
    clear
    
    print_header "$FRAMEWORK_NAME Framework v$FRAMEWORK_VERSION - Setup"
    
    # Detect OS
    OS=$(detect_os)
    print_info "Detected OS: $OS"
    echo ""
    
    # Check prerequisites
    check_python
    check_git
    echo ""
    
    # Install system dependencies
    read -p "Install system dependencies? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_system_dependencies
        echo ""
    fi
    
    # Setup virtual environment
    setup_venv
    echo ""
    
    # Upgrade pip
    upgrade_pip
    echo ""
    
    # Install requirements
    install_requirements
    echo ""
    
    # Setup directories
    setup_directories
    echo ""
    
    # Create configuration files
    create_config_files
    echo ""
    
    # Setup Gemini AI
    setup_gemini
    echo ""
    
    # Verify installation
    verify_installation
    echo ""
    
    # Setup Git repository
    setup_git_repo
    echo ""
    
    # Print post-installation info
    print_post_install_info
}

# Run main function
main

################################################################################
# Final Instructions
################################################################################

echo -e "\n${GREEN}================================================================${NC}"
echo -e "${GREEN}       NIGHTFURY FRAMEWORK v3.0-GOLD INSTALLATION COMPLETE       ${NC}"
echo -e "${GREEN}================================================================${NC}"
echo -e "\n${BLUE}To start the Professional Suite:${NC}"
echo -e "  source $VENV_NAME/bin/activate"
echo -e "  python3 nightfury_pro.py --cli"
echo -e "\n${BLUE}For aggressive testing:${NC}"
echo -e "  python3 nightfury_pro.py --target <domain>"
echo -e "\n${BLUE}For GUI Dashboard:${NC}"
echo -e "  python3 nightfury_pro.py --gui"
echo -e "\n${GREEN}Happy Hunting!${NC}\n"
