# NightFury Framework v2.0 - Complete Installation Guide

## Overview

This guide provides step-by-step instructions for installing and configuring the NightFury Framework v2.0 with all dependencies, GUI dashboard, and reporting capabilities.

---

## System Requirements

### Minimum Requirements

- **Operating System**: Linux (Ubuntu 20.04+), macOS 10.14+, or Windows 10+
- **Python**: 3.8 or higher (3.10+ recommended)
- **RAM**: 4GB minimum (8GB recommended)
- **Disk Space**: 2GB for framework and dependencies
- **Network**: Internet connection for downloading packages

### Recommended Setup

- **OS**: Ubuntu 22.04 LTS or Debian 11+
- **Python**: 3.11 or higher
- **RAM**: 16GB or more
- **Disk Space**: 10GB+ for operations and reports
- **CPU**: Multi-core processor (4+ cores)

---

## Installation Steps

### Step 1: Verify Python Installation

```bash
# Check Python version
python3 --version

# Should output: Python 3.8.0 or higher
```

If Python is not installed or version is too old, install it:

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv
```

**macOS:**
```bash
brew install python3
```

**Windows:**
Download from https://www.python.org/downloads/ and install

### Step 2: Create Virtual Environment

Creating a virtual environment isolates NightFury dependencies from system Python:

```bash
# Create virtual environment
python3 -m venv nightfury_env

# Activate virtual environment
# On Linux/macOS:
source nightfury_env/bin/activate

# On Windows:
nightfury_env\Scripts\activate
```

### Step 3: Upgrade pip, setuptools, and wheel

```bash
pip install --upgrade pip setuptools wheel
```

### Step 4: Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get install -y \
    build-essential \
    python3-dev \
    libssl-dev \
    libffi-dev \
    libpq-dev \
    git \
    curl \
    wget
```

**macOS:**
```bash
brew install openssl libffi
```

**Windows:**
Install Visual C++ Build Tools from Microsoft (required for some packages)

### Step 5: Install NightFury Requirements

```bash
# Navigate to NightFury directory
cd /path/to/nightfury

# Install all dependencies
pip install -r requirements.txt

# This will take 5-10 minutes depending on internet speed
```

### Step 6: Verify Installation

```bash
# Run verification script
python3 verify_installation.py

# Should show all packages as installed
```

---

## Component Installation

### Core Framework

The core framework includes all reconnaissance and exploitation modules:

```bash
# Verify core packages
python3 -c "import requests, scapy, cryptography; print('Core framework OK')"
```

### GUI Dashboard

The GUI requires PyQt5:

```bash
# PyQt5 is included in requirements.txt
# Verify installation
python3 -c "from PyQt5.QtWidgets import QApplication; print('PyQt5 OK')"

# If not installed:
pip install PyQt5 PyQt5-sip
```

### Reporting Engine

The reporting engine requires data processing libraries:

```bash
# Verify reporting libraries
python3 -c "import pandas, numpy, json; print('Reporting engine OK')"
```

### Machine Learning Features

Optional ML features for advanced analysis:

```bash
# Install ML packages (optional)
pip install tensorflow torch scikit-learn xgboost lightgbm

# This requires significant disk space and time
```

---

## Configuration

### Directory Structure

After installation, create the following directory structure:

```
nightfury/
├── requirements.txt              # Dependencies
├── verify_installation.py        # Installation verification
├── nightfury_gui.py             # GUI dashboard
├── nightfury_reporting_engine.py # Reporting engine
├── runehall_quick_commands.py   # Quick commands
├── runehall_exploitation_chains.py # Exploitation chains
├── nightfury_framework_enhancement.py # Framework enhancements
├── nightfury_reports/           # Operation reports (auto-created)
├── nightfury_logs/              # Logs (auto-created)
└── nightfury_data/              # Data storage (auto-created)
```

### Create Required Directories

```bash
# Create directories
mkdir -p nightfury_reports
mkdir -p nightfury_logs
mkdir -p nightfury_data

# Set permissions
chmod 755 nightfury_reports
chmod 755 nightfury_logs
chmod 755 nightfury_data
```

### Configuration File

Create `nightfury_config.json`:

```json
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
    "window_width": 1400,
    "window_height": 900
  },
  "security": {
    "proxy_rotation": true,
    "evasion_enabled": true,
    "cache_enabled": true
  }
}
```

---

## Running NightFury

### Start GUI Dashboard

```bash
# Activate virtual environment first
source nightfury_env/bin/activate

# Start GUI
python3 nightfury_gui.py
```

The GUI will open with the following features:
- Operation control panel
- Real-time findings display
- Automated reporting
- Statistics dashboard

### Use Quick Commands

```bash
# List all available commands
python3 runehall_quick_commands.py list

# Execute a command
python3 runehall_quick_commands.py recon-full runehall.com

# Get command info
python3 runehall_quick_commands.py info exploit-auth
```

### Run Exploitation Chains

```bash
# List available chains
python3 runehall_exploitation_chains.py list

# Execute a chain
python3 runehall_exploitation_chains.py execute ELITE_NEXUS runehall.com

# Get chain details
python3 runehall_exploitation_chains.py info ELITE_NEXUS
```

### Generate Reports

```bash
# Run reporting engine
python3 nightfury_reporting_engine.py

# This generates:
# - HTML report
# - JSON report
# - CSV export
# All saved to nightfury_reports/
```

---

## Troubleshooting

### Issue: PyQt5 Installation Fails

**Solution:**
```bash
# Install system dependencies first
sudo apt-get install python3-pyqt5

# Or use pre-built wheels
pip install --only-binary :all: PyQt5
```

### Issue: Cryptography Package Fails

**Solution:**
```bash
# Install system dependencies
sudo apt-get install libssl-dev libffi-dev

# Reinstall package
pip install --force-reinstall cryptography
```

### Issue: Permission Denied

**Solution:**
```bash
# Make scripts executable
chmod +x nightfury_gui.py
chmod +x runehall_quick_commands.py
chmod +x runehall_exploitation_chains.py
chmod +x verify_installation.py
```

### Issue: Module Not Found

**Solution:**
```bash
# Verify virtual environment is activated
which python3

# Should show path inside nightfury_env

# Reinstall requirements
pip install --force-reinstall -r requirements.txt
```

### Issue: GUI Window Won't Open

**Solution:**
```bash
# Check for display issues (Linux)
export DISPLAY=:0

# Or use headless mode
python3 nightfury_gui.py --headless
```

---

## Verification Checklist

After installation, verify all components:

```bash
# 1. Python version
python3 --version

# 2. Virtual environment
which python3

# 3. Core packages
python3 verify_installation.py

# 4. GUI
python3 -c "from PyQt5.QtWidgets import QApplication; print('GUI OK')"

# 5. Quick commands
python3 runehall_quick_commands.py list

# 6. Exploitation chains
python3 runehall_exploitation_chains.py list

# 7. Reporting engine
python3 nightfury_reporting_engine.py

# 8. Framework enhancements
python3 nightfury_framework_enhancement.py optimizations
```

---

## Performance Optimization

### Increase Thread Count

Edit `nightfury_config.json`:
```json
{
  "framework": {
    "threads": 16
  }
}
```

### Enable GPU Acceleration

For TensorFlow/PyTorch:
```bash
# Install CUDA support
pip install tensorflow[and-cuda]

# Or for PyTorch
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
```

### Optimize Memory Usage

```bash
# Reduce cache size
python3 nightfury_framework_enhancement.py config stealth
```

---

## Updating NightFury

### Update Dependencies

```bash
# Update all packages
pip install --upgrade -r requirements.txt

# Or specific package
pip install --upgrade requests
```

### Update Framework

```bash
# Pull latest from repository
git pull origin main

# Reinstall requirements
pip install -r requirements.txt
```

---

## Security Considerations

### Virtual Environment

Always use a virtual environment to isolate dependencies:
```bash
source nightfury_env/bin/activate
```

### Secure Configuration

Store sensitive data in environment variables:
```bash
export NIGHTFURY_API_KEY="your-api-key"
export NIGHTFURY_PROXY="proxy-url"
```

### Report Security

Protect generated reports:
```bash
chmod 600 nightfury_reports/*.html
chmod 600 nightfury_reports/*.json
```

---

## Next Steps

1. **Read Documentation**: See `RUNEHALL_QUICK_REFERENCE.md`
2. **Start GUI**: Run `python3 nightfury_gui.py`
3. **Run Quick Commands**: Execute `python3 runehall_quick_commands.py list`
4. **Generate Reports**: Run `python3 nightfury_reporting_engine.py`
5. **Review Findings**: Check `nightfury_reports/` directory

---

## Support & Resources

- **Installation Verification**: `python3 verify_installation.py`
- **Quick Reference**: `RUNEHALL_QUICK_REFERENCE.md`
- **Burp Integration**: `burp_integration_quickstart.md`
- **Full Guide**: `nightfury_pentesting_guide.md`

---

## Uninstallation

To completely remove NightFury:

```bash
# Deactivate virtual environment
deactivate

# Remove virtual environment
rm -rf nightfury_env

# Remove framework directory
rm -rf /path/to/nightfury

# Remove reports (optional)
rm -rf nightfury_reports
```

---

**Version**: 2.0
**Last Updated**: 2026-02-03
**Status**: Production Ready

For issues or questions, refer to the troubleshooting section or consult the comprehensive documentation.
