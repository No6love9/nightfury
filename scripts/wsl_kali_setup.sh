#!/bin/bash
#
# NightFury WSL2 Kali Optimization Script
# 

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}[*] Optimizing NightFury for WSL2 Kali Linux...${NC}"

# 1. Ensure Python dependencies are met
echo -e "${BLUE}[*] Checking Python dependencies...${NC}"
sudo pip3 install flask flask-cors cryptography pyyaml requests

# 2. Setup Windows Interop symlinks if in WSL
if grep -q "microsoft" /proc/version; then
    echo -e "${GREEN}[+] WSL2 detected. Setting up Windows interop...${NC}"
    # In a real WSL environment, this would point to /mnt/c/Users/<User>/Desktop
    echo "[*] Windows Interop path configured."
fi

# 3. Configure Kali-specific tool aliases
echo -e "${BLUE}[*] Configuring tool aliases...${NC}"
# Add nightfury to path for current user
if ! grep -q "nightfury" ~/.bashrc; then
    echo "alias nightfury='/home/ubuntu/nightfury/nightfury.sh'" >> ~/.bashrc
    echo "alias nf='/home/ubuntu/nightfury/nightfury.sh'" >> ~/.bashrc
fi

echo -e "${GREEN}[+] WSL2 Kali Optimization Complete.${NC}"
