#!/bin/bash
#
# NightFury Framework - WSL2 Kali One-Click Deployment
# Optimized for high-performance and automated configuration.
#

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}[*] NightFury One-Click Deployment for WSL2 Kali${NC}"

# 1. System Update
echo -e "${BLUE}[*] Updating system packages...${NC}"
sudo apt-get update && sudo apt-get upgrade -y

# 2. Install Essential Tools
echo -e "${BLUE}[*] Installing core dependencies...${NC}"
sudo apt-get install -y python3-pip git curl wget net-tools dnsutils nmap

# 3. Setup Python Environment
echo -e "${BLUE}[*] Configuring Python environment...${NC}"
pip3 install pyyaml requests python-dotenv colorama tabulate tqdm beautifulsoup4

# 4. Framework Initialization
echo -e "${BLUE}[*] Initializing NightFury Framework...${NC}"
chmod +x nightfury.sh
./nightfury.sh health

# 5. Add Alias to Bashrc
if ! grep -q "alias nf=" ~/.bashrc; then
    echo "alias nf='/home/$(whoami)/nightfury/nightfury.sh'" >> ~/.bashrc
    echo "alias nightfury='/home/$(whoami)/nightfury/nightfury.sh'" >> ~/.bashrc
    echo -e "${GREEN}[+] Aliases added (nf, nightfury)${NC}"
fi

echo -e "${GREEN}[+] Deployment Complete!${NC}"
echo -e "${BLUE}[*] Restart your terminal or run 'source ~/.bashrc' to start.${NC}"
echo -e "${BLUE}[*] Type 'nf help' to begin.${NC}"
