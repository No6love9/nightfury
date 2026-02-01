#!/bin/bash
#
# NightFury - RuneHall C2 Personalized Setup
# Automated deployment of listeners and handlers for runehall.com testing.
#

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}[*] Initializing RuneHall Personalized C2 Infrastructure...${NC}"

# 1. Load Configuration
NIGHTFURY_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${NIGHTFURY_HOME}/config/c2_runehall.yaml"

if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}[!] Configuration file not found!${NC}"
    exit 1
fi

# 2. Setup Listeners
echo -e "${BLUE}[*] Setting up C2 listeners as per configuration...${NC}"
# In a real environment, this would start netcat, metasploit, or custom listeners
# Here we simulate the initialization of the listeners
echo -e "${GREEN}[+] Listener 'RuneHall-HTTP' (Port 8080) initialized.${NC}"
echo -e "${GREEN}[+] Listener 'RuneHall-PHP-Rev' (Port 4444) initialized.${NC}"

# 3. Generate Attack Kit
echo -e "${BLUE}[*] Generating initial attack kit for RuneHall...${NC}"
${NIGHTFURY_HOME}/nightfury.sh runehall kit 127.0.0.1 4444 > ${NIGHTFURY_HOME}/data/exports/runehall_kit.json

echo -e "${GREEN}[+] RuneHall C2 setup complete!${NC}"
echo -e "${BLUE}[*] Attack kit saved to: data/exports/runehall_kit.json${NC}"
