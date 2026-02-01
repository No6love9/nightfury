#!/usr/bin/env python3
import json
import os

class CrackPrep:
    """
    Formats harvested credentials for password cracking tools.
    Supports Hashcat, John the Ripper, and custom wordlist generation.
    """
    def __init__(self, log_path="/home/ubuntu/nightfury/logs/harvested_creds.json"):
        self.log_path = log_path

    def extract_passwords(self):
        """Extracts unique passwords for wordlist generation."""
        passwords = set()
        if not os.path.exists(self.log_path):
            return []
            
        with open(self.log_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    pwd = entry.get('data', {}).get('p')
                    if pwd:
                        passwords.add(pwd)
                except json.JSONDecodeError:
                    continue
        return sorted(list(passwords))

    def format_for_john(self, output_file):
        """Formats credentials as user:pass for John the Ripper."""
        count = 0
        with open(output_file, 'w') as out, open(self.log_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    user = entry.get('data', {}).get('u', 'unknown')
                    pwd = entry.get('data', {}).get('p')
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
