from core.base_module import BaseModule
import socket

class BasicRecon(BaseModule):
    def __init__(self, framework):
        super().__init__(framework)
        self.name = "basic_recon"
        self.description = "Perform basic network reconnaissance on a target."
        self.options = {"target": ""}

    def run(self, args):
        target = self.options.get('target')
        if args:
            target = args[0]
            
        if not target:
            print("Usage: use basic_recon <target>")
            return
        self.log(f"Starting basic recon on {target}...")
        
        try:
            ip = socket.gethostbyname(target)
            print(f"Target: {target}")
            print(f"IP Address: {ip}")
            
            print("Common ports check:")
            for port in [21, 22, 23, 25, 53, 80, 443, 3306, 8080]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    print(f"  Port {port}: OPEN")
                sock.close()
        except Exception as e:
            self.log(f"Recon failed: {e}", "error")
