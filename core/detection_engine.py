#!/usr/bin/env python3
"""
NightFury Detection Engine
Comprehensive environment detection with intelligent fallbacks
"""

import os
import sys
import platform
import subprocess
import json
import socket
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

class EnvironmentDetector:
    """Comprehensive environment analysis with fallback mechanisms"""
    
    def __init__(self, log_file: str = "/tmp/nightfury_detection.log"):
        self.detection_results: Dict[str, Any] = {}
        self.fallbacks_activated: List[str] = []
        self.log_file = log_file
        self.warnings: List[str] = []
        
    def detect_all(self) -> Dict[str, Any]:
        """Execute all detection routines with error handling"""
        detectors = [
            ("WSL Version", self._detect_wsl_version),
            ("Network Stack", self._detect_network_stack),
            ("VPN Status", self._detect_vpn_status),
            ("Firewall Rules", self._detect_firewall_rules),
            ("System Resources", self._detect_system_resources),
            ("Kali Tools", self._detect_kali_tools),
            ("Python Environment", self._detect_python_environment),
        ]
        
        for name, detector in detectors:
            try:
                self._log(f"Running detector: {name}")
                detector()
                self._log(f"✓ {name} detection completed")
            except Exception as e:
                self._log_error(f"✗ {name} detection failed: {str(e)}")
                self._activate_fallback(detector.__name__)
        
        return self._generate_environment_profile()
    
    def _detect_wsl_version(self) -> None:
        """Precisely identify WSL1 vs WSL2 vs Native Linux"""
        uname = platform.uname()
        
        # Method 1: Check /proc/version
        try:
            with open('/proc/version', 'r') as f:
                content = f.read().lower()
                if 'microsoft' in content:
                    if 'wsl2' in content:
                        self.detection_results['wsl_version'] = 'WSL2'
                    else:
                        self.detection_results['wsl_version'] = 'WSL1'
                    self.detection_results['wsl_kernel'] = uname.release
                else:
                    self.detection_results['wsl_version'] = 'Native Linux'
        except FileNotFoundError:
            self.detection_results['wsl_version'] = 'Unknown'
        
        # Method 2: Check for systemd (WSL2 specific)
        try:
            result = subprocess.run(
                ['systemctl', '--version'],
                capture_output=True,
                timeout=2
            )
            self.detection_results['systemd_present'] = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.detection_results['systemd_present'] = False
        
        # Method 3: Check for Windows mount points
        self.detection_results['windows_mounts'] = []
        if os.path.exists('/mnt/c'):
            self.detection_results['windows_mounts'].append('/mnt/c')
            # Detect Windows username
            try:
                users_path = Path('/mnt/c/Users')
                if users_path.exists():
                    users = [u.name for u in users_path.iterdir() if u.is_dir() 
                            and u.name not in ['Public', 'Default', 'Default User']]
                    self.detection_results['windows_users'] = users
            except Exception:
                pass
        
        # Set environment-specific configurations
        self._configure_wsl_specific()
    
    def _configure_wsl_specific(self) -> None:
        """Apply WSL-specific optimizations"""
        wsl_version = self.detection_results.get('wsl_version', 'Unknown')
        
        if wsl_version == 'WSL2':
            self._log("Applying WSL2-specific configurations")
            
            # Check DNS configuration
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    dns_config = f.read()
                    self.detection_results['dns_servers'] = [
                        line.split()[1] for line in dns_config.split('\n')
                        if line.startswith('nameserver')
                    ]
            except Exception:
                pass
            
        elif wsl_version == 'WSL1':
            self._log("Detected WSL1 - some features may be limited")
            self.warnings.append("WSL1 detected: Consider upgrading to WSL2 for better performance")
    
    def _detect_network_stack(self) -> None:
        """Complete network configuration detection"""
        # Get all network interfaces
        self.detection_results['interfaces'] = {}
        
        try:
            result = subprocess.run(
                ['ip', '-j', 'addr', 'show'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                interfaces = json.loads(result.stdout)
                for iface in interfaces:
                    self.detection_results['interfaces'][iface['ifname']] = {
                        'state': iface.get('operstate', 'unknown'),
                        'addresses': [
                            addr['local'] for addr in iface.get('addr_info', [])
                        ]
                    }
        except Exception as e:
            self._log_error(f"Failed to parse network interfaces: {e}")
            self._fallback_network_detection()
        
        # Detect public IP
        self._detect_public_ip()
        
        # Detect default gateway
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout:
                parts = result.stdout.split()
                if 'via' in parts:
                    gateway_idx = parts.index('via') + 1
                    self.detection_results['default_gateway'] = parts[gateway_idx]
        except Exception:
            pass
    
    def _detect_public_ip(self) -> None:
        """Detect public IP with multiple fallback services"""
        ip_services = [
            'https://api.ipify.org?format=json',
            'https://ifconfig.me/ip',
            'https://ident.me',
            'https://ipinfo.io/ip'
        ]
        
        public_ip = None
        for service in ip_services:
            try:
                import urllib.request
                with urllib.request.urlopen(service, timeout=3) as response:
                    data = response.read().decode('utf-8').strip()
                    # Try to parse as JSON first
                    try:
                        json_data = json.loads(data)
                        public_ip = json_data.get('ip', data)
                    except json.JSONDecodeError:
                        public_ip = data
                    
                    if public_ip:
                        break
            except Exception:
                continue
        
        self.detection_results['public_ip'] = public_ip or 'Unknown'
    
    def _detect_vpn_status(self) -> None:
        """Identify active VPNs and proxies"""
        vpn_indicators = []
        
        # Check for OpenVPN
        try:
            result = subprocess.run(
                ['pgrep', '-x', 'openvpn'],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0:
                vpn_indicators.append('OpenVPN')
        except Exception:
            pass
        
        # Check for WireGuard
        try:
            result = subprocess.run(
                ['wg', 'show'],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.stdout.strip():
                vpn_indicators.append('WireGuard')
        except Exception:
            pass
        
        # Check for TUN/TAP devices
        try:
            result = subprocess.run(
                ['ip', 'link', 'show'],
                capture_output=True,
                text=True,
                timeout=2
            )
            if 'tun' in result.stdout or 'tap' in result.stdout:
                vpn_indicators.append('TUN/TAP Device')
        except Exception:
            pass
        
        # Check for common VPN processes
        vpn_processes = ['nordvpn', 'expressvpn', 'protonvpn', 'mullvad']
        for vpn in vpn_processes:
            try:
                result = subprocess.run(
                    ['pgrep', '-i', vpn],
                    capture_output=True,
                    timeout=2
                )
                if result.returncode == 0:
                    vpn_indicators.append(vpn.capitalize())
            except Exception:
                pass
        
        self.detection_results['vpn_active'] = bool(vpn_indicators)
        self.detection_results['vpn_types'] = vpn_indicators
    
    def _detect_firewall_rules(self) -> None:
        """Enumerate firewall configuration"""
        firewall_info = {}
        
        # Check iptables
        try:
            result = subprocess.run(
                ['sudo', '-n', 'iptables', '-L', '-n'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                firewall_info['iptables'] = 'active'
                firewall_info['iptables_rules_count'] = len(result.stdout.split('\n'))
            else:
                firewall_info['iptables'] = 'no_sudo_access'
        except Exception:
            firewall_info['iptables'] = 'not_available'
        
        # Check ufw
        try:
            result = subprocess.run(
                ['sudo', '-n', 'ufw', 'status'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                if 'active' in result.stdout.lower():
                    firewall_info['ufw'] = 'active'
                else:
                    firewall_info['ufw'] = 'inactive'
        except Exception:
            firewall_info['ufw'] = 'not_available'
        
        self.detection_results['firewall'] = firewall_info
    
    def _detect_system_resources(self) -> None:
        """Detect system resources and capabilities"""
        resources = {}
        
        # CPU information
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
                cpu_count = cpuinfo.count('processor')
                resources['cpu_cores'] = cpu_count
                
                # Extract CPU model
                for line in cpuinfo.split('\n'):
                    if 'model name' in line:
                        resources['cpu_model'] = line.split(':')[1].strip()
                        break
        except Exception:
            pass
        
        # Memory information
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
                for line in meminfo.split('\n'):
                    if 'MemTotal' in line:
                        mem_kb = int(line.split()[1])
                        resources['memory_total_gb'] = round(mem_kb / 1024 / 1024, 2)
                    elif 'MemAvailable' in line:
                        mem_kb = int(line.split()[1])
                        resources['memory_available_gb'] = round(mem_kb / 1024 / 1024, 2)
        except Exception:
            pass
        
        # Disk space
        try:
            result = subprocess.run(
                ['df', '-h', '/'],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                if len(lines) > 1:
                    parts = lines[1].split()
                    resources['disk_total'] = parts[1]
                    resources['disk_used'] = parts[2]
                    resources['disk_available'] = parts[3]
                    resources['disk_usage_percent'] = parts[4]
        except Exception:
            pass
        
        self.detection_results['system_resources'] = resources
    
    def _detect_kali_tools(self) -> None:
        """Detect installed Kali Linux tools"""
        common_tools = [
            'nmap', 'metasploit-framework', 'sqlmap', 'nikto', 'hydra',
            'john', 'hashcat', 'aircrack-ng', 'wireshark', 'burpsuite',
            'gobuster', 'ffuf', 'wfuzz', 'masscan', 'amass', 'subfinder',
            'nuclei', 'httpx', 'dnsx', 'naabu'
        ]
        
        installed_tools = []
        for tool in common_tools:
            try:
                result = subprocess.run(
                    ['which', tool],
                    capture_output=True,
                    timeout=1
                )
                if result.returncode == 0:
                    installed_tools.append(tool)
            except Exception:
                pass
        
        self.detection_results['kali_tools'] = {
            'installed': installed_tools,
            'count': len(installed_tools),
            'missing': list(set(common_tools) - set(installed_tools))
        }
    
    def _detect_python_environment(self) -> None:
        """Detect Python environment and packages"""
        python_info = {
            'version': sys.version,
            'executable': sys.executable,
            'platform': sys.platform
        }
        
        # Check for common packages
        required_packages = [
            'requests', 'beautifulsoup4', 'flask', 'socketio',
            'cryptography', 'paramiko', 'scapy', 'pyyaml'
        ]
        
        installed_packages = []
        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
                installed_packages.append(package)
            except ImportError:
                pass
        
        python_info['installed_packages'] = installed_packages
        python_info['missing_packages'] = list(set(required_packages) - set(installed_packages))
        
        self.detection_results['python'] = python_info
    
    def _activate_fallback(self, failed_component: str) -> None:
        """Activate appropriate fallback mechanisms"""
        fallback_strategies = {
            '_detect_wsl_version': self._fallback_wsl_detection,
            '_detect_network_stack': self._fallback_network_detection,
            '_detect_vpn_status': self._fallback_vpn_detection
        }
        
        if failed_component in fallback_strategies:
            try:
                fallback_strategies[failed_component]()
                self.fallbacks_activated.append(failed_component)
                self._log(f"✓ Fallback activated for {failed_component}")
            except Exception as e:
                self._log_error(f"✗ Fallback failed for {failed_component}: {e}")
    
    def _fallback_wsl_detection(self) -> None:
        """Fallback WSL detection method"""
        if os.path.exists('/mnt/c/Windows'):
            self.detection_results['wsl_version'] = 'WSL (version unknown)'
        else:
            self.detection_results['wsl_version'] = 'Native Linux'
    
    def _fallback_network_detection(self) -> None:
        """Fallback network detection using basic methods"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            self.detection_results['hostname'] = hostname
            self.detection_results['local_ip'] = local_ip
        except Exception:
            pass
    
    def _fallback_vpn_detection(self) -> None:
        """Fallback VPN detection"""
        self.detection_results['vpn_active'] = False
        self.detection_results['vpn_types'] = []
    
    def _generate_environment_profile(self) -> Dict[str, Any]:
        """Generate complete environment profile"""
        profile = {
            'timestamp': datetime.now().isoformat(),
            'environment': self.detection_results,
            'fallbacks_used': self.fallbacks_activated,
            'warnings': self.warnings,
            'recommendations': self._generate_recommendations(),
            'compatibility_score': self._calculate_compatibility_score()
        }
        
        return profile
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on detection results"""
        recommendations = []
        
        # WSL recommendations
        wsl_version = self.detection_results.get('wsl_version', 'Unknown')
        if wsl_version == 'WSL1':
            recommendations.append("Upgrade to WSL2 for better performance and compatibility")
        
        # Tool recommendations
        kali_tools = self.detection_results.get('kali_tools', {})
        missing_tools = kali_tools.get('missing', [])
        if len(missing_tools) > 5:
            recommendations.append(f"Install missing Kali tools: {', '.join(missing_tools[:5])}")
        
        # Python package recommendations
        python_info = self.detection_results.get('python', {})
        missing_packages = python_info.get('missing_packages', [])
        if missing_packages:
            recommendations.append(f"Install Python packages: pip3 install {' '.join(missing_packages)}")
        
        # Resource recommendations
        resources = self.detection_results.get('system_resources', {})
        mem_available = resources.get('memory_available_gb', 0)
        if mem_available < 2:
            recommendations.append("Low memory detected: Consider closing other applications")
        
        # VPN recommendations
        if not self.detection_results.get('vpn_active', False):
            recommendations.append("No VPN detected: Consider using VPN for operational security")
        
        return recommendations
    
    def _calculate_compatibility_score(self) -> int:
        """Calculate overall compatibility score (0-100)"""
        score = 100
        
        # Deduct points for issues
        if self.detection_results.get('wsl_version') == 'WSL1':
            score -= 10
        
        if not self.detection_results.get('systemd_present', False):
            score -= 5
        
        kali_tools = self.detection_results.get('kali_tools', {})
        missing_count = len(kali_tools.get('missing', []))
        score -= min(missing_count * 2, 20)
        
        python_info = self.detection_results.get('python', {})
        missing_packages = len(python_info.get('missing_packages', []))
        score -= min(missing_packages * 5, 20)
        
        if self.fallbacks_activated:
            score -= len(self.fallbacks_activated) * 5
        
        return max(0, score)
    
    def _log(self, message: str) -> None:
        """Log message to file"""
        try:
            with open(self.log_file, 'a') as f:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                f.write(f"[{timestamp}] {message}\n")
        except Exception:
            pass
    
    def _log_error(self, message: str) -> None:
        """Log error message"""
        self._log(f"ERROR: {message}")
        print(f"[!] {message}", file=sys.stderr)
    
    def save_profile(self, output_file: str) -> None:
        """Save environment profile to JSON file"""
        profile = self._generate_environment_profile()
        with open(output_file, 'w') as f:
            json.dump(profile, f, indent=2)
        self._log(f"Profile saved to {output_file}")
    
    def print_summary(self) -> None:
        """Print human-readable summary"""
        profile = self._generate_environment_profile()
        
        print("\n" + "="*60)
        print("NightFury Environment Detection Summary")
        print("="*60)
        
        print(f"\n[+] WSL Version: {self.detection_results.get('wsl_version', 'Unknown')}")
        print(f"[+] Systemd: {'Yes' if self.detection_results.get('systemd_present') else 'No'}")
        
        resources = self.detection_results.get('system_resources', {})
        print(f"\n[+] CPU Cores: {resources.get('cpu_cores', 'Unknown')}")
        print(f"[+] Memory: {resources.get('memory_total_gb', 'Unknown')} GB total, "
              f"{resources.get('memory_available_gb', 'Unknown')} GB available")
        print(f"[+] Disk Usage: {resources.get('disk_usage_percent', 'Unknown')}")
        
        print(f"\n[+] Public IP: {self.detection_results.get('public_ip', 'Unknown')}")
        print(f"[+] VPN Active: {'Yes' if self.detection_results.get('vpn_active') else 'No'}")
        if self.detection_results.get('vpn_types'):
            print(f"[+] VPN Types: {', '.join(self.detection_results['vpn_types'])}")
        
        kali_tools = self.detection_results.get('kali_tools', {})
        print(f"\n[+] Kali Tools Installed: {kali_tools.get('count', 0)}")
        
        print(f"\n[+] Compatibility Score: {profile['compatibility_score']}/100")
        
        if profile['recommendations']:
            print("\n[!] Recommendations:")
            for i, rec in enumerate(profile['recommendations'], 1):
                print(f"    {i}. {rec}")
        
        if self.warnings:
            print("\n[!] Warnings:")
            for warning in self.warnings:
                print(f"    - {warning}")
        
        print("\n" + "="*60 + "\n")

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='NightFury Environment Detection')
    parser.add_argument('-o', '--output', help='Output JSON file', default=None)
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (JSON only)')
    
    args = parser.parse_args()
    
    detector = EnvironmentDetector()
    profile = detector.detect_all()
    
    if not args.quiet:
        detector.print_summary()
    
    if args.output:
        detector.save_profile(args.output)
        if not args.quiet:
            print(f"[+] Profile saved to {args.output}")
    
    if args.quiet:
        print(json.dumps(profile, indent=2))
    
    # Return exit code based on compatibility score
    sys.exit(0 if profile['compatibility_score'] >= 70 else 1)

if __name__ == '__main__':
    main()
