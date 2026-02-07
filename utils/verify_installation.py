#!/usr/bin/env python3
"""
NightFury Framework Installation Verification
Checks all required packages and dependencies
"""

import sys
import subprocess
from typing import Dict, List, Tuple

class InstallationVerifier:
    """Verifies NightFury framework installation"""
    
    def __init__(self):
        self.results = {
            "installed": [],
            "missing": [],
            "errors": []
        }
        self.package_groups = self._define_package_groups()
    
    def _define_package_groups(self) -> Dict:
        """Define package groups and their import names"""
        return {
            "Core Framework": {
                "requests": "requests",
                "urllib3": "urllib3",
                "aiohttp": "aiohttp",
                "flask": "flask",
                "fastapi": "fastapi"
            },
            "Networking": {
                "scapy": "scapy",
                "dnspython": "dns",
                "paramiko": "paramiko",
                "websocket-client": "websocket"
            },
            "Security & Cryptography": {
                "cryptography": "cryptography",
                "pycryptodome": "Crypto",
                "PyNaCl": "nacl",
                "bcrypt": "bcrypt"
            },
            "Data Processing": {
                "pandas": "pandas",
                "numpy": "numpy",
                "scipy": "scipy",
                "scikit-learn": "sklearn"
            },
            "Visualization": {
                "matplotlib": "matplotlib",
                "seaborn": "seaborn",
                "plotly": "plotly",
                "bokeh": "bokeh"
            },
            "Database": {
                "sqlalchemy": "sqlalchemy",
                "pymongo": "pymongo",
                "redis": "redis",
                "elasticsearch": "elasticsearch"
            },
            "Machine Learning": {
                "tensorflow": "tensorflow",
                "torch": "torch",
                "xgboost": "xgboost",
                "lightgbm": "lightgbm"
            },
            "GUI & Web": {
                "PyQt5": "PyQt5",
                "dash": "dash",
                "streamlit": "streamlit",
                "gradio": "gradio"
            },
            "Reporting": {
                "reportlab": "reportlab",
                "fpdf2": "fpdf2",
                "weasyprint": "weasyprint",
                "python-docx": "docx"
            },
            "Utilities": {
                "click": "click",
                "colorama": "colorama",
                "rich": "rich",
                "loguru": "loguru"
            }
        }
    
    def verify_package(self, package_name: str, import_name: str) -> Tuple[bool, str]:
        """Verify if a package is installed"""
        try:
            __import__(import_name)
            return True, "✓"
        except ImportError:
            return False, "✗"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def verify_python_version(self) -> bool:
        """Verify Python version is 3.8+"""
        version = sys.version_info
        if version.major >= 3 and version.minor >= 8:
            print(f"[✓] Python Version: {version.major}.{version.minor}.{version.micro}")
            return True
        else:
            print(f"[✗] Python Version: {version.major}.{version.minor} (Required: 3.8+)")
            return False
    
    def verify_pip(self) -> bool:
        """Verify pip is available"""
        try:
            subprocess.run(["pip", "--version"], capture_output=True, check=True)
            print("[✓] pip is available")
            return True
        except Exception as e:
            print(f"[✗] pip is not available: {e}")
            return False
    
    def verify_all_packages(self) -> None:
        """Verify all packages"""
        print("\n" + "="*80)
        print("NIGHTFURY FRAMEWORK - INSTALLATION VERIFICATION")
        print("="*80 + "\n")
        
        # Check Python version
        self.verify_python_version()
        
        # Check pip
        self.verify_pip()
        
        print("\n" + "-"*80)
        print("PACKAGE VERIFICATION")
        print("-"*80 + "\n")
        
        total_packages = 0
        installed_count = 0
        
        for group, packages in self.package_groups.items():
            print(f"\n[{group}]")
            print("-" * 40)
            
            for package_name, import_name in packages.items():
                total_packages += 1
                is_installed, status = self.verify_package(package_name, import_name)
                
                if is_installed:
                    installed_count += 1
                    self.results["installed"].append(package_name)
                    print(f"  {status} {package_name:<25} {import_name}")
                else:
                    self.results["missing"].append(package_name)
                    print(f"  {status} {package_name:<25} {import_name}")
        
        # Print summary
        print("\n" + "="*80)
        print("VERIFICATION SUMMARY")
        print("="*80 + "\n")
        
        print(f"Total Packages Checked: {total_packages}")
        print(f"Installed: {installed_count}")
        print(f"Missing: {len(self.results['missing'])}")
        
        if self.results["missing"]:
            print(f"\n[!] Missing Packages:")
            for pkg in self.results["missing"]:
                print(f"    - {pkg}")
            print(f"\n[*] Install missing packages with:")
            print(f"    pip install {' '.join(self.results['missing'])}")
        else:
            print("\n[✓] All packages are installed!")
        
        # Calculate coverage
        coverage = (installed_count / total_packages) * 100
        print(f"\n[*] Installation Coverage: {coverage:.1f}%")
        
        if coverage >= 90:
            print("[✓] Framework is ready for operation!")
            return True
        elif coverage >= 70:
            print("[!] Framework is partially operational. Install missing packages for full functionality.")
            return True
        else:
            print("[✗] Framework is not ready. Please install missing packages.")
            return False
    
    def generate_install_command(self) -> str:
        """Generate pip install command for missing packages"""
        if not self.results["missing"]:
            return "All packages are installed!"
        
        return f"pip install {' '.join(self.results['missing'])}"
    
    def check_system_dependencies(self) -> None:
        """Check for system-level dependencies"""
        print("\n" + "-"*80)
        print("SYSTEM DEPENDENCIES")
        print("-"*80 + "\n")
        
        # Check for common system packages
        system_packages = {
            "gcc": "GCC Compiler",
            "python3-dev": "Python Development Headers",
            "libssl-dev": "OpenSSL Development",
            "libffi-dev": "FFI Development"
        }
        
        print("[*] System dependencies (Linux/Debian):")
        print("    sudo apt-get install python3-dev libssl-dev libffi-dev")
        print("\n[*] System dependencies (macOS):")
        print("    brew install python3 openssl libffi")
        print("\n[*] System dependencies (Windows):")
        print("    Install Visual C++ Build Tools from Microsoft")

def main():
    """Main entry point"""
    verifier = InstallationVerifier()
    
    # Verify all packages
    verifier.verify_all_packages()
    
    # Check system dependencies
    verifier.check_system_dependencies()
    
    # Print installation command if needed
    print("\n" + "="*80)
    print("INSTALLATION COMMAND")
    print("="*80 + "\n")
    print(f"[*] {verifier.generate_install_command()}")
    
    print("\n" + "="*80)
    print("NEXT STEPS")
    print("="*80 + "\n")
    
    if verifier.results["missing"]:
        print("1. Install missing packages:")
        print(f"   {verifier.generate_install_command()}")
        print("\n2. Run verification again:")
        print("   python verify_installation.py")
        print("\n3. Start NightFury GUI:")
        print("   python nightfury_gui.py")
    else:
        print("1. Start NightFury GUI:")
        print("   python nightfury_gui.py")
        print("\n2. Or use quick commands:")
        print("   python runehall_quick_commands.py list")
        print("\n3. Or use exploitation chains:")
        print("   python runehall_exploitation_chains.py list")
    
    print("\n" + "="*80 + "\n")

if __name__ == "__main__":
    main()
