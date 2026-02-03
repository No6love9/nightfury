#!/usr/bin/env python3

"""
NightFury Framework v2.0 - Universal Setup Utility
Cross-platform installation, configuration, and verification
Supports: Linux, macOS, Windows
"""

import os
import sys
import json
import platform
import subprocess
import shutil
from pathlib import Path
from typing import Optional, Dict, List
import argparse

# Color codes for output
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    NC = '\033[0m'

# Logging functions
def log_info(message: str) -> None:
    """Log informational message."""
    print(f"{Colors.BLUE}[*]{Colors.NC} {message}")

def log_success(message: str) -> None:
    """Log success message."""
    print(f"{Colors.GREEN}[+]{Colors.NC} {message}")

def log_error(message: str) -> None:
    """Log error message."""
    print(f"{Colors.RED}[X]{Colors.NC} {message}")

def log_warning(message: str) -> None:
    """Log warning message."""
    print(f"{Colors.YELLOW}[!]{Colors.NC} {message}")

def log_section(title: str) -> None:
    """Log section header."""
    print(f"\n{Colors.CYAN}{'=' * 64}{Colors.NC}")
    print(f"{Colors.CYAN}{title}{Colors.NC}")
    print(f"{Colors.CYAN}{'=' * 64}{Colors.NC}\n")

# System detection
class SystemInfo:
    """Detect and store system information."""
    
    def __init__(self):
        self.system = platform.system()
        self.release = platform.release()
        self.version = platform.version()
        self.python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        self.is_windows = self.system == "Windows"
        self.is_macos = self.system == "Darwin"
        self.is_linux = self.system == "Linux"
    
    def print_info(self) -> None:
        """Print system information."""
        log_section("System Information")
        log_success(f"OS: {self.system} {self.release}")
        log_success(f"Python: {self.python_version}")
        log_success(f"Architecture: {platform.machine()}")

# Framework setup
class FrameworkSetup:
    """Handle NightFury framework setup."""
    
    def __init__(self, venv_name: str = "nightfury_env"):
        self.venv_name = venv_name
        self.venv_path = Path(venv_name)
        self.sys_info = SystemInfo()
        self.config = {}
    
    def check_python_version(self) -> bool:
        """Check if Python version meets requirements."""
        log_section("Python Version Check")
        
        if sys.version_info < (3, 8):
            log_error(f"Python 3.8+ required, found: {self.sys_info.python_version}")
            return False
        
        log_success(f"Python {self.sys_info.python_version} found")
        return True
    
    def check_command(self, command: str) -> bool:
        """Check if a command exists in PATH."""
        return shutil.which(command) is not None
    
    def run_command(self, command: List[str], check: bool = True) -> bool:
        """Run a shell command."""
        try:
            result = subprocess.run(command, check=check, capture_output=True, text=True)
            if result.returncode != 0 and check:
                log_error(f"Command failed: {' '.join(command)}")
                if result.stderr:
                    log_error(result.stderr)
                return False
            return True
        except Exception as e:
            log_error(f"Error running command: {e}")
            return False
    
    def create_venv(self) -> bool:
        """Create virtual environment."""
        log_section("Virtual Environment Setup")
        
        if self.venv_path.exists():
            log_warning("Virtual environment already exists")
            response = input("Remove and recreate? (y/n): ").lower()
            if response == 'y':
                shutil.rmtree(self.venv_path)
                log_info("Creating new virtual environment...")
                return self.run_command([sys.executable, "-m", "venv", self.venv_name])
            return True
        
        log_info("Creating virtual environment...")
        success = self.run_command([sys.executable, "-m", "venv", self.venv_name])
        if success:
            log_success(f"Virtual environment created at: {self.venv_name}")
        return success
    
    def get_pip_command(self) -> List[str]:
        """Get pip command for current platform."""
        if self.sys_info.is_windows:
            return [str(self.venv_path / "Scripts" / "pip.exe")]
        else:
            return [str(self.venv_path / "bin" / "pip")]
    
    def get_python_command(self) -> List[str]:
        """Get python command for current platform."""
        if self.sys_info.is_windows:
            return [str(self.venv_path / "Scripts" / "python.exe")]
        else:
            return [str(self.venv_path / "bin" / "python")]
    
    def upgrade_pip(self) -> bool:
        """Upgrade pip, setuptools, and wheel."""
        log_section("Pip Upgrade")
        
        pip_cmd = self.get_pip_command()
        log_info("Upgrading pip, setuptools, and wheel...")
        return self.run_command(pip_cmd + ["install", "--upgrade", "pip", "setuptools", "wheel"])
    
    def install_dependencies(self) -> bool:
        """Install Python dependencies from requirements.txt."""
        log_section("Python Dependencies Installation")
        
        if not Path("requirements.txt").exists():
            log_error("requirements.txt not found")
            return False
        
        pip_cmd = self.get_pip_command()
        log_info("Installing Python packages from requirements.txt...")
        return self.run_command(pip_cmd + ["install", "-r", "requirements.txt"])
    
    def create_directories(self) -> bool:
        """Create necessary directories."""
        log_section("Directory Structure")
        
        directories = ["nightfury_reports", "nightfury_logs", "nightfury_data"]
        log_info("Creating directories...")
        
        for directory in directories:
            Path(directory).mkdir(exist_ok=True)
        
        log_success("Directories created")
        return True
    
    def create_config(self) -> bool:
        """Create configuration file."""
        log_section("Configuration Setup")
        
        config_path = Path("nightfury_config.json")
        if config_path.exists():
            log_warning("Configuration file already exists")
            return True
        
        config = {
            "framework": {
                "version": "2.0",
                "mode": "balanced",
                "threads": 8,
                "timeout": 300,
                "max_retries": 3
            },
            "reporting": {
                "output_dir": "./nightfury_reports",
                "auto_save": True,
                "formats": ["html", "json", "csv"],
                "include_screenshots": True
            },
            "gui": {
                "theme": "dark",
                "window_width": 1600,
                "window_height": 950,
                "auto_save_interval": 300
            },
            "security": {
                "proxy_rotation": True,
                "evasion_enabled": True,
                "cache_enabled": True,
                "cache_size_mb": 1024,
                "ssl_verify": False
            },
            "logging": {
                "level": "INFO",
                "format": "json",
                "rotation": "10 MB",
                "retention": "30 days"
            },
            "ai": {
                "provider": "gemini",
                "auto_analysis": True,
                "confidence_threshold": 0.85
            }
        }
        
        log_info("Creating configuration file...")
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        log_success("Configuration file created")
        self.config = config
        return True
    
    def setup_gemini(self) -> bool:
        """Setup Google Gemini AI integration."""
        log_section("Google Gemini AI Setup (Optional)")
        
        response = input("Do you want to set up Google Gemini AI? (y/n): ").lower()
        
        if response != 'y':
            return True
        
        print("\nGetting your Gemini API key:")
        print("  1. Visit: https://aistudio.google.com/app/apikeys")
        print("  2. Click 'Create API Key'")
        print("  3. Copy your API key\n")
        
        api_key = input("Enter your Gemini API key (or press Enter to skip): ").strip()
        
        if api_key:
            os.environ['GEMINI_API_KEY'] = api_key
            
            # Add to activation script
            if self.sys_info.is_windows:
                activate_script = self.venv_path / "Scripts" / "activate.bat"
                with open(activate_script, 'a') as f:
                    f.write(f"\nset GEMINI_API_KEY={api_key}\n")
            else:
                activate_script = self.venv_path / "bin" / "activate"
                with open(activate_script, 'a') as f:
                    f.write(f"\nexport GEMINI_API_KEY='{api_key}'\n")
            
            log_success("Gemini API key configured")
        else:
            log_warning("Gemini API key skipped")
        
        return True
    
    def verify_installation(self) -> bool:
        """Verify installation by running verification script."""
        log_section("Installation Verification")
        
        if not Path("verify_installation.py").exists():
            log_warning("verify_installation.py not found, skipping verification")
            return True
        
        log_info("Running installation verification...")
        python_cmd = self.get_python_command()
        return self.run_command(python_cmd + ["verify_installation.py"], check=False)
    
    def create_startup_script(self) -> bool:
        """Create startup script for the framework."""
        log_section("Startup Script Creation")
        
        log_info("Creating startup script...")
        
        if self.sys_info.is_windows:
            script_name = "start_nightfury.bat"
            script_content = f"""@echo off
call {self.venv_name}\\Scripts\\activate.bat
python nightfury_gui_gemini.py
"""
        else:
            script_name = "start_nightfury.sh"
            script_content = f"""#!/bin/bash
source {self.venv_name}/bin/activate
python3 nightfury_gui_gemini.py
"""
        
        with open(script_name, 'w') as f:
            f.write(script_content)
        
        if not self.sys_info.is_windows:
            os.chmod(script_name, 0o755)
        
        log_success(f"Startup script created: {script_name}")
        return True
    
    def print_post_install_info(self) -> None:
        """Print post-installation information."""
        log_section("Installation Complete!")
        
        print(f"{Colors.GREEN}NightFury Framework v2.0 is ready to use!{Colors.NC}\n")
        print("Next steps:\n")
        
        if self.sys_info.is_windows:
            print(f"1. Activate virtual environment:")
            print(f"   {self.venv_name}\\Scripts\\activate.bat\n")
            print(f"2. Start GUI Dashboard:")
            print(f"   python nightfury_gui_gemini.py\n")
        else:
            print(f"1. Activate virtual environment:")
            print(f"   source {self.venv_name}/bin/activate\n")
            print(f"2. Start GUI Dashboard:")
            print(f"   python3 nightfury_gui_gemini.py\n")
        
        print("3. Or use quick commands:")
        print("   python runehall_quick_commands.py list\n")
        print("4. Generate reports:")
        print("   python nightfury_reporting_engine.py\n")
        
        print("Documentation:")
        print("   - Quick Reference: RUNEHALL_QUICK_REFERENCE.md")
        print("   - Gemini Setup: GEMINI_SETUP.md")
        print("   - Installation: INSTALLATION_GUIDE.md")
        print("   - Pentesting Guide: nightfury_pentesting_guide.md\n")
        
        print("Repository: https://github.com/No6love9/nightfury\n")
    
    def run_setup(self) -> bool:
        """Run complete setup process."""
        print(f"\n{Colors.CYAN}")
        print("╔════════════════════════════════════════════════════════════════╗")
        print("║                                                                ║")
        print("║          NightFury Framework v2.0 - Setup Wizard               ║")
        print("║                                                                ║")
        print("║     Professional Penetration Testing Platform                 ║")
        print("║     with Google Gemini AI Integration                         ║")
        print("║                                                                ║")
        print("╚════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.NC}\n")
        
        self.sys_info.print_info()
        
        steps = [
            ("Python Version Check", self.check_python_version),
            ("Virtual Environment", self.create_venv),
            ("Pip Upgrade", self.upgrade_pip),
            ("Install Dependencies", self.install_dependencies),
            ("Create Directories", self.create_directories),
            ("Configuration Setup", self.create_config),
            ("Gemini AI Setup", self.setup_gemini),
            ("Installation Verification", self.verify_installation),
            ("Startup Script", self.create_startup_script),
        ]
        
        for step_name, step_func in steps:
            try:
                if not step_func():
                    log_error(f"{step_name} failed")
                    return False
            except Exception as e:
                log_error(f"{step_name} error: {e}")
                return False
        
        self.print_post_install_info()
        log_success("Setup completed successfully!")
        return True

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="NightFury Framework v2.0 - Universal Setup Utility"
    )
    parser.add_argument(
        "--venv",
        default="nightfury_env",
        help="Virtual environment name (default: nightfury_env)"
    )
    parser.add_argument(
        "--skip-verification",
        action="store_true",
        help="Skip installation verification"
    )
    
    args = parser.parse_args()
    
    setup = FrameworkSetup(venv_name=args.venv)
    success = setup.run_setup()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
