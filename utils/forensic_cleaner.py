#!/usr/bin/env python3
"""
NightFury Forensic Cleaner
Anti-forensics and artifact removal utility
"""

import os
import sys
import shutil
import subprocess
import glob
from pathlib import Path
from typing import List, Optional
import logging

class ForensicCleaner:
    """Anti-forensics and artifact removal"""
    
    def __init__(self, log_file: str = "/tmp/forensic_clean.log"):
        self.log_file = log_file
        self.setup_logging()
        self.cleaned_items: List[str] = []
        self.failed_items: List[str] = []
    
    def setup_logging(self):
        """Setup logging"""
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('forensic_cleaner')
    
    def clean_all(self, paranoid: bool = False) -> dict:
        """
        Execute all cleaning operations
        
        Args:
            paranoid: Enable paranoid mode (more aggressive cleaning)
        """
        self.logger.info("Starting forensic cleanup")
        
        operations = [
            ("Bash history", self.clear_bash_history),
            ("Python cache", self.clear_python_cache),
            ("Temp files", self.clear_temp_files),
            ("Log files", self.clear_logs),
            ("Command history", self.clear_command_history),
        ]
        
        if paranoid:
            operations.extend([
                ("Swap files", self.clear_swap),
                ("Memory cache", self.clear_memory_cache),
                ("Recent files", self.clear_recent_files),
            ])
        
        for name, operation in operations:
            try:
                self.logger.info(f"Executing: {name}")
                operation()
                self.cleaned_items.append(name)
            except Exception as e:
                self.logger.error(f"Failed: {name} - {str(e)}")
                self.failed_items.append(f"{name}: {str(e)}")
        
        # Final cleanup
        if paranoid:
            self.secure_delete_log()
        
        return {
            'cleaned': self.cleaned_items,
            'failed': self.failed_items,
            'total': len(operations)
        }
    
    def clear_bash_history(self):
        """Clear bash history"""
        history_files = [
            '~/.bash_history',
            '~/.zsh_history',
            '~/.sh_history',
        ]
        
        for hist_file in history_files:
            expanded = os.path.expanduser(hist_file)
            if os.path.exists(expanded):
                self.secure_delete(expanded)
                # Create empty file
                Path(expanded).touch()
                self.logger.info(f"Cleared: {hist_file}")
    
    def clear_python_cache(self):
        """Clear Python cache files"""
        cache_patterns = [
            '**/__pycache__',
            '**/*.pyc',
            '**/*.pyo',
            '**/.pytest_cache',
        ]
        
        for pattern in cache_patterns:
            for item in glob.glob(pattern, recursive=True):
                try:
                    if os.path.isdir(item):
                        shutil.rmtree(item)
                    else:
                        os.remove(item)
                    self.logger.info(f"Removed: {item}")
                except Exception as e:
                    self.logger.warning(f"Failed to remove {item}: {e}")
    
    def clear_temp_files(self):
        """Clear temporary files"""
        temp_patterns = [
            '/tmp/nightfury_*',
            '/tmp/nf_*',
            '/tmp/*.tmp',
            '~/.cache/nightfury/*',
        ]
        
        for pattern in temp_patterns:
            expanded = os.path.expanduser(pattern)
            for item in glob.glob(expanded):
                try:
                    if os.path.isdir(item):
                        shutil.rmtree(item)
                    else:
                        self.secure_delete(item)
                    self.logger.info(f"Removed: {item}")
                except Exception as e:
                    self.logger.warning(f"Failed to remove {item}: {e}")
    
    def clear_logs(self):
        """Clear log files"""
        log_dirs = [
            '/opt/nightfury/logs',
            '~/.nightfury/logs',
            '.',
        ]
        
        for log_dir in log_dirs:
            expanded = os.path.expanduser(log_dir)
            if os.path.exists(expanded):
                for log_file in glob.glob(f"{expanded}/*.log"):
                    try:
                        self.secure_delete(log_file)
                        self.logger.info(f"Cleared: {log_file}")
                    except Exception as e:
                        self.logger.warning(f"Failed to clear {log_file}: {e}")
    
    def clear_command_history(self):
        """Clear various command histories"""
        # Clear current session history
        try:
            subprocess.run(['history', '-c'], shell=True, check=False)
        except:
            pass
        
        # Clear less history
        less_history = os.path.expanduser('~/.lesshst')
        if os.path.exists(less_history):
            self.secure_delete(less_history)
        
        # Clear vim history
        vim_history = os.path.expanduser('~/.viminfo')
        if os.path.exists(vim_history):
            self.secure_delete(vim_history)
    
    def clear_swap(self):
        """Clear swap space (requires root)"""
        try:
            # This requires root privileges
            subprocess.run(['sudo', 'swapoff', '-a'], check=False)
            subprocess.run(['sudo', 'swapon', '-a'], check=False)
            self.logger.info("Swap cleared")
        except Exception as e:
            self.logger.warning(f"Failed to clear swap: {e}")
    
    def clear_memory_cache(self):
        """Clear memory cache (requires root)"""
        try:
            # Drop caches
            subprocess.run(
                ['sudo', 'sh', '-c', 'echo 3 > /proc/sys/vm/drop_caches'],
                check=False
            )
            self.logger.info("Memory cache cleared")
        except Exception as e:
            self.logger.warning(f"Failed to clear memory cache: {e}")
    
    def clear_recent_files(self):
        """Clear recent files list"""
        recent_files = [
            '~/.recently-used',
            '~/.local/share/recently-used.xbel',
        ]
        
        for recent_file in recent_files:
            expanded = os.path.expanduser(recent_file)
            if os.path.exists(expanded):
                self.secure_delete(expanded)
                self.logger.info(f"Cleared: {recent_file}")
    
    def secure_delete(self, file_path: str):
        """
        Securely delete file using shred if available
        
        Args:
            file_path: Path to file to delete
        """
        if not os.path.exists(file_path):
            return
        
        # Try shred first (overwrites data)
        if shutil.which('shred'):
            try:
                subprocess.run(
                    ['shred', '-vfz', '-n', '3', file_path],
                    check=True,
                    capture_output=True
                )
                self.logger.info(f"Securely deleted: {file_path}")
                return
            except subprocess.CalledProcessError:
                pass
        
        # Fallback to regular deletion
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
            self.logger.info(f"Deleted: {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to delete {file_path}: {e}")
            raise
    
    def secure_delete_log(self):
        """Securely delete the cleanup log itself"""
        if os.path.exists(self.log_file):
            self.secure_delete(self.log_file)
    
    def sanitize_file(self, file_path: str, patterns: List[str]):
        """
        Sanitize file by removing sensitive patterns
        
        Args:
            file_path: Path to file
            patterns: List of patterns to remove
        """
        if not os.path.exists(file_path):
            return
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Remove sensitive patterns
            for pattern in patterns:
                content = content.replace(pattern, '[REDACTED]')
            
            with open(file_path, 'w') as f:
                f.write(content)
            
            self.logger.info(f"Sanitized: {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to sanitize {file_path}: {e}")
    
    def emergency_cleanup(self):
        """Emergency cleanup - most aggressive"""
        self.logger.critical("EMERGENCY CLEANUP INITIATED")
        
        # Stop all NightFury processes
        try:
            subprocess.run(['pkill', '-9', '-f', 'nightfury'], check=False)
        except:
            pass
        
        # Execute paranoid cleanup
        self.clean_all(paranoid=True)
        
        # Additional emergency measures
        self.clear_network_connections()
        self.create_incident_report()
        
        self.logger.critical("EMERGENCY CLEANUP COMPLETED")
    
    def clear_network_connections(self):
        """Clear/reset network connections"""
        try:
            # Kill established non-standard connections
            subprocess.run(['ss', '-K', 'state', 'established', '!(', 'dport', '=', ':22', ')'], check=False)
            self.logger.info("Network connections cleared")
        except Exception as e:
            self.logger.error(f"Failed to clear network connections: {e}")
    
    def create_incident_report(self):
        """Create incident report for emergency cleanup"""
        from datetime import datetime
        
        report_path = f"/tmp/incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        try:
            with open(report_path, 'w') as f:
                f.write("NIGHTFURY INCIDENT REPORT\n")
                f.write("="*60 + "\n\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                f.write(f"Event: Emergency Cleanup\n")
                f.write(f"Cleaned Items: {len(self.cleaned_items)}\n")
                f.write(f"Failed Items: {len(self.failed_items)}\n\n")
                
                if self.failed_items:
                    f.write("Failed Operations:\n")
                    for item in self.failed_items:
                        f.write(f"  - {item}\n")
            
            self.logger.info(f"Incident report created: {report_path}")
        except Exception as e:
            self.logger.error(f"Failed to create incident report: {e}")

def main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='NightFury Forensic Cleaner')
    parser.add_argument(
        '-p', '--paranoid',
        action='store_true',
        help='Enable paranoid mode (aggressive cleaning)'
    )
    parser.add_argument(
        '-e', '--emergency',
        action='store_true',
        help='Emergency cleanup mode'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    cleaner = ForensicCleaner()
    
    print("[*] NightFury Forensic Cleaner")
    print("[*] Starting cleanup operations...\n")
    
    if args.emergency:
        print("[!] EMERGENCY MODE ACTIVATED")
        confirm = input("[!] This will perform aggressive cleanup. Continue? [y/N]: ")
        if confirm.lower() != 'y':
            print("[*] Cancelled")
            sys.exit(0)
        
        cleaner.emergency_cleanup()
    else:
        result = cleaner.clean_all(paranoid=args.paranoid)
        
        print(f"\n[+] Cleanup complete!")
        print(f"[+] Cleaned: {len(result['cleaned'])} items")
        
        if result['failed']:
            print(f"[!] Failed: {len(result['failed'])} items")
            if args.verbose:
                for item in result['failed']:
                    print(f"    - {item}")
    
    print(f"\n[*] Log file: {cleaner.log_file}")

if __name__ == '__main__':
    main()
