#!/usr/bin/env python3
"""
NightFury Authentication Manager
SHEBA-based access control with role-based permissions
"""

import os
import sys
import json
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import yaml


class SHEBAAuthManager:
    """SHEBA (Secure Hierarchical Entry & Boundary Authentication) Manager"""
    
    ROLES = {
        'admin': {
            'level': 3,
            'permissions': ['*'],  # All permissions
            'description': 'Full system access'
        },
        'operator': {
            'level': 2,
            'permissions': [
                'c2_control', 'proxy_config', 'osint_scan', 
                'web_exploit', 'report_view', 'module_control'
            ],
            'description': 'Standard red team operator'
        },
        'student': {
            'level': 1,
            'permissions': [
                'osint_scan', 'report_view', 'tool_usage'
            ],
            'description': 'Limited access for training'
        }
    }
    
    def __init__(self, config_path: str = "/home/ubuntu/nightfury/config/operators.yaml"):
        self.config_path = config_path
        self.operators: Dict = {}
        self.sessions: Dict = {}
        self.codeword = "SHEBA"  # Master codeword
        self.session_timeout = 3600  # 1 hour
        self.max_failed_attempts = 3
        self.lockout_duration = 300  # 5 minutes
        self.failed_attempts: Dict = {}
        self.locked_out: Dict = {}
        
        self._load_operators()
    
    def _load_operators(self) -> None:
        """Load operator configuration from YAML"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    self.operators = config.get('operators', {})
            except Exception as e:
                print(f"[!] Failed to load operators config: {e}")
                self._create_default_config()
        else:
            self._create_default_config()
    
    def _create_default_config(self) -> None:
        """Create default operator configuration"""
        default_config = {
            'operators': {
                'admin': {
                    'password_hash': self._hash_password('nightfury2024'),
                    'role': 'admin',
                    'created': datetime.now().isoformat(),
                    'last_login': None,
                    'enabled': True
                }
            },
            'settings': {
                'require_codeword': True,
                'session_timeout': self.session_timeout,
                'max_failed_attempts': self.max_failed_attempts,
                'lockout_duration': self.lockout_duration
            }
        }
        
        # Create config directory if it doesn't exist
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        
        with open(self.config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
        
        self.operators = default_config['operators']
        print(f"[+] Created default operator configuration at {self.config_path}")
        print("[!] Default credentials: admin / nightfury2024")
        print("[!] CHANGE DEFAULT PASSWORD IMMEDIATELY")
    
    def authenticate(self, username: str, password: str, codeword: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Authenticate user with username, password, and optional codeword
        Returns: (success, session_token, error_message)
        """
        # Check if user is locked out
        if self._is_locked_out(username):
            remaining = self._get_lockout_remaining(username)
            return False, None, f"Account locked. Try again in {remaining} seconds"
        
        # Validate codeword if required
        if codeword and codeword.upper() != self.codeword:
            self._record_failed_attempt(username)
            return False, None, "Invalid codeword"
        
        # Check if operator exists
        if username not in self.operators:
            self._record_failed_attempt(username)
            return False, None, "Invalid credentials"
        
        operator = self.operators[username]
        
        # Check if account is enabled
        if not operator.get('enabled', True):
            return False, None, "Account disabled"
        
        # Verify password
        password_hash = self._hash_password(password)
        if password_hash != operator.get('password_hash'):
            self._record_failed_attempt(username)
            return False, None, "Invalid credentials"
        
        # Authentication successful
        self._clear_failed_attempts(username)
        session_token = self._create_session(username, operator['role'])
        
        # Update last login
        self.operators[username]['last_login'] = datetime.now().isoformat()
        self._save_operators()
        
        return True, session_token, None
    
    def validate_session(self, session_token: str) -> Tuple[bool, Optional[Dict]]:
        """
        Validate session token
        Returns: (valid, session_info)
        """
        if session_token not in self.sessions:
            return False, None
        
        session = self.sessions[session_token]
        
        # Check if session has expired
        if time.time() > session['expires_at']:
            del self.sessions[session_token]
            return False, None
        
        # Extend session
        session['expires_at'] = time.time() + self.session_timeout
        
        return True, session
    
    def check_permission(self, session_token: str, permission: str) -> bool:
        """Check if session has specific permission"""
        valid, session = self.validate_session(session_token)
        if not valid:
            return False
        
        role = session['role']
        role_info = self.ROLES.get(role, {})
        permissions = role_info.get('permissions', [])
        
        # Admin has all permissions
        if '*' in permissions:
            return True
        
        return permission in permissions
    
    def logout(self, session_token: str) -> bool:
        """Logout and invalidate session"""
        if session_token in self.sessions:
            del self.sessions[session_token]
            return True
        return False
    
    def add_operator(self, username: str, password: str, role: str, created_by: str) -> Tuple[bool, str]:
        """Add new operator (requires admin privileges)"""
        if role not in self.ROLES:
            return False, f"Invalid role. Must be one of: {', '.join(self.ROLES.keys())}"
        
        if username in self.operators:
            return False, "Operator already exists"
        
        self.operators[username] = {
            'password_hash': self._hash_password(password),
            'role': role,
            'created': datetime.now().isoformat(),
            'created_by': created_by,
            'last_login': None,
            'enabled': True
        }
        
        self._save_operators()
        return True, f"Operator {username} created successfully"
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Change operator password"""
        if username not in self.operators:
            return False, "Operator not found"
        
        operator = self.operators[username]
        
        # Verify old password
        if self._hash_password(old_password) != operator['password_hash']:
            return False, "Invalid current password"
        
        # Update password
        operator['password_hash'] = self._hash_password(new_password)
        operator['password_changed'] = datetime.now().isoformat()
        
        self._save_operators()
        return True, "Password changed successfully"
    
    def disable_operator(self, username: str) -> Tuple[bool, str]:
        """Disable operator account"""
        if username not in self.operators:
            return False, "Operator not found"
        
        self.operators[username]['enabled'] = False
        self.operators[username]['disabled_at'] = datetime.now().isoformat()
        
        # Invalidate all sessions for this user
        sessions_to_remove = [
            token for token, session in self.sessions.items()
            if session['username'] == username
        ]
        for token in sessions_to_remove:
            del self.sessions[token]
        
        self._save_operators()
        return True, f"Operator {username} disabled"
    
    def enable_operator(self, username: str) -> Tuple[bool, str]:
        """Enable operator account"""
        if username not in self.operators:
            return False, "Operator not found"
        
        self.operators[username]['enabled'] = True
        self.operators[username]['enabled_at'] = datetime.now().isoformat()
        
        self._save_operators()
        return True, f"Operator {username} enabled"
    
    def list_operators(self) -> List[Dict]:
        """List all operators"""
        operators_list = []
        for username, info in self.operators.items():
            operators_list.append({
                'username': username,
                'role': info['role'],
                'enabled': info.get('enabled', True),
                'created': info.get('created'),
                'last_login': info.get('last_login')
            })
        return operators_list
    
    def get_session_info(self, session_token: str) -> Optional[Dict]:
        """Get session information"""
        valid, session = self.validate_session(session_token)
        if not valid:
            return None
        
        return {
            'username': session['username'],
            'role': session['role'],
            'permissions': self.ROLES[session['role']]['permissions'],
            'expires_at': datetime.fromtimestamp(session['expires_at']).isoformat(),
            'created_at': session['created_at']
        }
    
    def _create_session(self, username: str, role: str) -> str:
        """Create new session"""
        session_token = secrets.token_urlsafe(32)
        
        self.sessions[session_token] = {
            'username': username,
            'role': role,
            'created_at': datetime.now().isoformat(),
            'expires_at': time.time() + self.session_timeout,
            'ip_address': None  # Can be set by caller
        }
        
        return session_token
    
    def _hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _record_failed_attempt(self, username: str) -> None:
        """Record failed authentication attempt"""
        if username not in self.failed_attempts:
            self.failed_attempts[username] = []
        
        self.failed_attempts[username].append(time.time())
        
        # Keep only recent attempts
        cutoff = time.time() - self.lockout_duration
        self.failed_attempts[username] = [
            t for t in self.failed_attempts[username] if t > cutoff
        ]
        
        # Check if should lock out
        if len(self.failed_attempts[username]) >= self.max_failed_attempts:
            self.locked_out[username] = time.time() + self.lockout_duration
    
    def _clear_failed_attempts(self, username: str) -> None:
        """Clear failed attempts for user"""
        if username in self.failed_attempts:
            del self.failed_attempts[username]
        if username in self.locked_out:
            del self.locked_out[username]
    
    def _is_locked_out(self, username: str) -> bool:
        """Check if user is locked out"""
        if username not in self.locked_out:
            return False
        
        if time.time() > self.locked_out[username]:
            del self.locked_out[username]
            return False
        
        return True
    
    def _get_lockout_remaining(self, username: str) -> int:
        """Get remaining lockout time in seconds"""
        if username not in self.locked_out:
            return 0
        
        remaining = int(self.locked_out[username] - time.time())
        return max(0, remaining)
    
    def _save_operators(self) -> None:
        """Save operators configuration to file"""
        config = {
            'operators': self.operators,
            'settings': {
                'require_codeword': True,
                'session_timeout': self.session_timeout,
                'max_failed_attempts': self.max_failed_attempts,
                'lockout_duration': self.lockout_duration
            }
        }
        
        with open(self.config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
    
    def export_audit_log(self, output_file: str) -> None:
        """Export authentication audit log"""
        audit_data = {
            'timestamp': datetime.now().isoformat(),
            'operators': self.list_operators(),
            'active_sessions': len(self.sessions),
            'locked_accounts': list(self.locked_out.keys())
        }
        
        with open(output_file, 'w') as f:
            json.dump(audit_data, f, indent=2)


def main():
    """CLI interface for authentication manager"""
    import argparse
    
    parser = argparse.ArgumentParser(description='NightFury Authentication Manager')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Login command
    login_parser = subparsers.add_parser('login', help='Authenticate user')
    login_parser.add_argument('username', help='Username')
    login_parser.add_argument('password', help='Password')
    login_parser.add_argument('--codeword', help='SHEBA codeword', default=None)
    
    # Add operator command
    add_parser = subparsers.add_parser('add', help='Add new operator')
    add_parser.add_argument('username', help='Username')
    add_parser.add_argument('password', help='Password')
    add_parser.add_argument('role', choices=['admin', 'operator', 'student'], help='Role')
    add_parser.add_argument('--created-by', required=True, help='Creator username')
    
    # List operators command
    subparsers.add_parser('list', help='List all operators')
    
    # Change password command
    passwd_parser = subparsers.add_parser('passwd', help='Change password')
    passwd_parser.add_argument('username', help='Username')
    passwd_parser.add_argument('old_password', help='Current password')
    passwd_parser.add_argument('new_password', help='New password')
    
    # Disable/Enable commands
    disable_parser = subparsers.add_parser('disable', help='Disable operator')
    disable_parser.add_argument('username', help='Username')
    
    enable_parser = subparsers.add_parser('enable', help='Enable operator')
    enable_parser.add_argument('username', help='Username')
    
    args = parser.parse_args()
    
    auth_manager = SHEBAAuthManager()
    
    if args.command == 'login':
        success, token, error = auth_manager.authenticate(
            args.username, args.password, args.codeword
        )
        if success:
            print(f"[+] Authentication successful")
            print(f"[+] Session Token: {token}")
            session_info = auth_manager.get_session_info(token)
            print(f"[+] Role: {session_info['role']}")
            print(f"[+] Permissions: {', '.join(session_info['permissions'])}")
        else:
            print(f"[!] Authentication failed: {error}")
            sys.exit(1)
    
    elif args.command == 'add':
        success, message = auth_manager.add_operator(
            args.username, args.password, args.role, args.created_by
        )
        if success:
            print(f"[+] {message}")
        else:
            print(f"[!] {message}")
            sys.exit(1)
    
    elif args.command == 'list':
        operators = auth_manager.list_operators()
        print("\n" + "="*60)
        print("NightFury Operators")
        print("="*60)
        for op in operators:
            status = "✓" if op['enabled'] else "✗"
            print(f"{status} {op['username']:15} | {op['role']:10} | Last: {op['last_login'] or 'Never'}")
        print("="*60 + "\n")
    
    elif args.command == 'passwd':
        success, message = auth_manager.change_password(
            args.username, args.old_password, args.new_password
        )
        if success:
            print(f"[+] {message}")
        else:
            print(f"[!] {message}")
            sys.exit(1)
    
    elif args.command == 'disable':
        success, message = auth_manager.disable_operator(args.username)
        if success:
            print(f"[+] {message}")
        else:
            print(f"[!] {message}")
            sys.exit(1)
    
    elif args.command == 'enable':
        success, message = auth_manager.enable_operator(args.username)
        if success:
            print(f"[+] {message}")
        else:
            print(f"[!] {message}")
            sys.exit(1)
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
