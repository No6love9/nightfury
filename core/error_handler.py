#!/usr/bin/env python3
"""
NightFury Error Handler
Comprehensive exception management with intelligent recovery strategies
"""

import os
import sys
import traceback
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any
from enum import Enum
from pathlib import Path

class ErrorCategory(Enum):
    """Error categories for classification"""
    NETWORK = "network"
    PERMISSION = "permission"
    RESOURCE = "resource"
    SECURITY = "security"
    CONFIGURATION = "configuration"
    MODULE = "module"
    UNKNOWN = "unknown"

class RecoveryStrategy(Enum):
    """Recovery strategies"""
    RETRY = "retry"
    FALLBACK = "fallback"
    OFFLINE_MODE = "offline_mode"
    ESCALATE = "escalate"
    SANITIZE_EVACUATE = "sanitize_evacuate"
    IGNORE = "ignore"
    ABORT = "abort"

class NightFuryErrorHandler:
    """Global exception management with recovery capabilities"""
    
    ERROR_MAPPINGS = {
        # Network errors
        'ConnectionError': ErrorCategory.NETWORK,
        'TimeoutError': ErrorCategory.NETWORK,
        'Timeout': ErrorCategory.NETWORK,
        'URLError': ErrorCategory.NETWORK,
        'HTTPError': ErrorCategory.NETWORK,
        'DNSError': ErrorCategory.NETWORK,
        'socket.error': ErrorCategory.NETWORK,
        'socket.timeout': ErrorCategory.NETWORK,
        
        # Permission errors
        'PermissionError': ErrorCategory.PERMISSION,
        'PermissionDenied': ErrorCategory.PERMISSION,
        'AccessDenied': ErrorCategory.PERMISSION,
        'OSError': ErrorCategory.PERMISSION,  # Can be permission-related
        
        # Resource errors
        'MemoryError': ErrorCategory.RESOURCE,
        'DiskFull': ErrorCategory.RESOURCE,
        'ProcessLimit': ErrorCategory.RESOURCE,
        'ResourceExhausted': ErrorCategory.RESOURCE,
        
        # Security errors
        'AuthenticationError': ErrorCategory.SECURITY,
        'AuthorizationError': ErrorCategory.SECURITY,
        'SSLError': ErrorCategory.SECURITY,
        'CertificateError': ErrorCategory.SECURITY,
        'IntrusionDetected': ErrorCategory.SECURITY,
        
        # Configuration errors
        'ConfigurationError': ErrorCategory.CONFIGURATION,
        'ValueError': ErrorCategory.CONFIGURATION,
        'KeyError': ErrorCategory.CONFIGURATION,
        'FileNotFoundError': ErrorCategory.CONFIGURATION,
    }
    
    RECOVERY_STRATEGIES = {
        ErrorCategory.NETWORK: RecoveryStrategy.OFFLINE_MODE,
        ErrorCategory.PERMISSION: RecoveryStrategy.ESCALATE,
        ErrorCategory.RESOURCE: RecoveryStrategy.RETRY,
        ErrorCategory.SECURITY: RecoveryStrategy.SANITIZE_EVACUATE,
        ErrorCategory.CONFIGURATION: RecoveryStrategy.FALLBACK,
        ErrorCategory.MODULE: RecoveryStrategy.FALLBACK,
        ErrorCategory.UNKNOWN: RecoveryStrategy.RETRY,
    }
    
    def __init__(self, log_dir: str = "/home/ubuntu/nightfury/logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.error_log = self.log_dir / "errors.log"
        self.recovery_log = self.log_dir / "recovery.log"
        self.critical_log = self.log_dir / "critical.log"
        
        self._setup_logging()
        
        self.error_count: Dict[ErrorCategory, int] = {}
        self.recovery_attempts: Dict[str, int] = {}
        self.max_recovery_attempts = 3
        self.offline_mode = False
        self.emergency_mode = False
        
    def _setup_logging(self) -> None:
        """Setup logging configuration"""
        # Error logger
        self.error_logger = logging.getLogger('nightfury.errors')
        self.error_logger.setLevel(logging.ERROR)
        error_handler = logging.FileHandler(self.error_log)
        error_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        self.error_logger.addHandler(error_handler)
        
        # Recovery logger
        self.recovery_logger = logging.getLogger('nightfury.recovery')
        self.recovery_logger.setLevel(logging.INFO)
        recovery_handler = logging.FileHandler(self.recovery_log)
        recovery_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        self.recovery_logger.addHandler(recovery_handler)
        
        # Critical logger
        self.critical_logger = logging.getLogger('nightfury.critical')
        self.critical_logger.setLevel(logging.CRITICAL)
        critical_handler = logging.FileHandler(self.critical_log)
        critical_handler.setFormatter(
            logging.Formatter('%(asctime)s - CRITICAL - %(message)s')
        )
        self.critical_logger.addHandler(critical_handler)
    
    def handle_exception(
        self,
        exception: Exception,
        context: Optional[Dict[str, Any]] = None,
        allow_recovery: bool = True
    ) -> Dict[str, Any]:
        """
        Handle exception with intelligent recovery
        
        Args:
            exception: The exception to handle
            context: Additional context information
            allow_recovery: Whether to attempt recovery
            
        Returns:
            Dictionary with handling results
        """
        error_type = type(exception).__name__
        category = self._categorize_error(error_type)
        
        # Log the error
        self._log_error(exception, context, category)
        
        # Update error statistics
        self.error_count[category] = self.error_count.get(category, 0) + 1
        
        # Check if we should attempt recovery
        if not allow_recovery or self.emergency_mode:
            return {
                'recovered': False,
                'strategy': RecoveryStrategy.ABORT,
                'message': 'Recovery disabled or emergency mode active'
            }
        
        # Check recovery attempt limit
        error_key = f"{category.value}:{error_type}"
        attempts = self.recovery_attempts.get(error_key, 0)
        
        if attempts >= self.max_recovery_attempts:
            self._log_critical(
                f"Max recovery attempts exceeded for {error_key}",
                exception,
                context
            )
            return {
                'recovered': False,
                'strategy': RecoveryStrategy.ABORT,
                'message': 'Maximum recovery attempts exceeded'
            }
        
        # Increment recovery attempts
        self.recovery_attempts[error_key] = attempts + 1
        
        # Execute recovery strategy
        strategy = self.RECOVERY_STRATEGIES.get(category, RecoveryStrategy.RETRY)
        recovery_result = self._execute_recovery(strategy, exception, context)
        
        # Reset recovery attempts on success
        if recovery_result.get('success', False):
            self.recovery_attempts[error_key] = 0
        
        return recovery_result
    
    def _categorize_error(self, error_type: str) -> ErrorCategory:
        """Categorize error by type"""
        return self.ERROR_MAPPINGS.get(error_type, ErrorCategory.UNKNOWN)
    
    def _execute_recovery(
        self,
        strategy: RecoveryStrategy,
        exception: Exception,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Execute recovery strategy"""
        self.recovery_logger.info(f"Executing recovery strategy: {strategy.value}")
        
        recovery_methods = {
            RecoveryStrategy.RETRY: self._recovery_retry,
            RecoveryStrategy.FALLBACK: self._recovery_fallback,
            RecoveryStrategy.OFFLINE_MODE: self._recovery_offline_mode,
            RecoveryStrategy.ESCALATE: self._recovery_escalate,
            RecoveryStrategy.SANITIZE_EVACUATE: self._recovery_sanitize_evacuate,
            RecoveryStrategy.IGNORE: self._recovery_ignore,
            RecoveryStrategy.ABORT: self._recovery_abort,
        }
        
        method = recovery_methods.get(strategy, self._recovery_abort)
        
        try:
            result = method(exception, context)
            self.recovery_logger.info(f"Recovery result: {result}")
            return result
        except Exception as e:
            self.recovery_logger.error(f"Recovery failed: {str(e)}")
            return {
                'success': False,
                'strategy': strategy,
                'message': f'Recovery method failed: {str(e)}'
            }
    
    def _recovery_retry(
        self,
        exception: Exception,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Retry the failed operation"""
        import time
        
        # Implement exponential backoff
        attempt = self.recovery_attempts.get(str(exception), 0)
        wait_time = min(2 ** attempt, 30)  # Max 30 seconds
        
        self.recovery_logger.info(f"Retrying after {wait_time} seconds")
        time.sleep(wait_time)
        
        return {
            'success': True,
            'strategy': RecoveryStrategy.RETRY,
            'message': f'Retrying after {wait_time}s backoff',
            'wait_time': wait_time
        }
    
    def _recovery_fallback(
        self,
        exception: Exception,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Use fallback mechanism"""
        fallback_method = context.get('fallback_method') if context else None
        
        if fallback_method and callable(fallback_method):
            try:
                fallback_method()
                return {
                    'success': True,
                    'strategy': RecoveryStrategy.FALLBACK,
                    'message': 'Fallback method executed successfully'
                }
            except Exception as e:
                return {
                    'success': False,
                    'strategy': RecoveryStrategy.FALLBACK,
                    'message': f'Fallback method failed: {str(e)}'
                }
        
        return {
            'success': True,
            'strategy': RecoveryStrategy.FALLBACK,
            'message': 'Using default fallback behavior'
        }
    
    def _recovery_offline_mode(
        self,
        exception: Exception,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Switch to offline mode"""
        if not self.offline_mode:
            self.offline_mode = True
            self.recovery_logger.warning("Switching to OFFLINE MODE")
            
            # Disable network-dependent features
            self._disable_network_features()
            
            # Enable offline capabilities
            self._enable_offline_features()
        
        return {
            'success': True,
            'strategy': RecoveryStrategy.OFFLINE_MODE,
            'message': 'Switched to offline mode',
            'offline_mode': True
        }
    
    def _recovery_escalate(
        self,
        exception: Exception,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Attempt privilege escalation or use alternative method"""
        # Try to escalate privileges
        if os.geteuid() != 0:
            self.recovery_logger.info("Attempting privilege escalation")
            return {
                'success': False,
                'strategy': RecoveryStrategy.ESCALATE,
                'message': 'Requires elevated privileges. Run with sudo.',
                'requires_sudo': True
            }
        
        # Already have privileges, try alternative method
        alternative_method = context.get('alternative_method') if context else None
        if alternative_method and callable(alternative_method):
            try:
                alternative_method()
                return {
                    'success': True,
                    'strategy': RecoveryStrategy.ESCALATE,
                    'message': 'Alternative method executed successfully'
                }
            except Exception as e:
                return {
                    'success': False,
                    'strategy': RecoveryStrategy.ESCALATE,
                    'message': f'Alternative method failed: {str(e)}'
                }
        
        return {
            'success': False,
            'strategy': RecoveryStrategy.ESCALATE,
            'message': 'No alternative method available'
        }
    
    def _recovery_sanitize_evacuate(
        self,
        exception: Exception,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Execute security protocol: sanitize and evacuate"""
        self.critical_logger.critical(
            f"SECURITY INCIDENT: {type(exception).__name__} - {str(exception)}"
        )
        
        # Activate emergency mode
        self.emergency_mode = True
        
        # Sanitize logs
        self._sanitize_logs()
        
        # Activate forensic countermeasures
        self._activate_forensic_countermeasures()
        
        # Send secure alert
        self._send_secure_alert(exception, context)
        
        return {
            'success': True,
            'strategy': RecoveryStrategy.SANITIZE_EVACUATE,
            'message': 'Security protocol activated',
            'emergency_mode': True
        }
    
    def _recovery_ignore(
        self,
        exception: Exception,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Ignore the error and continue"""
        return {
            'success': True,
            'strategy': RecoveryStrategy.IGNORE,
            'message': 'Error ignored'
        }
    
    def _recovery_abort(
        self,
        exception: Exception,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Abort operation"""
        return {
            'success': False,
            'strategy': RecoveryStrategy.ABORT,
            'message': 'Operation aborted'
        }
    
    def _disable_network_features(self) -> None:
        """Disable network-dependent features"""
        self.recovery_logger.info("Disabling network-dependent features")
        # Implementation would disable specific modules
        pass
    
    def _enable_offline_features(self) -> None:
        """Enable offline capabilities"""
        self.recovery_logger.info("Enabling offline features")
        # Implementation would enable cached/local features
        pass
    
    def _sanitize_logs(self) -> None:
        """Sanitize sensitive information from logs"""
        self.critical_logger.critical("Sanitizing logs")
        # Implementation would remove sensitive data
        pass
    
    def _activate_forensic_countermeasures(self) -> None:
        """Activate forensic countermeasures"""
        self.critical_logger.critical("Activating forensic countermeasures")
        # Implementation would clear artifacts, modify timestamps, etc.
        pass
    
    def _send_secure_alert(
        self,
        exception: Exception,
        context: Optional[Dict[str, Any]]
    ) -> None:
        """Send secure alert to operators"""
        alert_file = self.log_dir / f"alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'type': 'SECURITY_INCIDENT',
            'exception': str(exception),
            'exception_type': type(exception).__name__,
            'context': context or {},
            'traceback': traceback.format_exc()
        }
        
        with open(alert_file, 'w') as f:
            json.dump(alert_data, f, indent=2)
        
        self.critical_logger.critical(f"Alert saved to {alert_file}")
    
    def _log_error(
        self,
        exception: Exception,
        context: Optional[Dict[str, Any]],
        category: ErrorCategory
    ) -> None:
        """Log error with full context"""
        error_data = {
            'timestamp': datetime.now().isoformat(),
            'exception_type': type(exception).__name__,
            'exception_message': str(exception),
            'category': category.value,
            'context': context or {},
            'traceback': traceback.format_exc()
        }
        
        self.error_logger.error(json.dumps(error_data))
    
    def _log_critical(
        self,
        message: str,
        exception: Exception,
        context: Optional[Dict[str, Any]]
    ) -> None:
        """Log critical error"""
        critical_data = {
            'timestamp': datetime.now().isoformat(),
            'message': message,
            'exception_type': type(exception).__name__,
            'exception_message': str(exception),
            'context': context or {},
            'traceback': traceback.format_exc()
        }
        
        self.critical_logger.critical(json.dumps(critical_data))
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics"""
        return {
            'total_errors': sum(self.error_count.values()),
            'errors_by_category': {
                cat.value: count for cat, count in self.error_count.items()
            },
            'recovery_attempts': dict(self.recovery_attempts),
            'offline_mode': self.offline_mode,
            'emergency_mode': self.emergency_mode
        }
    
    def reset_statistics(self) -> None:
        """Reset error statistics"""
        self.error_count.clear()
        self.recovery_attempts.clear()
    
    def export_error_report(self, output_file: str) -> None:
        """Export comprehensive error report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'statistics': self.get_error_statistics(),
            'recent_errors': self._get_recent_errors(50),
            'recovery_history': self._get_recovery_history(50)
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
    
    def _get_recent_errors(self, count: int) -> List[str]:
        """Get recent errors from log"""
        try:
            with open(self.error_log, 'r') as f:
                lines = f.readlines()
                return lines[-count:]
        except Exception:
            return []
    
    def _get_recovery_history(self, count: int) -> List[str]:
        """Get recovery history from log"""
        try:
            with open(self.recovery_log, 'r') as f:
                lines = f.readlines()
                return lines[-count:]
        except Exception:
            return []

# Global error handler instance
_global_error_handler: Optional[NightFuryErrorHandler] = None

def get_error_handler() -> NightFuryErrorHandler:
    """Get global error handler instance"""
    global _global_error_handler
    if _global_error_handler is None:
        _global_error_handler = NightFuryErrorHandler()
    return _global_error_handler

def handle_exception(
    exception: Exception,
    context: Optional[Dict[str, Any]] = None,
    allow_recovery: bool = True
) -> Dict[str, Any]:
    """Convenience function to handle exceptions"""
    handler = get_error_handler()
    return handler.handle_exception(exception, context, allow_recovery)

def main():
    """Test error handler"""
    handler = NightFuryErrorHandler()
    
    # Test network error
    try:
        raise ConnectionError("Network connection failed")
    except Exception as e:
        result = handler.handle_exception(e, {'module': 'test'})
        print(f"Network error handled: {result}")
    
    # Test permission error
    try:
        raise PermissionError("Access denied")
    except Exception as e:
        result = handler.handle_exception(e, {'module': 'test'})
        print(f"Permission error handled: {result}")
    
    # Print statistics
    print("\nError Statistics:")
    print(json.dumps(handler.get_error_statistics(), indent=2))

if __name__ == '__main__':
    main()
