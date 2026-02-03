#!/usr/bin/env python3
"""
NightFury Framework - Advanced GUI Dashboard with Gemini AI
Professional interface with AI-powered analysis and reporting
Version: 2.0 - Gemini AI Edition
"""

import sys
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QLabel, QLineEdit, QComboBox, QTextEdit, QTableWidget,
        QTableWidgetItem, QTabWidget, QProgressBar, QSpinBox, QCheckBox,
        QFileDialog, QMessageBox, QSplitter, QListWidget, QListWidgetItem,
        QStatusBar, QMenuBar, QMenu, QDialog, QFormLayout, QGroupBox,
        QScrollArea
    )
    from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, QSize
    from PyQt5.QtGui import QIcon, QColor, QFont, QPixmap
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False

try:
    from gemini_ai_integration import GeminiAIIntegration, GeminiAIReportGenerator
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False


class DataCollector:
    """Collects and manages operation data"""
    
    def __init__(self, output_dir: str = "./nightfury_reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.current_operation = None
        self.operations = []
        self.results = []
    
    def start_operation(self, operation_name: str, target: str, 
                       operation_type: str) -> Dict:
        """Start a new operation"""
        operation = {
            "id": len(self.operations) + 1,
            "name": operation_name,
            "target": target,
            "type": operation_type,
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "status": "running",
            "findings": [],
            "logs": [],
            "ai_analysis": None
        }
        self.current_operation = operation
        self.operations.append(operation)
        return operation
    
    def add_finding(self, severity: str, title: str, description: str, 
                   evidence: Optional[str] = None) -> None:
        """Add a finding to current operation"""
        if self.current_operation:
            finding = {
                "timestamp": datetime.now().isoformat(),
                "severity": severity,
                "title": title,
                "description": description,
                "evidence": evidence
            }
            self.current_operation["findings"].append(finding)
    
    def add_log(self, level: str, message: str) -> None:
        """Add a log entry"""
        if self.current_operation:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "level": level,
                "message": message
            }
            self.current_operation["logs"].append(log_entry)
    
    def end_operation(self, status: str = "completed") -> None:
        """End current operation"""
        if self.current_operation:
            self.current_operation["end_time"] = datetime.now().isoformat()
            self.current_operation["status"] = status
    
    def save_operation(self) -> str:
        """Save operation to file"""
        if not self.current_operation:
            return ""
        
        filename = f"operation_{self.current_operation['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(self.current_operation, f, indent=2)
        
        return str(filepath)


class NightFuryGeminiGUI(QMainWindow):
    """Main GUI application with Gemini AI integration"""
    
    def __init__(self):
        super().__init__()
        self.data_collector = DataCollector()
        self.gemini = None
        self.init_gemini()
        self.init_ui()
    
    def init_gemini(self):
        """Initialize Gemini AI"""
        api_key = os.getenv("GEMINI_API_KEY")
        if api_key and GEMINI_AVAILABLE:
            try:
                self.gemini = GeminiAIIntegration(api_key)
            except Exception as e:
                print(f"[!] Gemini initialization error: {e}")
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("NightFury Framework v2.0 - Gemini AI Edition")
        self.setGeometry(100, 100, 1600, 950)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout
        main_layout = QHBoxLayout()
        
        # Create left panel (controls)
        left_panel = self.create_left_panel()
        
        # Create right panel (results)
        right_panel = self.create_right_panel()
        
        # Add to main layout
        main_layout.addWidget(left_panel, 1)
        main_layout.addWidget(right_panel, 2)
        
        central_widget.setLayout(main_layout)
        
        # Create status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        gemini_status = "✓ Gemini AI Ready" if self.gemini else "✗ Gemini AI Not Configured"
        self.statusBar.showMessage(f"Ready | {gemini_status}")
        
        # Apply stylesheet
        self.apply_stylesheet()
    
    def create_menu_bar(self):
        """Create application menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        file_menu.addAction("New Operation", self.new_operation)
        file_menu.addAction("Open Report", self.open_report)
        file_menu.addAction("Save Report", self.save_report)
        file_menu.addSeparator()
        file_menu.addAction("Exit", self.close)
        
        # Operations menu
        ops_menu = menubar.addMenu("Operations")
        ops_menu.addAction("Quick Reconnaissance", self.run_quick_recon)
        ops_menu.addAction("Full Reconnaissance", self.run_full_recon)
        ops_menu.addAction("Exploitation", self.run_exploitation)
        ops_menu.addAction("Advanced Chain", self.run_advanced_chain)
        
        # AI menu
        ai_menu = menubar.addMenu("Gemini AI")
        ai_menu.addAction("Analyze Findings", self.ai_analyze_findings)
        ai_menu.addAction("Generate Summary", self.ai_generate_summary)
        ai_menu.addAction("Remediation Steps", self.ai_remediation)
        ai_menu.addAction("Threat Model", self.ai_threat_model)
        ai_menu.addAction("Chat with AI", self.ai_chat)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        tools_menu.addAction("Verify Installation", self.verify_installation)
        tools_menu.addAction("Settings", self.show_settings)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        help_menu.addAction("Documentation", self.show_documentation)
        help_menu.addAction("About", self.show_about)
    
    def create_left_panel(self) -> QWidget:
        """Create left control panel"""
        panel = QWidget()
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Operation Control Panel")
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Operation name
        layout.addWidget(QLabel("Operation Name:"))
        self.operation_name_input = QLineEdit()
        self.operation_name_input.setPlaceholderText("e.g., Runehall Penetration Test")
        layout.addWidget(self.operation_name_input)
        
        # Target
        layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., runehall.com")
        layout.addWidget(self.target_input)
        
        # Operation type
        layout.addWidget(QLabel("Operation Type:"))
        self.operation_type = QComboBox()
        self.operation_type.addItems([
            "Reconnaissance",
            "Exploitation",
            "Post-Exploitation",
            "Full Penetration Test",
            "Vulnerability Assessment",
            "Social Engineering",
            "Custom"
        ])
        layout.addWidget(self.operation_type)
        
        # Quick commands
        layout.addWidget(QLabel("Quick Commands:"))
        self.quick_command = QComboBox()
        self.quick_command.addItems([
            "recon-full",
            "recon-quick",
            "recon-users",
            "exploit-auth",
            "exploit-bet",
            "exploit-payment",
            "exploit-rng",
            "chain-osint-exploit",
            "chain-full-test",
            "batch-users",
            "continuous-monitor"
        ])
        layout.addWidget(self.quick_command)
        
        # Performance mode
        layout.addWidget(QLabel("Performance Mode:"))
        self.performance_mode = QComboBox()
        self.performance_mode.addItems([
            "Balanced",
            "Ultra Performance",
            "Stealth",
            "Precision"
        ])
        layout.addWidget(self.performance_mode)
        
        # Threads
        layout.addWidget(QLabel("Threads:"))
        self.threads_spinbox = QSpinBox()
        self.threads_spinbox.setMinimum(1)
        self.threads_spinbox.setMaximum(32)
        self.threads_spinbox.setValue(8)
        layout.addWidget(self.threads_spinbox)
        
        # Options
        layout.addWidget(QLabel("Options:"))
        self.proxy_checkbox = QCheckBox("Enable Proxy Rotation")
        self.proxy_checkbox.setChecked(True)
        layout.addWidget(self.proxy_checkbox)
        
        self.evasion_checkbox = QCheckBox("Enable Evasion")
        self.evasion_checkbox.setChecked(True)
        layout.addWidget(self.evasion_checkbox)
        
        self.cache_checkbox = QCheckBox("Enable Caching")
        self.cache_checkbox.setChecked(True)
        layout.addWidget(self.cache_checkbox)
        
        self.ai_checkbox = QCheckBox("Enable Gemini AI Analysis")
        self.ai_checkbox.setChecked(bool(self.gemini))
        self.ai_checkbox.setEnabled(bool(self.gemini))
        layout.addWidget(self.ai_checkbox)
        
        # Buttons
        layout.addSpacing(20)
        
        start_button = QPushButton("Start Operation")
        start_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 10px; font-weight: bold;")
        start_button.clicked.connect(self.start_operation)
        layout.addWidget(start_button)
        
        pause_button = QPushButton("Pause")
        pause_button.setStyleSheet("background-color: #ff9800; color: white; padding: 10px;")
        pause_button.clicked.connect(self.pause_operation)
        layout.addWidget(pause_button)
        
        stop_button = QPushButton("Stop")
        stop_button.setStyleSheet("background-color: #f44336; color: white; padding: 10px;")
        stop_button.clicked.connect(self.stop_operation)
        layout.addWidget(stop_button)
        
        layout.addSpacing(20)
        
        ai_button = QPushButton("🤖 Gemini AI Analysis")
        ai_button.setStyleSheet("background-color: #2196F3; color: white; padding: 10px; font-weight: bold;")
        ai_button.clicked.connect(self.ai_analyze_findings)
        ai_button.setEnabled(bool(self.gemini))
        layout.addWidget(ai_button)
        
        layout.addStretch()
        
        panel.setLayout(layout)
        return panel
    
    def create_right_panel(self) -> QWidget:
        """Create right results panel"""
        panel = QWidget()
        layout = QVBoxLayout()
        
        # Tabs
        tabs = QTabWidget()
        
        # Results tab
        results_tab = QWidget()
        results_layout = QVBoxLayout()
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["Timestamp", "Severity", "Title", "Description", "Evidence"])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        results_layout.addWidget(self.results_table)
        results_tab.setLayout(results_layout)
        tabs.addTab(results_tab, "Findings")
        
        # Logs tab
        logs_tab = QWidget()
        logs_layout = QVBoxLayout()
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        logs_layout.addWidget(self.logs_text)
        logs_tab.setLayout(logs_layout)
        tabs.addTab(logs_tab, "Logs")
        
        # AI Analysis tab
        ai_tab = QWidget()
        ai_layout = QVBoxLayout()
        self.ai_analysis_text = QTextEdit()
        self.ai_analysis_text.setReadOnly(True)
        ai_layout.addWidget(self.ai_analysis_text)
        ai_tab.setLayout(ai_layout)
        tabs.addTab(ai_tab, "AI Analysis")
        
        # Statistics tab
        stats_tab = QWidget()
        stats_layout = QVBoxLayout()
        
        stats_group = QGroupBox("Operation Statistics")
        stats_form = QFormLayout()
        
        self.total_findings_label = QLabel("0")
        self.high_severity_label = QLabel("0")
        self.medium_severity_label = QLabel("0")
        self.low_severity_label = QLabel("0")
        self.operation_time_label = QLabel("0s")
        
        stats_form.addRow("Total Findings:", self.total_findings_label)
        stats_form.addRow("High Severity:", self.high_severity_label)
        stats_form.addRow("Medium Severity:", self.medium_severity_label)
        stats_form.addRow("Low Severity:", self.low_severity_label)
        stats_form.addRow("Operation Time:", self.operation_time_label)
        
        stats_group.setLayout(stats_form)
        stats_layout.addWidget(stats_group)
        stats_layout.addStretch()
        stats_tab.setLayout(stats_layout)
        tabs.addTab(stats_tab, "Statistics")
        
        layout.addWidget(tabs)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        panel.setLayout(layout)
        return panel
    
    def start_operation(self):
        """Start a new operation"""
        operation_name = self.operation_name_input.text() or "Unnamed Operation"
        target = self.target_input.text() or "localhost"
        operation_type = self.operation_type.currentText()
        
        self.data_collector.start_operation(operation_name, target, operation_type)
        
        self.log_message("INFO", f"Operation started: {operation_name}")
        self.log_message("INFO", f"Target: {target}")
        self.log_message("INFO", f"Type: {operation_type}")
        
        if self.ai_checkbox.isChecked() and self.gemini:
            self.log_message("INFO", "Gemini AI analysis enabled")
        
        self.statusBar.showMessage(f"Running: {operation_name}")
        
        # Simulate operation
        self.simulate_operation()
    
    def simulate_operation(self):
        """Simulate an operation with sample findings"""
        findings = [
            ("high", "SQL Injection in Login Form", "Vulnerable parameter detected in authentication endpoint", "payload: ' OR '1'='1"),
            ("high", "Authentication Bypass", "Session token validation flaw detected", "session_id parameter"),
            ("medium", "Insufficient Rate Limiting", "No rate limiting on API endpoints", "1000 requests/minute possible"),
            ("medium", "Weak Encryption", "Sensitive data transmitted over HTTP", "Payment information exposed"),
            ("low", "Information Disclosure", "Version information leaked in headers", "Server: Apache/2.4.41"),
            ("low", "Missing Security Headers", "HSTS and CSP headers not configured", "X-Frame-Options missing")
        ]
        
        for i, (severity, title, description, evidence) in enumerate(findings):
            self.data_collector.add_finding(severity, title, description, evidence)
            self.add_result_row(severity, title, description, evidence)
            self.progress_bar.setValue(int((i + 1) / len(findings) * 100))
        
        self.data_collector.end_operation("completed")
        self.statusBar.showMessage("Operation completed")
        self.log_message("INFO", "Operation completed successfully")
        self.update_statistics()
        
        # Run AI analysis if enabled
        if self.ai_checkbox.isChecked() and self.gemini:
            self.run_ai_analysis()
    
    def run_ai_analysis(self):
        """Run Gemini AI analysis on findings"""
        if not self.gemini or not self.data_collector.current_operation:
            return
        
        self.log_message("INFO", "Running Gemini AI analysis...")
        
        try:
            findings = self.data_collector.current_operation.get("findings", [])
            analysis = self.gemini.analyze_findings(findings)
            
            self.ai_analysis_text.setText(analysis)
            self.data_collector.current_operation["ai_analysis"] = analysis
            
            self.log_message("INFO", "Gemini AI analysis completed")
        except Exception as e:
            self.log_message("ERROR", f"AI analysis error: {str(e)}")
    
    def ai_analyze_findings(self):
        """Analyze findings with Gemini AI"""
        if not self.gemini or not self.data_collector.current_operation:
            QMessageBox.warning(self, "Error", "No operation data or Gemini AI not configured")
            return
        
        findings = self.data_collector.current_operation.get("findings", [])
        if not findings:
            QMessageBox.warning(self, "Error", "No findings to analyze")
            return
        
        self.log_message("INFO", "Requesting Gemini AI analysis...")
        
        try:
            analysis = self.gemini.analyze_findings(findings)
            self.ai_analysis_text.setText(analysis)
            self.log_message("INFO", "Analysis complete")
        except Exception as e:
            self.log_message("ERROR", f"Error: {str(e)}")
    
    def ai_generate_summary(self):
        """Generate executive summary with Gemini AI"""
        if not self.gemini or not self.data_collector.current_operation:
            QMessageBox.warning(self, "Error", "No operation data or Gemini AI not configured")
            return
        
        self.log_message("INFO", "Generating executive summary...")
        
        try:
            summary = self.gemini.generate_executive_summary(self.data_collector.current_operation)
            self.ai_analysis_text.setText(summary)
            self.log_message("INFO", "Summary generated")
        except Exception as e:
            self.log_message("ERROR", f"Error: {str(e)}")
    
    def ai_remediation(self):
        """Generate remediation steps with Gemini AI"""
        if not self.gemini or not self.data_collector.current_operation:
            QMessageBox.warning(self, "Error", "No operation data or Gemini AI not configured")
            return
        
        findings = self.data_collector.current_operation.get("findings", [])
        if not findings:
            QMessageBox.warning(self, "Error", "No findings")
            return
        
        self.log_message("INFO", "Generating remediation steps...")
        
        try:
            remediation = self.gemini.generate_remediation_steps(findings[0])
            self.ai_analysis_text.setText(remediation)
            self.log_message("INFO", "Remediation steps generated")
        except Exception as e:
            self.log_message("ERROR", f"Error: {str(e)}")
    
    def ai_threat_model(self):
        """Generate threat model with Gemini AI"""
        if not self.gemini:
            QMessageBox.warning(self, "Error", "Gemini AI not configured")
            return
        
        target = self.target_input.text() or "Unknown"
        
        self.log_message("INFO", "Generating threat model...")
        
        try:
            threat_model = self.gemini.generate_threat_model({
                "target": target,
                "type": self.operation_type.currentText()
            })
            self.ai_analysis_text.setText(threat_model)
            self.log_message("INFO", "Threat model generated")
        except Exception as e:
            self.log_message("ERROR", f"Error: {str(e)}")
    
    def ai_chat(self):
        """Chat with Gemini AI"""
        if not self.gemini:
            QMessageBox.warning(self, "Error", "Gemini AI not configured")
            return
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Chat with Gemini AI")
        dialog.setGeometry(200, 200, 600, 400)
        
        layout = QVBoxLayout()
        
        chat_display = QTextEdit()
        chat_display.setReadOnly(True)
        layout.addWidget(chat_display)
        
        input_field = QLineEdit()
        input_field.setPlaceholderText("Ask Gemini AI about security...")
        layout.addWidget(input_field)
        
        def send_message():
            message = input_field.text()
            if message:
                chat_display.append(f"You: {message}")
                response = self.gemini.chat(message)
                chat_display.append(f"Gemini: {response}\n")
                input_field.clear()
        
        send_button = QPushButton("Send")
        send_button.clicked.connect(send_message)
        layout.addWidget(send_button)
        
        dialog.setLayout(layout)
        dialog.exec_()
    
    def add_result_row(self, severity: str, title: str, description: str, evidence: str):
        """Add a result row to the table"""
        row_position = self.results_table.rowCount()
        self.results_table.insertRow(row_position)
        
        self.results_table.setItem(row_position, 0, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))
        self.results_table.setItem(row_position, 1, QTableWidgetItem(severity.upper()))
        self.results_table.setItem(row_position, 2, QTableWidgetItem(title))
        self.results_table.setItem(row_position, 3, QTableWidgetItem(description))
        self.results_table.setItem(row_position, 4, QTableWidgetItem(evidence))
        
        color_map = {
            "high": QColor(255, 107, 107),
            "medium": QColor(255, 165, 0),
            "low": QColor(78, 205, 196),
            "info": QColor(0, 102, 204)
        }
        
        for col in range(5):
            item = self.results_table.item(row_position, col)
            if item:
                item.setBackground(color_map.get(severity.lower(), QColor(255, 255, 255)))
    
    def log_message(self, level: str, message: str):
        """Add a log message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.logs_text.append(log_entry)
        
        if self.data_collector.current_operation:
            self.data_collector.add_log(level, message)
    
    def update_statistics(self):
        """Update statistics display"""
        if not self.data_collector.current_operation:
            return
        
        findings = self.data_collector.current_operation["findings"]
        
        high = len([f for f in findings if f["severity"] == "high"])
        medium = len([f for f in findings if f["severity"] == "medium"])
        low = len([f for f in findings if f["severity"] == "low"])
        
        self.total_findings_label.setText(str(len(findings)))
        self.high_severity_label.setText(str(high))
        self.medium_severity_label.setText(str(medium))
        self.low_severity_label.setText(str(low))
    
    def pause_operation(self):
        """Pause current operation"""
        self.statusBar.showMessage("Operation paused")
        self.log_message("INFO", "Operation paused")
    
    def stop_operation(self):
        """Stop current operation"""
        self.data_collector.end_operation("stopped")
        self.statusBar.showMessage("Operation stopped")
        self.log_message("INFO", "Operation stopped")
    
    def save_report(self):
        """Save current operation report"""
        filepath = self.data_collector.save_operation()
        self.log_message("INFO", f"Report saved to: {filepath}")
        QMessageBox.information(self, "Report Saved", f"Report saved to:\n{filepath}")
    
    def new_operation(self):
        """Start a new operation"""
        self.operation_name_input.clear()
        self.target_input.clear()
        self.results_table.setRowCount(0)
        self.logs_text.clear()
        self.ai_analysis_text.clear()
        self.progress_bar.setValue(0)
        self.statusBar.showMessage("Ready for new operation")
    
    def open_report(self):
        """Open a saved report"""
        filepath, _ = QFileDialog.getOpenFileName(self, "Open Report", "./nightfury_reports", "JSON Files (*.json)")
        if filepath:
            self.log_message("INFO", f"Opened report: {filepath}")
    
    def run_quick_recon(self):
        """Run quick reconnaissance"""
        self.operation_name_input.setText("Quick Reconnaissance")
        self.operation_type.setCurrentText("Reconnaissance")
        self.start_operation()
    
    def run_full_recon(self):
        """Run full reconnaissance"""
        self.operation_name_input.setText("Full Reconnaissance")
        self.operation_type.setCurrentText("Reconnaissance")
        self.start_operation()
    
    def run_exploitation(self):
        """Run exploitation"""
        self.operation_name_input.setText("Exploitation Test")
        self.operation_type.setCurrentText("Exploitation")
        self.start_operation()
    
    def run_advanced_chain(self):
        """Run advanced exploitation chain"""
        self.operation_name_input.setText("Advanced Exploitation Chain")
        self.operation_type.setCurrentText("Full Penetration Test")
        self.start_operation()
    
    def verify_installation(self):
        """Verify framework installation"""
        self.log_message("INFO", "Verifying installation...")
        QMessageBox.information(self, "Installation", "Run: python verify_installation.py")
    
    def show_settings(self):
        """Show settings dialog"""
        QMessageBox.information(self, "Settings", "Settings dialog coming soon")
    
    def show_documentation(self):
        """Show documentation"""
        QMessageBox.information(self, "Documentation", "See RUNEHALL_QUICK_REFERENCE.md and GEMINI_SETUP.md")
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.information(self, "About", 
            "NightFury Framework v2.0 - Gemini AI Edition\n\n"
            "Advanced Penetration Testing Platform\n"
            "Powered by Google Gemini AI\n\n"
            "For authorized security testing only")
    
    def apply_stylesheet(self):
        """Apply custom stylesheet"""
        stylesheet = """
            QMainWindow {
                background-color: #f5f5f5;
            }
            QLabel {
                color: #333;
            }
            QLineEdit, QComboBox, QSpinBox {
                padding: 5px;
                border: 1px solid #ddd;
                border-radius: 3px;
            }
            QPushButton {
                padding: 8px;
                border-radius: 3px;
                font-weight: bold;
            }
            QTableWidget {
                background-color: white;
                alternate-background-color: #f9f9f9;
            }
            QTextEdit {
                background-color: #1e1e1e;
                color: #00ff00;
                font-family: Courier New;
            }
        """
        self.setStyleSheet(stylesheet)


def main():
    """Main entry point"""
    if not PYQT_AVAILABLE:
        print("[!] PyQt5 is required. Install with:")
        print("    pip install PyQt5 PyQt5-sip")
        sys.exit(1)
    
    app = QApplication(sys.argv)
    window = NightFuryGeminiGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
