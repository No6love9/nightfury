#!/usr/bin/env python3
"""
OSINT FUSION FRAMEWORK - Advanced Cross-Platform Intelligence Gathering
A comprehensive tool for analyzing gaming communities, social media, and code repositories
with advanced correlation capabilities and AI-guided workflow.
"""

import sys
import os
import re
import csv
import json
import logging
import threading
import pandas as pd
import numpy as np
from datetime import datetime
from collections import defaultdict

# GUI imports
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QCheckBox, QGroupBox,
    QComboBox, QListWidget, QListWidgetItem, QProgressBar, QMessageBox,
    QFileDialog, QSplitter, QFormLayout, QStatusBar, QTreeWidget, QTreeWidgetItem,
    QTableWidget, QTableWidgetItem, QHeaderView, QToolBar, QAction, QToolButton,
    QDialog, QInputDialog, QFrame, QGridLayout, QSizePolicy, QMenu, QSystemTrayIcon
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon, QPixmap, QTextCursor
from PyQt5.QtWebEngineWidgets import QWebEngineView
import qtmodern.styles
import qtmodern.windows

# Data processing imports
from PIL import Image
import pytesseract
import pdfplumber
import docx2txt
import openpyxl
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options

# AI/ML imports
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("osint_fusion.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("OSINT_Fusion")

class AIAssistant:
    """AI Assistant that guides users through the OSINT process"""
    
    def __init__(self):
        self.knowledge_base = self._load_knowledge_base()
        self.current_step = 0
        self.workflow_steps = [
            "Data Collection",
            "Data Processing",
            "Pattern Recognition",
            "Correlation Analysis",
            "Visualization",
            "Report Generation"
        ]
    
    def _load_knowledge_base(self):
        """Load OSINT knowledge base"""
        return {
            "Data Collection": [
                "Start by importing all available data sources",
                "Consider using the web scraper for public forums",
                "Don't forget to check archive.org for historical data"
            ],
            "Data Processing": [
                "Clean the data by removing duplicates",
                "Standardize usernames and other identifiers",
                "Extract metadata from images and documents"
            ],
            "Pattern Recognition": [
                "Look for common usernames across platforms",
                "Identify posting patterns and time zones",
                "Note any unique phrases or terminology"
            ],
            "Correlation Analysis": [
                "Cross-reference findings across multiple sources",
                "Build relationship graphs between entities",
                "Look for connections between seemingly unrelated data"
            ],
            "Visualization": [
                "Use network graphs to show relationships",
                "Timeline views can reveal activity patterns",
                "Geographic mapping can show physical connections"
            ],
            "Report Generation": [
                "Document all findings with supporting evidence",
                "Include methodology for reproducibility",
                "Highlight the most significant discoveries"
            ]
        }
    
    def get_guidance(self, current_step=None):
        """Get guidance for the current step"""
        if current_step is not None:
            self.current_step = current_step
        
        if self.current_step >= len(self.workflow_steps):
            return "Analysis complete! Review your findings and generate a report."
        
        current_phase = self.workflow_steps[self.current_step]
        tips = self.knowledge_base.get(current_phase, ["No specific guidance available for this phase."])
        
        guidance = f"## Phase: {current_phase}\n\n"
        guidance += "### Recommended Actions:\n"
        for i, tip in enumerate(tips, 1):
            guidance += f"{i}. {tip}\n"
        
        guidance += f"\nNext phase: {self.workflow_steps[self.current_step + 1] if self.current_step + 1 < len(self.workflow_steps) else 'Complete'}"
        
        return guidance
    
    def next_step(self):
        """Advance to the next step"""
        if self.current_step < len(self.workflow_steps) - 1:
            self.current_step += 1
        return self.get_guidance()
    
    def previous_step(self):
        """Go back to the previous step"""
        if self.current_step > 0:
            self.current_step -= 1
        return self.get_guidance()

class DataImporter:
    """Handles importing data from various file formats"""
    
    def __init__(self):
        self.supported_formats = {
            '.txt': self._import_text,
            '.csv': self._import_csv,
            '.json': self._import_json,
            '.xlsx': self._import_excel,
            '.xls': self._import_excel,
            '.pdf': self._import_pdf,
            '.docx': self._import_docx,
            '.doc': self._import_doc,
            '.png': self._import_image,
            '.jpg': self._import_image,
            '.jpeg': self._import_image,
            '.gif': self._import_image,
            '.bmp': self._import_image
        }
    
    def import_data(self, file_path):
        """Import data from a file based on its extension"""
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        if ext in self.supported_formats:
            try:
                return self.supported_formats[ext](file_path)
            except Exception as e:
                logger.error(f"Error importing {file_path}: {e}")
                return None
        else:
            logger.warning(f"Unsupported file format: {ext}")
            return None
    
    def _import_text(self, file_path):
        """Import text from a plain text file"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return {'content': f.read(), 'type': 'text', 'path': file_path}
    
    def _import_csv(self, file_path):
        """Import data from a CSV file"""
        df = pd.read_csv(file_path)
        return {'data': df.to_dict('records'), 'type': 'tabular', 'path': file_path}
    
    def _import_json(self, file_path):
        """Import data from a JSON file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            return {'data': json.load(f), 'type': 'json', 'path': file_path}
    
    def _import_excel(self, file_path):
        """Import data from an Excel file"""
        df = pd.read_excel(file_path)
        return {'data': df.to_dict('records'), 'type': 'tabular', 'path': file_path}
    
    def _import_pdf(self, file_path):
        """Extract text from a PDF file"""
        text = ""
        with pdfplumber.open(file_path) as pdf:
            for page in pdf.pages:
                text += page.extract_text() + "\n"
        return {'content': text, 'type': 'text', 'path': file_path}
    
    def _import_docx(self, file_path):
        """Extract text from a DOCX file"""
        text = docx2txt.process(file_path)
        return {'content': text, 'type': 'text', 'path': file_path}
    
    def _import_doc(self, file_path):
        """Extract text from a DOC file (placeholder)"""
        # This is a simplified version - in production, you might use antiword or other tools
        return {'content': f"Binary DOC file: {file_path}", 'type': 'text', 'path': file_path}
    
    def _import_image(self, file_path):
        """Extract text from an image using OCR"""
        try:
            text = pytesseract.image_to_string(Image.open(file_path))
            return {'content': text, 'type': 'text', 'path': file_path, 'image_data': file_path}
        except Exception as e:
            logger.error(f"OCR failed for {file_path}: {e}")
            return {'content': f"OCR failed: {e}", 'type': 'text', 'path': file_path, 'image_data': file_path}

class WebScraper(QThread):
    """Web scraping worker thread"""
    
    progress = pyqtSignal(int)
    result = pyqtSignal(dict)
    finished = pyqtSignal()
    status = pyqtSignal(str)
    
    def __init__(self, sites_to_scrape, search_terms):
        super().__init__()
        self.sites_to_scrape = sites_to_scrape
        self.search_terms = search_terms
        self.driver = None
        self.is_running = True
    
    def run(self):
        """Run the web scraping process"""
        try:
            # Set up headless Chrome
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
            
            self.driver = webdriver.Chrome(options=chrome_options)
            results = {}
            
            total_sites = len(self.sites_to_scrape)
            for i, site in enumerate(self.sites_to_scrape):
                if not self.is_running:
                    break
                    
                self.status.emit(f"Scraping {site}...")
                site_results = self.scrape_site(site)
                results[site] = site_results
                
                progress = int((i + 1) / total_sites * 100)
                self.progress.emit(progress)
            
            self.result.emit(results)
            
        except Exception as e:
            logger.error(f"Web scraping error: {e}")
            self.result.emit({'error': str(e)})
        finally:
            if self.driver:
                self.driver.quit()
            self.finished.emit()
    
    def scrape_site(self, site):
        """Scrape a specific site based on its type"""
        try:
            if "runehall.com" in site:
                return self.scrape_runehall(site)
            elif "runewager.com" in site:
                return self.scrape_runewager(site)
            elif "runechat.com" in site:
                return self.scrape_runechat(site)
            elif "facebook.com" in site:
                return self.scrape_facebook(site)
            elif "tiktok.com" in site:
                return self.scrape_tiktok(site)
            else:
                return self.scrape_general(site)
        except Exception as e:
            logger.error(f"Error scraping {site}: {e}")
            return {"error": str(e)}
    
    def scrape_runehall(self, url):
        """Scrape RuneHall for user information"""
        self.driver.get(url)
        
        # Wait for page to load
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        
        # Extract user information
        users = []
        try:
            # This is a simplified example - actual implementation would need to adapt to site structure
            user_elements = self.driver.find_elements(By.CLASS_NAME, "user")
            for user_element in user_elements:
                username = user_element.find_element(By.CLASS_NAME, "username").text
                post_count = user_element.find_element(By.CLASS_NAME, "post-count").text
                join_date = user_element.find_element(By.CLASS_NAME, "join-date").text
                
                users.append({
                    "username": username,
                    "post_count": post_count,
                    "join_date": join_date,
                    "source": url
                })
        except Exception as e:
            logger.warning(f"Could not extract detailed user info from {url}: {e}")
        
        # Extract page content
        content = self.driver.find_element(By.TAG_NAME, "body").text
        
        return {
            "content": content,
            "users": users,
            "url": url
        }
    
    def scrape_runewager(self, url):
        """Scrape RuneWager for user information"""
        # Similar implementation to scrape_runehall
        # Adapted to RuneWager's structure
        self.driver.get(url)
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        
        content = self.driver.find_element(By.TAG_NAME, "body").text
        
        return {
            "content": content,
            "url": url
        }
    
    def scrape_runechat(self, url):
        """Scrape RuneChat for user information"""
        # Similar implementation to scrape_runehall
        # Adapted to RuneChat's structure
        self.driver.get(url)
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        
        content = self.driver.find_element(By.TAG_NAME, "body").text
        
        return {
            "content": content,
            "url": url
        }
    
    def scrape_facebook(self, url):
        """Scrape Facebook for public information"""
        # Note: Facebook scraping is limited by their terms of service
        # This should only be used for publicly available information
        self.driver.get(url)
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        
        content = self.driver.find_element(By.TAG_NAME, "body").text
        
        return {
            "content": content,
            "url": url,
            "note": "Facebook data extraction is limited to public information only"
        }
    
    def scrape_tiktok(self, url):
        """Scrape TikTok for public information"""
        # Note: TikTok scraping is limited by their terms of service
        self.driver.get(url)
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        
        content = self.driver.find_element(By.TAG_NAME, "body").text
        
        return {
            "content": content,
            "url": url,
            "note": "TikTok data extraction is limited to public information only"
        }
    
    def scrape_general(self, url):
        """Scrape a general website"""
        self.driver.get(url)
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        
        content = self.driver.find_element(By.TAG_NAME, "body").text
        
        return {
            "content": content,
            "url": url
        }
    
    def stop(self):
        """Stop the scraping process"""
        self.is_running = False
        if self.driver:
            self.driver.quit()

class CorrelationEngine:
    """Advanced correlation engine for finding connections between data points"""
    
    def __init__(self):
        self.data_points = []
        self.entity_graph = nx.Graph()
        self.patterns = []
    
    def add_data(self, data):
        """Add data to the correlation engine"""
        if isinstance(data, list):
            self.data_points.extend(data)
        else:
            self.data_points.append(data)
    
    def add_log_data(self, log_data):
        """Add log analysis data to the correlation engine"""
        # Extract subdomains and add to correlation data
        for domain, data in log_data.get('domains', {}).items():
            for subdomain in data.get('subdomains', []):
                self.add_data({
                    'type': 'subdomain',
                    'domain': domain,
                    'subdomain': subdomain,
                    'source': 'log_analysis'
                })
        
        # Add technologies found
        for finding in log_data.get('findings', []):
            if finding['type'] == 'technologies':
                for tech in finding['details']:
                    self.add_data({
                        'type': 'technology',
                        'technology': tech,
                        'source': 'log_analysis'
                    })
    
    def extract_entities(self):
        """Extract entities from the collected data"""
        entities = {
            'usernames': set(),
            'emails': set(),
            'phones': set(),
            'locations': set(),
            'ips': set(),
            'domains': set()
        }
        
        for data_point in self.data_points:
            if isinstance(data_point, dict):
                content = data_point.get('content', '')
                source = data_point.get('source', 'unknown')
                
                # Extract usernames (common patterns)
                usernames = re.findall(r'@([a-zA-Z0-9_]{3,})', content)
                entities['usernames'].update([(u, source) for u in usernames])
                
                # Extract emails
                emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
                entities['emails'].update([(e, source) for e in emails])
                
                # Extract phone numbers
                phones = re.findall(r'(\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4})', content)
                entities['phones'].update([(p, source) for p in phones])
                
                # Extract IP addresses
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
                entities['ips'].update([(ip, source) for ip in ips])
                
                # Extract domains
                domains = re.findall(r'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', content)
                entities['domains'].update([(d, source) for d in domains])
        
        return entities
    
    def build_correlation_graph(self):
        """Build a graph of correlations between entities"""
        entities = self.extract_entities()
        
        # Add nodes for each entity type
        for entity_type, values in entities.items():
            for value, source in values:
                self.entity_graph.add_node(f"{entity_type}_{value}", type=entity_type, value=value, source=source)
        
        # Create connections between entities that share sources
        source_entities = defaultdict(list)
        for node, data in self.entity_graph.nodes(data=True):
            source_entities[data['source']].append(node)
        
        for source, nodes in source_entities.items():
            if len(nodes) > 1:
                for i in range(len(nodes)):
                    for j in range(i + 1, len(nodes)):
                        self.entity_graph.add_edge(nodes[i], nodes[j], weight=1, type="shared_source")
        
        return self.entity_graph
    
    def find_connections(self, entity, depth=2):
        """Find connections to a specific entity"""
        if entity not in self.entity_graph:
            return []
        
        # Use BFS to find connections within specified depth
        connections = []
        visited = set()
        queue = [(entity, 0)]
        
        while queue:
            node, current_depth = queue.pop(0)
            if node in visited or current_depth > depth:
                continue
            
            visited.add(node)
            if node != entity:
                connections.append((node, current_depth))
            
            for neighbor in self.entity_graph.neighbors(node):
                if neighbor not in visited:
                    queue.append((neighbor, current_depth + 1))
        
        return connections
    
    def detect_patterns(self):
        """Detect patterns in the data"""
        # Cluster similar content using TF-IDF and DBSCAN
        text_data = []
        for data_point in self.data_points:
            if isinstance(data_point, dict) and 'content' in data_point:
                text_data.append(data_point['content'])
        
        if len(text_data) > 1:
            vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
            X = vectorizer.fit_transform(text_data)
            
            # Use DBSCAN for clustering
            dbscan = DBSCAN(eps=0.5, min_samples=2)
            clusters = dbscan.fit_predict(X.toarray())
            
            # Group data by cluster
            clustered_data = defaultdict(list)
            for i, cluster_id in enumerate(clusters):
                if cluster_id != -1:  # Ignore noise
                    clustered_data[cluster_id].append(self.data_points[i])
            
            self.patterns = clustered_data
        
        return self.patterns

class ModernButton(QPushButton):
    """Modern styled button"""
    
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(35)
        self.setStyleSheet("""
            QPushButton {
                background-color: #5a9cff;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3d8eff;
            }
            QPushButton:pressed {
                background-color: #2a7ae9;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)

class GraphCanvas(FigureCanvas):
    """Matplotlib graph canvas for PyQt"""
    
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        self.fig, self.ax = plt.subplots(figsize=(width, height), dpi=dpi)
        super().__init__(self.fig)
        self.setParent(parent)
        
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.updateGeometry()
    
    def plot_network(self, graph):
        """Plot a network graph"""
        self.ax.clear()
        
        pos = nx.spring_layout(graph, k=1, iterations=50)
        node_colors = []
        
        for node in graph.nodes():
            node_type = graph.nodes[node].get('type', 'unknown')
            if node_type == 'usernames':
                node_colors.append('lightblue')
            elif node_type == 'emails':
                node_colors.append('lightgreen')
            elif node_type == 'phones':
                node_colors.append('lightcoral')
            elif node_type == 'locations':
                node_colors.append('lightyellow')
            elif node_type == 'ips':
                node_colors.append('lightpink')
            elif node_type == 'domains':
                node_colors.append('lightgray')
            else:
                node_colors.append('orange')
        
        nx.draw_networkx_nodes(graph, pos, node_color=node_colors, node_size=500, ax=self.ax)
        nx.draw_networkx_edges(graph, pos, alpha=0.5, ax=self.ax)
        nx.draw_networkx_labels(graph, pos, font_size=8, ax=self.ax)
        
        self.ax.set_title("Entity Correlation Network")
        self.ax.axis('off')
        self.fig.tight_layout()
        self.draw()

class LogAnalyzer:
    """Advanced log analysis for OSINT tool outputs"""
    
    def __init__(self):
        self.subdomains = defaultdict(list)
        self.crawled_urls = []
        self.scan_results = []
        self.entity_graph = nx.Graph()
    
    def parse_osint_log(self, log_content):
        """Parse OSINT tool log content"""
        lines = log_content.split('\n')
        
        # Parse subdomain enumeration results
        current_domain = None
        for line in lines:
            # Check for subdomain completion lines
            subdomain_match = re.search(r'\[\+\] Loaded (\d+) subdomains for (.+)', line)
            if subdomain_match:
                count, domain = subdomain_match.groups()
                current_domain = domain
                continue
                
            # Check for crawling lines
            crawl_match = re.search(r'\[\*\] Crawling: (https?://[^\s]+)', line)
            if crawl_match:
                url = crawl_match.group(1)
                self.crawled_urls.append(url)
                
                # Extract subdomain from URL
                if current_domain and current_domain in url:
                    subdomain = url.split('//')[1].split('/')[0]
                    if subdomain not in self.subdomains[current_domain]:
                        self.subdomains[current_domain].append(subdomain)
        
        return {
            'subdomains': dict(self.subdomains),
            'crawled_urls': self.crawled_urls,
            'crawled_count': len(self.crawled_urls)
        }
    
    def extract_entities_from_urls(self):
        """Extract entities from crawled URLs"""
        entities = {
            'usernames': set(),
            'parameters': set(),
            'paths': set(),
            'technologies': set()
        }
        
        for url in self.crawled_urls:
            # Extract URL parameters
            if '?' in url:
                params = url.split('?')[1]
                if '&' in params:
                    for param in params.split('&'):
                        if '=' in param:
                            entities['parameters'].add(param.split('=')[0])
            
            # Extract path components
            path = url.split('//')[1].split('/')[1:]
            for component in path:
                if component and not component.startswith('?'):
                    entities['paths'].add(component)
            
            # Guess technologies from paths
            if 'api' in url:
                entities['technologies'].add('API')
            if 'admin' in url:
                entities['technologies'].add('Admin Panel')
            if 'blog' in url:
                entities['technologies'].add('WordPress/Blog')
            if 'cdn' in url:
                entities['technologies'].add('CDN')
            if 'static' in url:
                entities['technologies'].add('Static Resources')
            if 'staging' in url:
                entities['technologies'].add('Staging Environment')
        
        return entities
    
    def build_domain_relationship_graph(self):
        """Build a graph showing relationships between domains and subdomains"""
        for domain, subdomains in self.subdomains.items():
            self.entity_graph.add_node(domain, type='domain')
            for subdomain in subdomains:
                self.entity_graph.add_node(subdomain, type='subdomain')
                self.entity_graph.add_edge(domain, subdomain, relationship='subdomain')
        
        return self.entity_graph
    
    def generate_log_report(self):
        """Generate a comprehensive report from the log analysis"""
        report = {
            'summary': {
                'domains_analyzed': len(self.subdomains),
                'total_subdomains': sum(len(subs) for subs in self.subdomains.values()),
                'urls_crawled': len(self.crawled_urls),
                'analysis_date': datetime.now().isoformat()
            },
            'domains': {},
            'findings': []
        }
        
        for domain, subdomains in self.subdomains.items():
            report['domains'][domain] = {
                'subdomain_count': len(subdomains),
                'subdomains': subdomains,
                'crawled_urls': [url for url in self.crawled_urls if domain in url]
            }
        
        # Add technology findings
        entities = self.extract_entities_from_urls()
        if entities['technologies']:
            report['findings'].append({
                'type': 'technologies',
                'description': 'Technologies identified from URL patterns',
                'details': list(entities['technologies'])
            })
        
        # Add parameter findings
        if entities['parameters']:
            report['findings'].append({
                'type': 'parameters',
                'description': 'URL parameters discovered',
                'details': list(entities['parameters'])
            })
        
        return report

class OSINTFusionGUI(QMainWindow):
    """Main GUI for the OSINT Fusion Framework"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OSINT Fusion Framework")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize components
        self.data_importer = DataImporter()
        self.correlation_engine = CorrelationEngine()
        self.ai_assistant = AIAssistant()
        self.log_analyzer = LogAnalyzer()
        self.scraper = None
        self.imported_data = []
        self.scraping_results = {}
        
        # Setup UI
        self.setup_ui()
        
        # Apply dark theme
        self.apply_dark_theme()
        
        # Show initial AI guidance
        self.update_ai_guidance()
    
    def setup_ui(self):
        """Setup the user interface"""
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        
        # Create sidebar for AI assistant
        sidebar = QFrame()
        sidebar.setFixedWidth(300)
        sidebar.setFrameShape(QFrame.StyledPanel)
        sidebar_layout = QVBoxLayout(sidebar)
        
        # AI Assistant section
        ai_group = QGroupBox("AI Assistant")
        ai_layout = QVBoxLayout()
        
        self.ai_guidance = QTextEdit()
        self.ai_guidance.setReadOnly(True)
        ai_layout.addWidget(self.ai_guidance)
        
        ai_buttons_layout = QHBoxLayout()
        self.prev_btn = ModernButton("Previous Step")
        self.prev_btn.clicked.connect(self.prev_ai_step)
        ai_buttons_layout.addWidget(self.prev_btn)
        
        self.next_btn = ModernButton("Next Step")
        self.next_btn.clicked.connect(self.next_ai_step)
        ai_buttons_layout.addWidget(self.next_btn)
        
        ai_layout.addLayout(ai_buttons_layout)
        ai_group.setLayout(ai_layout)
        sidebar_layout.addWidget(ai_group)
        
        # Data overview section
        data_group = QGroupBox("Data Overview")
        data_layout = QVBoxLayout()
        
        self.data_stats = QTextEdit()
        self.data_stats.setReadOnly(True)
        self.data_stats.setMaximumHeight(150)
        data_layout.addWidget(self.data_stats)
        
        data_group.setLayout(data_layout)
        sidebar_layout.addWidget(data_group)
        
        sidebar_layout.addStretch()
        main_layout.addWidget(sidebar)
        
        # Create main tabs
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.North)
        self.tabs.setDocumentMode(True)
        main_layout.addWidget(self.tabs)
        
        # Create tabs
        self.setup_data_tab()
        self.setup_scraping_tab()
        self.setup_analysis_tab()
        self.setup_visualization_tab()
        self.setup_log_analysis_tab()
        self.setup_report_tab()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Create toolbar
        self.setup_toolbar()
        
        # Update data stats initially
        self.update_data_stats()
    
    def setup_toolbar(self):
        """Setup the toolbar"""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)
        
        # Import action
        import_action = QAction(QIcon.fromTheme("document-open"), "Import Data", self)
        import_action.triggered.connect(self.import_data)
        toolbar.addAction(import_action)
        
        # Scrape action
        scrape_action = QAction(QIcon.fromTheme("emblem-web"), "Start Scraping", self)
        scrape_action.triggered.connect(self.start_scraping)
        toolbar.addAction(scrape_action)
        
        # Analyze action
        analyze_action = QAction(QIcon.fromTheme("office-chart-bar"), "Analyze Data", self)
        analyze_action.triggered.connect(self.analyze_data)
        toolbar.addAction(analyze_action)
        
        # Export action
        export_action = QAction(QIcon.fromTheme("document-save"), "Export Report", self)
        export_action.triggered.connect(self.export_report)
        toolbar.addAction(export_action)
    
    def setup_data_tab(self):
        """Setup the data import tab"""
        data_tab = QWidget()
        layout = QVBoxLayout(data_tab)
        
        # Import section
        import_group = QGroupBox("Data Import")
        import_layout = QVBoxLayout()
        
        import_buttons_layout = QHBoxLayout()
        self.import_btn = ModernButton("Import Files")
        self.import_btn.clicked.connect(self.import_data)
        import_buttons_layout.addWidget(self.import_btn)
        
        self.clear_btn = ModernButton("Clear Data")
        self.clear_btn.clicked.connect(self.clear_data)
        import_buttons_layout.addWidget(self.clear_btn)
        
        import_layout.addLayout(import_buttons_layout)
        
        # File list
        self.file_list = QListWidget()
        import_layout.addWidget(self.file_list)
        
        import_group.setLayout(import_layout)
        layout.addWidget(import_group)
        
        # Preview section
        preview_group = QGroupBox("Data Preview")
        preview_layout = QVBoxLayout()
        
        self.data_preview = QTextEdit()
        self.data_preview.setReadOnly(True)
        preview_layout.addWidget(self.data_preview)
        
        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)
        
        self.tabs.addTab(data_tab, "📁 Data")
    
    def setup_scraping_tab(self):
        """Setup the web scraping tab"""
        scraping_tab = QWidget()
        layout = QVBoxLayout(scraping_tab)
        
        # Configuration section
        config_group = QGroupBox("Scraping Configuration")
        config_layout = QFormLayout()
        
        self.sites_input = QTextEdit()
        self.sites_input.setPlaceholderText("Enter URLs to scrape (one per line)\nExample: https://www.runehall.com\nhttps://www.runewager.com")
        config_layout.addRow("Sites to scrape:", self.sites_input)
        
        self.terms_input = QLineEdit()
        self.terms_input.setPlaceholderText("Enter search terms (comma-separated)")
        config_layout.addRow("Search terms:", self.terms_input)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Control section
        control_group = QGroupBox("Scraping Controls")
        control_layout = QVBoxLayout()
        
        self.scrape_btn = ModernButton("Start Scraping")
        self.scrape_btn.clicked.connect(self.start_scraping)
        control_layout.addWidget(self.scrape_btn)
        
        self.stop_btn = ModernButton("Stop Scraping")
        self.stop_btn.clicked.connect(self.stop_scraping)
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.stop_btn)
        
        self.scraping_progress = QProgressBar()
        control_layout.addWidget(self.scraping_progress)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Results section
        results_group = QGroupBox("Scraping Results")
        results_layout = QVBoxLayout()
        
        self.scraping_results_view = QTextEdit()
        self.scraping_results_view.setReadOnly(True)
        results_layout.addWidget(self.scraping_results_view)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        self.tabs.addTab(scraping_tab, "🌐 Web Scraping")
    
    def setup_analysis_tab(self):
        """Setup the data analysis tab"""
        analysis_tab = QWidget()
        layout = QVBoxLayout(analysis_tab)
        
        # Control section
        control_group = QGroupBox("Analysis Controls")
        control_layout = QVBoxLayout()
        
        self.analyze_btn = ModernButton("Analyze Data")
        self.analyze_btn.clicked.connect(self.analyze_data)
        control_layout.addWidget(self.analyze_btn)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Results section
        results_group = QGroupBox("Analysis Results")
        results_layout = QVBoxLayout()
        
        self.analysis_results = QTextEdit()
        self.analysis_results.setReadOnly(True)
        results_layout.addWidget(self.analysis_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Entities section
        entities_group = QGroupBox("Extracted Entities")
        entities_layout = QVBoxLayout()
        
        self.entities_view = QTextEdit()
        self.entities_view.setReadOnly(True)
        entities_layout.addWidget(self.entities_view)
        
        results_group.setLayout(entities_layout)
        layout.addWidget(entities_group)
        
        self.tabs.addTab(analysis_tab, "🔍 Analysis")
    
    def setup_visualization_tab(self):
        """Setup the visualization tab"""
        visualization_tab = QWidget()
        layout = QVBoxLayout(visualization_tab)
        
        # Control section
        control_group = QGroupBox("Visualization Controls")
        control_layout = QVBoxLayout()
        
        self.visualize_btn = ModernButton("Generate Visualization")
        self.visualize_btn.clicked.connect(self.generate_visualization)
        control_layout.addWidget(self.visualize_btn)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Graph section
        graph_group = QGroupBox("Correlation Network")
        graph_layout = QVBoxLayout()
        
        self.graph_canvas = GraphCanvas(self, width=10, height=8, dpi=100)
        graph_layout.addWidget(self.graph_canvas)
        
        graph_group.setLayout(graph_layout)
        layout.addWidget(graph_group)
        
        self.tabs.addTab(visualization_tab, "📊 Visualization")
    
    def setup_log_analysis_tab(self):
        """Setup the log analysis tab"""
        log_tab = QWidget()
        layout = QVBoxLayout(log_tab)
        
        # Log import section
        import_group = QGroupBox("OSINT Log Import")
        import_layout = QVBoxLayout()
        
        self.log_input = QTextEdit()
        self.log_input.setPlaceholderText("Paste OSINT tool log content here...")
        import_layout.addWidget(self.log_input)
        
        import_buttons_layout = QHBoxLayout()
        self.analyze_log_btn = ModernButton("Analyze Log")
        self.analyze_log_btn.clicked.connect(self.analyze_osint_log)
        import_buttons_layout.addWidget(self.analyze_log_btn)
        
        self.clear_log_btn = ModernButton("Clear Log")
        self.clear_log_btn.clicked.connect(self.clear_log)
        import_buttons_layout.addWidget(self.clear_log_btn)
        
        import_layout.addLayout(import_buttons_layout)
        import_group.setLayout(import_layout)
        layout.addWidget(import_group)
        
        # Log analysis results
        results_group = QGroupBox("Log Analysis Results")
        results_layout = QVBoxLayout()
        
        self.log_results = QTextEdit()
        self.log_results.setReadOnly(True)
        results_layout.addWidget(self.log_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Visualization section
        viz_group = QGroupBox("Domain Relationship Visualization")
        viz_layout = QVBoxLayout()
        
        self.log_graph_canvas = FigureCanvas(plt.figure(figsize=(10, 8)))
        viz_layout.addWidget(self.log_graph_canvas)
        
        viz_group.setLayout(viz_layout)
        layout.addWidget(viz_group)
        
        self.tabs.addTab(log_tab, "📋 Log Analysis")
    
    def setup_report_tab(self):
        """Setup the report generation tab"""
        report_tab = QWidget()
        layout = QVBoxLayout(report_tab)
        
        # Control section
        control_group = QGroupBox("Report Generation")
        control_layout = QVBoxLayout()
        
        self.generate_btn = ModernButton("Generate Report")
        self.generate_btn.clicked.connect(self.generate_report)
        control_layout.addWidget(self.generate_btn)
        
        self.export_btn = ModernButton("Export Report")
        self.export_btn.clicked.connect(self.export_report)
        control_layout.addWidget(self.export_btn)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Report section
        report_group = QGroupBox("Report Preview")
        report_layout = QVBoxLayout()
        
        self.report_view = QTextEdit()
        report_layout.addWidget(self.report_view)
        
        report_group.setLayout(report_layout)
        layout.addWidget(report_group)
        
        self.tabs.addTab(report_tab, "📝 Report")
    
    def apply_dark_theme(self):
        """Apply a dark theme to the application"""
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, QColor(220, 220, 220))
        dark_palette.setColor(QPalette.Base, QColor(30, 32, 38))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, QColor(220, 220, 220))
        dark_palette.setColor(QPalette.ToolTipText, QColor(220, 220, 220))
        dark_palette.setColor(QPalette.Text, QColor(220, 220, 220))
        dark_palette.setColor(QPalette.Button, QColor(61, 142, 255))
        dark_palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Highlight, QColor(61, 142, 255))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        
        self.setPalette(dark_palette)
        
        # Set style for specific widgets
        self.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #4a4a4a;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #61aeee;
            }
            QTextEdit, QListWidget, QLineEdit {
                background-color: #282c34;
                color: #abb2bf;
                border: 1px solid #4a4a4a;
                border-radius: 5px;
                padding: 8px;
                font-family: 'Consolas';
            }
            QPushButton {
                background-color: #3d8eff;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                min-height: 30px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #5a9cff;
            }
            QPushButton:disabled {
                background-color: #555;
            }
            QTabWidget::pane {
                border: 1px solid #4a4a4a;
                background: #282c34;
            }
            QTabBar::tab {
                background: #282c34;
                color: #abb2bf;
                padding: 10px;
                border: 1px solid #4a4a4a;
                border-bottom: none;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background: #3d8eff;
                color: white;
                border-color: #4a4a4a;
            }
            QProgressBar {
                border: 1px solid #4a4a4a;
                border-radius: 5px;
                text-align: center;
                background: #282c34;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #3d8eff;
                width: 10px;
            }
            QStatusBar {
                background: #21252b;
                color: #abb2bf;
                padding: 4px;
            }
            QToolBar {
                background: #21252b;
                border: none;
                spacing: 5px;
            }
            QToolButton {
                background: #3d8eff;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 5px;
            }
            QToolButton:hover {
                background: #5a9cff;
            }
            QSplitter::handle {
                background: #4a4a4a;
            }
        """)
    
    def update_ai_guidance(self):
        """Update the AI guidance text"""
        guidance = self.ai_assistant.get_guidance()
        self.ai_guidance.setMarkdown(guidance)
    
    def next_ai_step(self):
        """Advance to the next AI step"""
        guidance = self.ai_assistant.next_step()
        self.ai_guidance.setMarkdown(guidance)
        self.update_data_stats()
    
    def prev_ai_step(self):
        """Go back to the previous AI step"""
        guidance = self.ai_assistant.previous_step()
        self.ai_guidance.setMarkdown(guidance)
        self.update_data_stats()
    
    def import_data(self):
        """Import data from files"""
        file_dialog = QFileDialog()
        file_paths, _ = file_dialog.getOpenFileNames(
            self, "Select Files to Import", "",
            "All Supported Files (*.txt *.csv *.json *.xlsx *.xls *.pdf *.docx *.doc *.png *.jpg *.jpeg *.gif *.bmp);;"
            "Text Files (*.txt);;CSV Files (*.csv);;JSON Files (*.json);;Excel Files (*.xlsx *.xls);;"
            "PDF Files (*.pdf);;Word Documents (*.docx *.doc);;Images (*.png *.jpg *.jpeg *.gif *.bmp)"
        )
        
        if not file_paths:
            return
        
        for file_path in file_paths:
            data = self.data_importer.import_data(file_path)
            if data:
                self.imported_data.append(data)
                self.file_list.addItem(QListWidgetItem(file_path))
        
        self.status_bar.showMessage(f"Imported {len(file_paths)} files")
        self.update_data_stats()
        
        # Show preview of the first file
        if self.imported_data:
            self.show_data_preview(0)
    
    def show_data_preview(self, index):
        """Show preview of the selected data"""
        if index < 0 or index >= len(self.imported_data):
            return
        
        data = self.imported_data[index]
        preview_text = f"File: {data.get('path', 'Unknown')}\n"
        preview_text += f"Type: {data.get('type', 'Unknown')}\n\n"
        
        if data['type'] == 'text':
            content = data.get('content', 'No content')
            preview_text += content[:1000] + ("..." if len(content) > 1000 else "")
        elif data['type'] == 'tabular':
            preview_text += f"Table with {len(data.get('data', []))} rows\n"
            if data.get('data'):
                preview_text += "First row:\n"
                for key, value in list(data['data'][0].items())[:5]:
                    preview_text += f"  {key}: {value}\n"
        elif data['type'] == 'json':
            preview_text += f"JSON data: {json.dumps(data.get('data', {}), indent=2)[:1000]}..."
        
        self.data_preview.setPlainText(preview_text)
    
    def clear_data(self):
        """Clear all imported data"""
        self.imported_data = []
        self.file_list.clear()
        self.data_preview.clear()
        self.update_data_stats()
        self.status_bar.showMessage("Data cleared")
    
    def update_data_stats(self):
        """Update the data statistics display"""
        stats_text = f"Data Points: {len(self.imported_data)}\n"
        
        # Count by type
        type_count = {}
        for data in self.imported_data:
            data_type = data.get('type', 'unknown')
            type_count[data_type] = type_count.get(data_type, 0) + 1
        
        for data_type, count in type_count.items():
            stats_text += f"{data_type.capitalize()}: {count}\n"
        
        # Add scraping results if available
        if self.scraping_results:
            stats_text += f"\nScraped Sites: {len(self.scraping_results)}"
        
        self.data_stats.setPlainText(stats_text)
    
    def start_scraping(self):
        """Start the web scraping process"""
        sites_text = self.sites_input.toPlainText().strip()
        if not sites_text:
            QMessageBox.warning(self, "Warning", "Please enter at least one URL to scrape")
            return
        
        sites = [site.strip() for site in sites_text.split('\n') if site.strip()]
        search_terms = [term.strip() for term in self.terms_input.text().split(',') if term.strip()]
        
        self.scraper = WebScraper(sites, search_terms)
        self.scraper.progress.connect(self.scraping_progress.setValue)
        self.scraper.result.connect(self.handle_scraping_results)
        self.scraper.status.connect(self.status_bar.showMessage)
        self.scraper.finished.connect(self.scraping_finished)
        
        self.scrape_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.scraping_results_view.setPlainText("Scraping started...")
        
        self.scraper.start()
    
    def stop_scraping(self):
        """Stop the web scraping process"""
        if self.scraper:
            self.scraper.stop()
            self.scraping_finished()
    
    def handle_scraping_results(self, results):
        """Handle the results from web scraping"""
        self.scraping_results = results
        self.scraping_results_view.setPlainText(json.dumps(results, indent=2))
        
        # Add scraping results to imported data
        for site, data in results.items():
            if 'error' not in data:
                self.imported_data.append({
                    'content': data.get('content', ''),
                    'type': 'text',
                    'source': f"web_scraping:{site}",
                    'url': site
                })
        
        self.update_data_stats()
        self.status_bar.showMessage(f"Scraping completed: {len(results)} sites")
    
    def scraping_finished(self):
        """Handle scraping finished signal"""
        self.scrape_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_bar.showMessage("Scraping finished")
    
    def analyze_data(self):
        """Analyze the collected data"""
        if not self.imported_data:
            QMessageBox.warning(self, "Warning", "No data to analyze. Please import data first.")
            return
        
        # Add data to correlation engine
        self.correlation_engine.add_data(self.imported_data)
        
        # Extract entities
        entities = self.correlation_engine.extract_entities()
        
        # Display entities
        entities_text = "Extracted Entities:\n\n"
        for entity_type, values in entities.items():
            entities_text += f"{entity_type.upper()}:\n"
            for value, source in values:
                entities_text += f"  {value} (from {source})\n"
            entities_text += "\n"
        
        self.entities_view.setPlainText(entities_text)
        
        # Build correlation graph
        graph = self.correlation_engine.build_correlation_graph()
        
        # Detect patterns
        patterns = self.correlation_engine.detect_patterns()
        
        # Display analysis results
        analysis_text = f"Analysis Complete!\n\n"
        analysis_text += f"Entities extracted: {sum(len(v) for v in entities.values())}\n"
        analysis_text += f"Correlation graph nodes: {len(graph.nodes())}\n"
        analysis_text += f"Correlation graph edges: {len(graph.edges())}\n"
        analysis_text += f"Patterns detected: {len(patterns)}\n\n"
        
        # Show some example correlations
        if entities['usernames']:
            example_username = list(entities['usernames'])[0][0]
            connections = self.correlation_engine.find_connections(f"usernames_{example_username}")
            
            analysis_text += f"Example correlations for '{example_username}':\n"
            for node, depth in connections[:5]:  # Show first 5 connections
                node_type = graph.nodes[node].get('type', 'unknown')
                node_value = graph.nodes[node].get('value', 'unknown')
                analysis_text += f"  - {node_type}: {node_value} (distance: {depth})\n"
        
        self.analysis_results.setPlainText(analysis_text)
        self.status_bar.showMessage("Analysis completed")
        
        # Advance AI step
        self.next_ai_step()
    
    def generate_visualization(self):
        """Generate visualization of the correlation graph"""
        if not hasattr(self.correlation_engine, 'entity_graph') or len(self.correlation_engine.entity_graph.nodes()) == 0:
            QMessageBox.warning(self, "Warning", "No correlation data to visualize. Please analyze data first.")
            return
        
        self.graph_canvas.plot_network(self.correlation_engine.entity_graph)
        self.status_bar.showMessage("Visualization generated")
        
        # Advance AI step
        self.next_ai_step()
    
    def analyze_osint_log(self):
        """Analyze OSINT tool log content"""
        log_content = self.log_input.toPlainText()
        if not log_content.strip():
            QMessageBox.warning(self, "Warning", "Please paste log content first")
            return
        
        try:
            # Parse the log
            results = self.log_analyzer.parse_osint_log(log_content)
            
            # Extract entities
            entities = self.log_analyzer.extract_entities_from_urls()
            
            # Build relationship graph
            graph = self.log_analyzer.build_domain_relationship_graph()
            
            # Generate report
            report = self.log_analyzer.generate_log_report()
            
            # Display results
            result_text = f"Log Analysis Results:\n\n"
            result_text += f"Domains Analyzed: {len(results['subdomains'])}\n"
            result_text += f"Subdomains Found: {sum(len(subs) for subs in results['subdomains'].values())}\n"
            result_text += f"URLs Crawled: {results['crawled_count']}\n\n"
            
            result_text += "Domain Details:\n"
            for domain, subdomains in results['subdomains'].items():
                result_text += f"- {domain}: {len(subdomains)} subdomains\n"
            
            result_text += "\nDiscovered Technologies:\n"
            for tech in entities['technologies']:
                result_text += f"- {tech}\n"
            
            result_text += "\nURL Parameters Found:\n"
            for param in entities['parameters']:
                result_text += f"- {param}\n"
            
            self.log_results.setPlainText(result_text)
            
            # Visualize the domain relationship graph
            self.visualize_domain_graph(graph)
            
            # Add log data to correlation engine
            self.correlation_engine.add_log_data(report)
            
            self.status_bar.showMessage("Log analysis completed successfully")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Log analysis failed: {str(e)}")
    
    def visualize_domain_graph(self, graph):
        """Visualize the domain relationship graph"""
        fig = self.log_graph_canvas.figure
        fig.clear()
        
        if len(graph.nodes()) == 0:
            ax = fig.add_subplot(111)
            ax.text(0.5, 0.5, 'No domain relationships to visualize', 
                   horizontalalignment='center', verticalalignment='center',
                   transform=ax.transAxes, fontsize=14)
            self.log_graph_canvas.draw()
            return
        
        ax = fig.add_subplot(111)
        
        # Use spring layout
        pos = nx.spring_layout(graph, k=2, iterations=50)
        
        # Define node colors based on type
        node_colors = []
        for node in graph.nodes():
            if graph.nodes[node].get('type') == 'domain':
                node_colors.append('lightblue')
            else:
                node_colors.append('lightgreen')
        
        # Draw the graph
        nx.draw_networkx_nodes(graph, pos, node_color=node_colors, 
                              node_size=800, ax=ax)
        nx.draw_networkx_edges(graph, pos, alpha=0.5, ax=ax)
        nx.draw_networkx_labels(graph, pos, font_size=8, ax=ax)
        
        ax.set_title("Domain-Subdomain Relationship Graph")
        ax.axis('off')
        fig.tight_layout()
        self.log_graph_canvas.draw()
    
    def clear_log(self):
        """Clear the log input and results"""
        self.log_input.clear()
        self.log_results.clear()
        self.log_graph_canvas.figure.clear()
        self.log_graph_canvas.draw()
        self.status_bar.showMessage("Log cleared")
    
    def generate_report(self):
        """Generate a comprehensive report"""
        if not self.imported_data:
            QMessageBox.warning(self, "Warning", "No data to report. Please import data first.")
            return
        
        report_text = "# OSINT Fusion Framework Report\n\n"
        report_text += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Data overview
        report_text += "## Data Overview\n\n"
        report_text += f"Total data points: {len(self.imported_data)}\n\n"
        
        type_count = {}
        for data in self.imported_data:
            data_type = data.get('type', 'unknown')
            type_count[data_type] = type_count.get(data_type, 0) + 1
        
        for data_type, count in type_count.items():
            report_text += f"- {data_type.capitalize()}: {count}\n"
        
        # Entity extraction results
        if hasattr(self.correlation_engine, 'entity_graph'):
            entities = self.correlation_engine.extract_entities()
            report_text += "\n## Extracted Entities\n\n"
            
            for entity_type, values in entities.items():
                report_text += f"### {entity_type.capitalize()}\n\n"
                for value, source in values:
                    report_text += f"- {value} (source: {source})\n"
                report_text += "\n"
        
        # Correlation analysis
        if hasattr(self.correlation_engine, 'entity_graph'):
            graph = self.correlation_engine.entity_graph
            report_text += "## Correlation Analysis\n\n"
            report_text += f"- Nodes: {len(graph.nodes())}\n"
            report_text += f"- Edges: {len(graph.edges())}\n"
            report_text += f"- Isolated nodes: {len(list(nx.isolates(graph)))}\n\n"
            
            # Most connected nodes
            if graph.nodes():
                degrees = dict(graph.degree())
                most_connected = sorted(degrees.items(), key=lambda x: x[1], reverse=True)[:5]
                
                report_text += "### Most Connected Entities\n\n"
                for node, degree in most_connected:
                    node_data = graph.nodes[node]
                    report_text += f"- {node_data.get('value', node)} ({node_data.get('type', 'unknown')}): {degree} connections\n"
        
        # Patterns detected
        if hasattr(self.correlation_engine, 'patterns') and self.correlation_engine.patterns:
            report_text += "\n## Patterns Detected\n\n"
            for cluster_id, items in self.correlation_engine.patterns.items():
                report_text += f"### Pattern {cluster_id}\n\n"
                report_text += f"Items: {len(items)}\n\n"
                
                # Show sample content from the pattern
                sample_content = items[0].get('content', '')[:200] + "..." if len(items[0].get('content', '')) > 200 else items[0].get('content', '')
                report_text += f"Sample content: {sample_content}\n\n"
        
        # Conclusions
        report_text += "## Conclusions\n\n"
        report_text += "Based on the analysis, the following conclusions can be drawn:\n\n"
        
        if hasattr(self.correlation_engine, 'entity_graph') and len(self.correlation_engine.entity_graph.nodes()) > 0:
            report_text += "- Multiple entities were successfully extracted and correlated\n"
            
            # Check for cross-platform presence
            usernames = set()
            sources_by_username = defaultdict(set)
            
            for node, data in self.correlation_engine.entity_graph.nodes(data=True):
                if data.get('type') == 'usernames':
                    usernames.add(data.get('value'))
                    sources_by_username[data.get('value')].add(data.get('source'))
            
            cross_platform_users = [user for user, sources in sources_by_username.items() if len(sources) > 1]
            
            if cross_platform_users:
                report_text += f"- {len(cross_platform_users)} users found across multiple platforms\n"
                for user in cross_platform_users[:3]:  # Show first 3
                    report_text += f"  - {user} found on: {', '.join(sources_by_username[user])}\n"
        
        report_text += "\n## Recommendations\n\n"
        report_text += "1. Verify all correlations with additional sources\n"
        report_text += "2. Conduct further investigation on the most connected entities\n"
        report_text += "3. Monitor identified patterns for future activity\n"
        
        self.report_view.setPlainText(report_text)
        self.status_bar.showMessage("Report generated")
        
        # Advance AI step
        self.next_ai_step()
    
    def export_report(self):
        """Export the report to a file"""
        if not self.report_view.toPlainText().strip():
            QMessageBox.warning(self, "Warning", "No report to export. Please generate a report first.")
            return
        
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getSaveFileName(
            self, "Save Report", f"osint_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;Markdown Files (*.md);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(self.report_view.toPlainText())
            self.status_bar.showMessage(f"Report exported to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export report: {e}")

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("OSINT Fusion Framework")
    app.setApplicationVersion("1.0.0")
    
    # Apply modern style
    qtmodern.styles.dark(app)
    
    # Create and show main window
    window = OSINTFusionGUI()
    modern_window = qtmodern.windows.ModernWindow(window)
    modern_window.show()
    
    # Run the application
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()