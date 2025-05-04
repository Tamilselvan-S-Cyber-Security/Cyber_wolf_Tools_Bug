"""
Advanced Scanner Plugin
A demonstration of the advanced plugin system with configuration,
event handling, and UI integration.
"""

import logging
import requests
import socket
import dns.resolver
import dns.exception
import concurrent.futures
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

from core.advanced_plugin import AdvancedPlugin, PluginMetadata, PluginCategory

class AdvancedScanner(AdvancedPlugin):
    """Advanced scanner plugin with multiple scanning capabilities"""
    
    def _get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        return PluginMetadata(
            name="Advanced Scanner",
            version="1.0.0",
            description="Comprehensive scanner with multiple scanning capabilities",
            author="CyberWolf Team",
            website="https://cyberwolf.example.com",
            category=PluginCategory.SCANNER,
            tags=["scanner", "security", "reconnaissance"],
            dependencies=[],
            config_schema={
                "scan_ports": {
                    "type": "boolean",
                    "description": "Scan for open ports",
                    "default": True
                },
                "scan_subdomains": {
                    "type": "boolean",
                    "description": "Scan for subdomains",
                    "default": True
                },
                "scan_vulnerabilities": {
                    "type": "boolean",
                    "description": "Scan for common vulnerabilities",
                    "default": True
                },
                "port_range": {
                    "type": "string",
                    "description": "Port range to scan (e.g., '1-1000' or '80,443,8080')",
                    "default": "1-1000"
                },
                "max_threads": {
                    "type": "number",
                    "description": "Maximum number of concurrent threads",
                    "default": 10,
                    "minimum": 1,
                    "maximum": 50
                },
                "timeout": {
                    "type": "number",
                    "description": "Connection timeout in seconds",
                    "default": 2,
                    "minimum": 0.5,
                    "maximum": 10
                }
            }
        )
    
    def initialize(self) -> bool:
        """Initialize the plugin"""
        # Call parent initialization
        if not super().initialize():
            return False
        
        # Set default configuration if not already set
        if not self.config:
            self.configure({
                "scan_ports": True,
                "scan_subdomains": True,
                "scan_vulnerabilities": True,
                "port_range": "1-1000",
                "max_threads": 10,
                "timeout": 2
            })
        
        # Register event handlers
        self.register_event_handler("scan.port.open", self._handle_open_port)
        self.register_event_handler("scan.subdomain.found", self._handle_subdomain_found)
        self.register_event_handler("scan.vulnerability.found", self._handle_vulnerability_found)
        
        return True
    
    def _handle_open_port(self, event):
        """Handle open port event"""
        self._logger.info(f"Open port found: {event.data}")
    
    def _handle_subdomain_found(self, event):
        """Handle subdomain found event"""
        self._logger.info(f"Subdomain found: {event.data}")
    
    def _handle_vulnerability_found(self, event):
        """Handle vulnerability found event"""
        self._logger.info(f"Vulnerability found: {event.data}")
    
    def run(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run the scanner with the given target and options"""
        options = options or {}
        
        # Merge options with configuration
        scan_config = self.config.copy()
        scan_config.update(options)
        
        self._logger.info(f"Starting advanced scan of {target} with options: {scan_config}")
        
        results = {
            "target": target,
            "scan_time": time.time(),
            "open_ports": [],
            "subdomains": [],
            "vulnerabilities": []
        }
        
        # Resolve IP address
        try:
            ip_address = socket.gethostbyname(target)
            results["ip_address"] = ip_address
            self._logger.info(f"Resolved {target} to {ip_address}")
        except socket.gaierror:
            self._logger.warning(f"Could not resolve hostname: {target}")
            results["ip_address"] = None
        
        # Scan ports if enabled
        if scan_config.get("scan_ports", True):
            self._logger.info(f"Scanning ports on {target}")
            results["open_ports"] = self._scan_ports(target, scan_config)
        
        # Scan subdomains if enabled
        if scan_config.get("scan_subdomains", True):
            self._logger.info(f"Scanning subdomains of {target}")
            results["subdomains"] = self._scan_subdomains(target, scan_config)
        
        # Scan vulnerabilities if enabled
        if scan_config.get("scan_vulnerabilities", True):
            self._logger.info(f"Scanning vulnerabilities on {target}")
            results["vulnerabilities"] = self._scan_vulnerabilities(target, scan_config)
        
        self._logger.info(f"Completed advanced scan of {target}")
        return results
    
    def _scan_ports(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for open ports"""
        open_ports = []
        
        # Parse port range
        port_range = config.get("port_range", "1-1000")
        ports_to_scan = []
        
        if "-" in port_range:
            start, end = port_range.split("-")
            ports_to_scan = range(int(start), int(end) + 1)
        else:
            ports_to_scan = [int(p.strip()) for p in port_range.split(",")]
        
        # Get target IP
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            self._logger.error(f"Could not resolve hostname: {target}")
            return open_ports
        
        # Set up thread pool
        max_threads = config.get("max_threads", 10)
        timeout = config.get("timeout", 2)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit scanning tasks
            future_to_port = {
                executor.submit(self._check_port, ip, port, timeout): port
                for port in ports_to_scan
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        # Emit event for open port
                        self._emit_event("scan.port.open", result)
                except Exception as e:
                    self._logger.error(f"Error scanning port {port}: {str(e)}")
        
        return open_ports
    
    def _check_port(self, ip: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
        """Check if a port is open"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Try to identify service
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                
                return {
                    "port": port,
                    "state": "open",
                    "service": service
                }
            return None
        except Exception as e:
            self._logger.debug(f"Error checking port {port}: {str(e)}")
            return None
        finally:
            if sock:
                sock.close()
    
    def _scan_subdomains(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for subdomains"""
        subdomains = []
        
        # Common subdomains to check
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 
            'test', 'store', 'shop', 'api', 'secure', 'vpn',
            'cloud', 'portal', 'webmail', 'remote', 'support',
            'docs', 'git', 'gitlab', 'jenkins', 'jira', 'wiki'
        ]
        
        for subdomain in common_subdomains:
            try:
                hostname = f"{subdomain}.{target}"
                answers = dns.resolver.resolve(hostname, 'A')
                for answer in answers:
                    result = {
                        'subdomain': hostname,
                        'ip': answer.address
                    }
                    subdomains.append(result)
                    # Emit event for found subdomain
                    self._emit_event("scan.subdomain.found", result)
                self._logger.debug(f"Found subdomain: {hostname}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                continue
            except Exception as e:
                self._logger.error(f"Error checking subdomain {hostname}: {str(e)}")
        
        return subdomains
    
    def _scan_vulnerabilities(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for common vulnerabilities"""
        vulnerabilities = []
        
        # Check for common security headers
        try:
            url = f"https://{target}"
            response = requests.get(url, timeout=config.get("timeout", 2), verify=False)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing Content-Security-Policy header',
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header'
            }
            
            for header, message in security_headers.items():
                if header not in headers:
                    vuln = {
                        'type': 'Missing Security Header',
                        'header': header,
                        'description': message,
                        'severity': 'Medium'
                    }
                    vulnerabilities.append(vuln)
                    # Emit event for found vulnerability
                    self._emit_event("scan.vulnerability.found", vuln)
            
            # Check for server information disclosure
            if 'Server' in headers:
                vuln = {
                    'type': 'Information Disclosure',
                    'header': 'Server',
                    'value': headers['Server'],
                    'description': 'Server header reveals version information',
                    'severity': 'Low'
                }
                vulnerabilities.append(vuln)
                self._emit_event("scan.vulnerability.found", vuln)
            
        except requests.exceptions.RequestException as e:
            self._logger.error(f"Error checking security headers: {str(e)}")
        
        return vulnerabilities
