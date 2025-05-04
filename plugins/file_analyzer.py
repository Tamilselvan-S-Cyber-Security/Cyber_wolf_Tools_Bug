"""
File Analyzer Plugin
Analyzes various file types for security issues and metadata extraction.
"""

import logging
import os
import hashlib
import magic
import zipfile
import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, BinaryIO
import re
import time
from datetime import datetime

from core.advanced_plugin import AdvancedPlugin, PluginMetadata, PluginCategory

class FileAnalyzer(AdvancedPlugin):
    """Plugin for analyzing various file types for security issues"""
    
    def _get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        return PluginMetadata(
            name="File Analyzer",
            version="1.0.0",
            description="Analyzes various file types for security issues and metadata extraction",
            author="CyberWolf Team",
            website="https://cyberwolf.example.com",
            category=PluginCategory.ANALYZER,
            tags=["file", "analysis", "security", "metadata"],
            dependencies=[],
            config_schema={
                "max_file_size": {
                    "type": "number",
                    "description": "Maximum file size to analyze in MB",
                    "default": 50,
                    "minimum": 1,
                    "maximum": 500
                },
                "extract_archives": {
                    "type": "boolean",
                    "description": "Extract and analyze archive contents",
                    "default": True
                },
                "analyze_code": {
                    "type": "boolean",
                    "description": "Perform code analysis for security issues",
                    "default": True
                },
                "analyze_metadata": {
                    "type": "boolean",
                    "description": "Extract and analyze file metadata",
                    "default": True
                },
                "temp_dir": {
                    "type": "string",
                    "description": "Temporary directory for extracted files",
                    "default": "temp"
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
                "max_file_size": 50,
                "extract_archives": True,
                "analyze_code": True,
                "analyze_metadata": True,
                "temp_dir": "temp"
            })
        
        # Create temp directory if it doesn't exist
        os.makedirs(self.config["temp_dir"], exist_ok=True)
        
        return True
    
    def run(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze a file for security issues"""
        options = options or {}
        
        # Check if target is a file path
        if not os.path.isfile(target):
            self._logger.error(f"Target is not a valid file: {target}")
            return {"error": f"Target is not a valid file: {target}"}
        
        # Merge options with configuration
        analysis_config = self.config.copy()
        analysis_config.update(options)
        
        self._logger.info(f"Analyzing file: {target}")
        
        # Check file size
        file_size_mb = os.path.getsize(target) / (1024 * 1024)
        max_size_mb = analysis_config.get("max_file_size", 50)
        
        if file_size_mb > max_size_mb:
            self._logger.error(f"File size ({file_size_mb:.2f} MB) exceeds maximum allowed size ({max_size_mb} MB)")
            return {"error": f"File size ({file_size_mb:.2f} MB) exceeds maximum allowed size ({max_size_mb} MB)"}
        
        # Get file type
        try:
            file_type = magic.from_file(target, mime=True)
        except Exception as e:
            self._logger.error(f"Error determining file type: {str(e)}")
            file_type = "unknown"
        
        # Calculate file hashes
        hashes = self._calculate_hashes(target)
        
        # Initialize results
        results = {
            "file_path": target,
            "file_name": os.path.basename(target),
            "file_size": os.path.getsize(target),
            "file_type": file_type,
            "hashes": hashes,
            "analysis_time": time.time(),
            "metadata": {},
            "security_issues": [],
            "extracted_files": []
        }
        
        # Extract metadata if enabled
        if analysis_config.get("analyze_metadata", True):
            self._logger.info(f"Extracting metadata from {target}")
            results["metadata"] = self._extract_metadata(target, file_type)
        
        # Analyze file based on type
        if file_type.startswith("text/"):
            # Text file analysis
            self._analyze_text_file(target, results, analysis_config)
        elif file_type == "application/zip" or file_type.endswith("zip"):
            # ZIP file analysis
            self._analyze_zip_file(target, results, analysis_config)
        elif file_type == "application/json":
            # JSON file analysis
            self._analyze_json_file(target, results, analysis_config)
        elif file_type == "application/xml" or file_type.endswith("xml"):
            # XML file analysis
            self._analyze_xml_file(target, results, analysis_config)
        elif file_type.startswith("image/"):
            # Image file analysis
            self._analyze_image_file(target, results, analysis_config)
        elif "pdf" in file_type:
            # PDF file analysis
            self._analyze_pdf_file(target, results, analysis_config)
        elif "msword" in file_type or "officedocument" in file_type:
            # Office document analysis
            self._analyze_office_file(target, results, analysis_config)
        elif "executable" in file_type or "application/x-dosexec" in file_type:
            # Executable file analysis
            self._analyze_executable_file(target, results, analysis_config)
        else:
            # Generic binary file analysis
            self._analyze_binary_file(target, results, analysis_config)
        
        self._logger.info(f"Completed analysis of {target}")
        return results
    
    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate MD5, SHA1, and SHA256 hashes of a file"""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            # Read the file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        
        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest()
        }
    
    def _extract_metadata(self, file_path: str, file_type: str) -> Dict[str, Any]:
        """Extract metadata from a file based on its type"""
        metadata = {
            "created": None,
            "modified": None,
            "accessed": None
        }
        
        # Get file timestamps
        try:
            stat_info = os.stat(file_path)
            metadata["created"] = datetime.fromtimestamp(stat_info.st_ctime).isoformat()
            metadata["modified"] = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            metadata["accessed"] = datetime.fromtimestamp(stat_info.st_atime).isoformat()
        except Exception as e:
            self._logger.error(f"Error getting file timestamps: {str(e)}")
        
        # Additional metadata extraction based on file type
        # This would be expanded with specific extractors for different file types
        
        return metadata
    
    def _analyze_text_file(self, file_path: str, results: Dict[str, Any], config: Dict[str, Any]) -> None:
        """Analyze a text file for security issues"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            # Check for sensitive information
            self._check_sensitive_info(content, results)
            
            # Check for code if enabled
            if config.get("analyze_code", True):
                self._analyze_code(content, file_path, results)
        except Exception as e:
            self._logger.error(f"Error analyzing text file: {str(e)}")
            results["security_issues"].append({
                "type": "Analysis Error",
                "description": f"Error analyzing text file: {str(e)}",
                "severity": "Low"
            })
    
    def _check_sensitive_info(self, content: str, results: Dict[str, Any]) -> None:
        """Check for sensitive information in text content"""
        # Define patterns for sensitive information
        patterns = {
            "API Key": r"(?i)(api[_-]?key|apikey)[ :='\"]+([\w\-]{20,})(?:[^w]|$)",
            "AWS Key": r"(?i)AKIA[0-9A-Z]{16}",
            "Password": r"(?i)(password|passwd|pwd)[ :='\"]+([\w\-@#$%^&*]{8,})(?:[^w]|$)",
            "Private Key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
            "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
            "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "IP Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "Social Security Number": r"\b\d{3}-\d{2}-\d{4}\b"
        }
        
        for pattern_name, pattern in patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                results["security_issues"].append({
                    "type": "Sensitive Information",
                    "description": f"Possible {pattern_name} found",
                    "severity": "High",
                    "location": f"Line containing: {match.group(0)[:20]}..."
                })
    
    def _analyze_code(self, content: str, file_path: str, results: Dict[str, Any]) -> None:
        """Analyze code for security issues"""
        # Determine language based on file extension
        ext = os.path.splitext(file_path)[1].lower()
        
        # Define patterns for common security issues by language
        if ext in [".py", ".pyw"]:
            # Python code analysis
            patterns = {
                "Command Injection": r"(?i)os\.system|subprocess\.(?:call|Popen|run)|eval\(",
                "SQL Injection": r"(?i)execute\([\"'].*?\%|cursor\.execute\([^,]*?\+",
                "Hardcoded Credentials": r"(?i)password\s*=\s*['\"][^'\"]+['\"]",
                "Insecure Hash": r"(?i)hashlib\.md5|hashlib\.sha1",
                "Pickle Usage": r"(?i)pickle\.(?:load|loads)",
                "Temp File": r"(?i)tempfile\.mk(?:temp|stemp)"
            }
        elif ext in [".js", ".ts", ".jsx", ".tsx"]:
            # JavaScript/TypeScript analysis
            patterns = {
                "Command Injection": r"(?i)eval\(|setTimeout\(['\"][^'\"]+['\"]|Function\(",
                "DOM XSS": r"(?i)\.innerHTML\s*=|document\.write\(",
                "Hardcoded Credentials": r"(?i)password\s*[:=]\s*['\"][^'\"]+['\"]",
                "Insecure Random": r"(?i)Math\.random\("
            }
        elif ext in [".php"]:
            # PHP code analysis
            patterns = {
                "Command Injection": r"(?i)shell_exec|exec\(|system\(|passthru\(|eval\(",
                "SQL Injection": r"(?i)mysql_query\([^,]*?\$|mysqli_query\([^,]*?\$",
                "File Inclusion": r"(?i)include\s*\(\s*\$|require\s*\(\s*\$",
                "XSS": r"(?i)echo\s+\$_(?:GET|POST|REQUEST|COOKIE)",
                "Hardcoded Credentials": r"(?i)\$password\s*=\s*['\"][^'\"]+['\"]"
            }
        elif ext in [".java", ".kt", ".scala"]:
            # Java/Kotlin/Scala analysis
            patterns = {
                "Command Injection": r"(?i)Runtime\.getRuntime\(\)\.exec\(",
                "SQL Injection": r"(?i)executeQuery\([^,]*?\+",
                "XSS": r"(?i)response\.getWriter\(\)\.print\([^)]*?request",
                "Hardcoded Credentials": r"(?i)password\s*=\s*['\"][^'\"]+['\"]",
                "Insecure Random": r"(?i)new Random\("
            }
        else:
            # Generic code analysis
            patterns = {
                "Command Injection": r"(?i)system\(|exec\(|eval\(",
                "SQL Injection": r"(?i)SELECT\s+.*?\s+FROM.*?\s+WHERE.*?\s*\+",
                "Hardcoded Credentials": r"(?i)password\s*[:=]\s*['\"][^'\"]+['\"]",
                "IP Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
            }
        
        # Check for security issues
        for issue_type, pattern in patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                results["security_issues"].append({
                    "type": issue_type,
                    "description": f"Potential {issue_type} vulnerability found",
                    "severity": "Medium",
                    "location": f"Line containing: {match.group(0)}"
                })
    
    def _analyze_zip_file(self, file_path: str, results: Dict[str, Any], config: Dict[str, Any]) -> None:
        """Analyze a ZIP file for security issues"""
        try:
            with zipfile.ZipFile(file_path, "r") as zip_file:
                # Check for zip slip vulnerability
                for file_info in zip_file.infolist():
                    if ".." in file_info.filename or file_info.filename.startswith("/"):
                        results["security_issues"].append({
                            "type": "Zip Slip",
                            "description": f"Potential zip slip vulnerability in {file_info.filename}",
                            "severity": "High"
                        })
                
                # Extract and analyze contents if enabled
                if config.get("extract_archives", True):
                    temp_dir = os.path.join(config["temp_dir"], os.path.basename(file_path) + "_extracted")
                    os.makedirs(temp_dir, exist_ok=True)
                    
                    # Extract files
                    zip_file.extractall(temp_dir)
                    
                    # Analyze extracted files
                    for root, dirs, files in os.walk(temp_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            rel_path = os.path.relpath(file_path, temp_dir)
                            
                            # Get file type
                            try:
                                file_type = magic.from_file(file_path, mime=True)
                            except:
                                file_type = "unknown"
                            
                            # Add to extracted files
                            results["extracted_files"].append({
                                "path": rel_path,
                                "size": os.path.getsize(file_path),
                                "type": file_type
                            })
                            
                            # Check for sensitive files
                            sensitive_files = [
                                ".env", "config.php", "wp-config.php", "settings.py",
                                "id_rsa", "id_dsa", ".htpasswd", "credentials.json"
                            ]
                            
                            if any(file.lower().endswith(s) for s in sensitive_files):
                                results["security_issues"].append({
                                    "type": "Sensitive File",
                                    "description": f"Potentially sensitive file found: {rel_path}",
                                    "severity": "High"
                                })
        except Exception as e:
            self._logger.error(f"Error analyzing ZIP file: {str(e)}")
            results["security_issues"].append({
                "type": "Analysis Error",
                "description": f"Error analyzing ZIP file: {str(e)}",
                "severity": "Low"
            })
    
    def _analyze_json_file(self, file_path: str, results: Dict[str, Any], config: Dict[str, Any]) -> None:
        """Analyze a JSON file for security issues"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                data = json.loads(content)
            
            # Check for sensitive information in JSON
            self._check_sensitive_info(content, results)
            
            # Check for sensitive keys in JSON
            sensitive_keys = ["password", "secret", "key", "token", "api_key", "apikey", "auth"]
            self._check_sensitive_keys(data, sensitive_keys, "", results)
        except Exception as e:
            self._logger.error(f"Error analyzing JSON file: {str(e)}")
            results["security_issues"].append({
                "type": "Analysis Error",
                "description": f"Error analyzing JSON file: {str(e)}",
                "severity": "Low"
            })
    
    def _check_sensitive_keys(self, data: Any, sensitive_keys: List[str], path: str, results: Dict[str, Any]) -> None:
        """Recursively check for sensitive keys in a data structure"""
        if isinstance(data, dict):
            for key, value in data.items():
                new_path = f"{path}.{key}" if path else key
                
                # Check if key is sensitive
                if any(s in key.lower() for s in sensitive_keys):
                    results["security_issues"].append({
                        "type": "Sensitive Key",
                        "description": f"Sensitive key found: {new_path}",
                        "severity": "Medium",
                        "location": new_path
                    })
                
                # Recurse into nested structures
                self._check_sensitive_keys(value, sensitive_keys, new_path, results)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_path = f"{path}[{i}]"
                self._check_sensitive_keys(item, sensitive_keys, new_path, results)
    
    def _analyze_xml_file(self, file_path: str, results: Dict[str, Any], config: Dict[str, Any]) -> None:
        """Analyze an XML file for security issues"""
        try:
            # Check for XXE vulnerability
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            if "<!ENTITY" in content or "<!DOCTYPE" in content:
                results["security_issues"].append({
                    "type": "XXE Vulnerability",
                    "description": "XML file contains entity declarations which could lead to XXE attacks",
                    "severity": "High"
                })
            
            # Parse XML and check structure
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Check for sensitive information
            self._check_sensitive_info(content, results)
        except Exception as e:
            self._logger.error(f"Error analyzing XML file: {str(e)}")
            results["security_issues"].append({
                "type": "Analysis Error",
                "description": f"Error analyzing XML file: {str(e)}",
                "severity": "Low"
            })
    
    def _analyze_image_file(self, file_path: str, results: Dict[str, Any], config: Dict[str, Any]) -> None:
        """Analyze an image file for security issues"""
        # This would be expanded with image-specific analysis
        pass
    
    def _analyze_pdf_file(self, file_path: str, results: Dict[str, Any], config: Dict[str, Any]) -> None:
        """Analyze a PDF file for security issues"""
        # This would be expanded with PDF-specific analysis
        pass
    
    def _analyze_office_file(self, file_path: str, results: Dict[str, Any], config: Dict[str, Any]) -> None:
        """Analyze an Office document for security issues"""
        # This would be expanded with Office-specific analysis
        pass
    
    def _analyze_executable_file(self, file_path: str, results: Dict[str, Any], config: Dict[str, Any]) -> None:
        """Analyze an executable file for security issues"""
        # This would be expanded with executable-specific analysis
        pass
    
    def _analyze_binary_file(self, file_path: str, results: Dict[str, Any], config: Dict[str, Any]) -> None:
        """Analyze a binary file for security issues"""
        # This would be expanded with binary-specific analysis
        pass
