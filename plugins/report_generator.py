"""
Report Generator Plugin
Generates comprehensive HTML and PDF reports from scan results.
"""

import logging
import os
import json
import base64
from datetime import datetime
from typing import Dict, List, Any, Optional
from jinja2 import Template

from core.advanced_plugin import AdvancedPlugin, PluginMetadata, PluginCategory

class ReportGenerator(AdvancedPlugin):
    """Plugin for generating HTML and PDF reports from scan results"""
    
    def _get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        return PluginMetadata(
            name="Report Generator",
            version="1.0.0",
            description="Generates comprehensive HTML and PDF reports from scan results",
            author="CyberWolf Team",
            website="https://cyberwolf.example.com",
            category=PluginCategory.REPORTER,
            tags=["report", "html", "pdf", "export"],
            dependencies=[],
            config_schema={
                "report_dir": {
                    "type": "string",
                    "description": "Directory to save reports",
                    "default": "reports"
                },
                "company_name": {
                    "type": "string",
                    "description": "Company name to display in reports",
                    "default": "CyberWolf Security"
                },
                "company_logo": {
                    "type": "string",
                    "description": "Base64 encoded company logo",
                    "default": ""
                },
                "include_timestamp": {
                    "type": "boolean",
                    "description": "Include timestamp in report filenames",
                    "default": True
                },
                "include_executive_summary": {
                    "type": "boolean",
                    "description": "Include executive summary in reports",
                    "default": True
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
                "report_dir": "reports",
                "company_name": "CyberWolf Security",
                "company_logo": "",
                "include_timestamp": True,
                "include_executive_summary": True
            })
        
        # Create reports directory if it doesn't exist
        os.makedirs(self.config["report_dir"], exist_ok=True)
        
        return True
    
    def run(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate reports for the given scan results"""
        options = options or {}
        
        # Get scan results from options
        scan_results = options.get("scan_results", {})
        if not scan_results:
            self._logger.error("No scan results provided")
            return {"error": "No scan results provided"}
        
        # Merge options with configuration
        report_config = self.config.copy()
        report_config.update(options)
        
        self._logger.info(f"Generating reports for {target}")
        
        # Generate reports
        html_report = self._generate_html_report(target, scan_results, report_config)
        pdf_html = self._generate_pdf_html(target, scan_results, report_config)
        
        # Save reports
        timestamp = ""
        if report_config.get("include_timestamp", True):
            timestamp = f"_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        html_filename = f"{target}{timestamp}_report.html"
        pdf_filename = f"{target}{timestamp}_report_pdf.html"
        
        html_path = os.path.join(report_config["report_dir"], html_filename)
        pdf_path = os.path.join(report_config["report_dir"], pdf_filename)
        
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_report)
        
        with open(pdf_path, "w", encoding="utf-8") as f:
            f.write(pdf_html)
        
        self._logger.info(f"Reports saved to {html_path} and {pdf_path}")
        
        return {
            "target": target,
            "html_report": html_path,
            "pdf_report": pdf_path,
            "html_content": html_report,
            "pdf_content": pdf_html
        }
    
    def _generate_html_report(self, target: str, scan_results: Dict[str, Any], config: Dict[str, Any]) -> str:
        """Generate HTML report from scan results"""
        # HTML template for the report
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Scan Report - {{ target }}</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    color: #333;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                }
                h1, h2, h3 {
                    color: #2c3e50;
                }
                .header {
                    background-color: #3498db;
                    color: white;
                    padding: 20px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .header-content {
                    flex: 1;
                }
                .logo {
                    max-width: 200px;
                    max-height: 80px;
                }
                .section {
                    background-color: #f9f9f9;
                    padding: 15px;
                    margin-bottom: 20px;
                    border-radius: 5px;
                    border-left: 5px solid #3498db;
                }
                .info-box {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 20px;
                    margin-bottom: 20px;
                }
                .info-item {
                    background-color: #ecf0f1;
                    padding: 15px;
                    border-radius: 5px;
                    flex: 1;
                    min-width: 200px;
                }
                .vulnerability {
                    background-color: #fff;
                    padding: 15px;
                    margin-bottom: 10px;
                    border-radius: 5px;
                    border-left: 5px solid #e74c3c;
                }
                .high {
                    border-left-color: #e74c3c;
                }
                .medium {
                    border-left-color: #f39c12;
                }
                .low {
                    border-left-color: #2ecc71;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                }
                th, td {
                    padding: 12px 15px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }
                th {
                    background-color: #3498db;
                    color: white;
                }
                tr:nth-child(even) {
                    background-color: #f2f2f2;
                }
                .footer {
                    text-align: center;
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #eee;
                    color: #7f8c8d;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="header-content">
                        <h1>Security Scan Report</h1>
                        <p>Target: {{ target }}</p>
                        <p>Generated on {{ timestamp }}</p>
                    </div>
                    {% if company_logo %}
                    <img src="{{ company_logo }}" alt="{{ company_name }} Logo" class="logo">
                    {% endif %}
                </div>
                
                {% if include_executive_summary %}
                <div class="section">
                    <h2>Executive Summary</h2>
                    <p>This report presents the findings of a security scan conducted on {{ target }}. The scan was performed on {{ timestamp }} by {{ company_name }}.</p>
                    
                    <div class="info-box">
                        <div class="info-item">
                            <h3>Open Ports</h3>
                            <p>{{ scan_results.open_ports|length }}</p>
                        </div>
                        <div class="info-item">
                            <h3>Subdomains</h3>
                            <p>{{ scan_results.subdomains|length }}</p>
                        </div>
                        <div class="info-item">
                            <h3>Vulnerabilities</h3>
                            <p>{{ scan_results.vulnerabilities|length }}</p>
                        </div>
                    </div>
                </div>
                {% endif %}
                
                <div class="section">
                    <h2>Target Information</h2>
                    <table>
                        <tr>
                            <th>Property</th>
                            <th>Value</th>
                        </tr>
                        <tr>
                            <td>Target</td>
                            <td>{{ target }}</td>
                        </tr>
                        <tr>
                            <td>IP Address</td>
                            <td>{{ scan_results.ip_address or "Unknown" }}</td>
                        </tr>
                        <tr>
                            <td>Scan Time</td>
                            <td>{{ scan_time }}</td>
                        </tr>
                    </table>
                </div>
                
                {% if scan_results.open_ports %}
                <div class="section">
                    <h2>Open Ports</h2>
                    <table>
                        <tr>
                            <th>Port</th>
                            <th>State</th>
                            <th>Service</th>
                        </tr>
                        {% for port in scan_results.open_ports %}
                        <tr>
                            <td>{{ port.port }}</td>
                            <td>{{ port.state }}</td>
                            <td>{{ port.service }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                </div>
                {% endif %}
                
                {% if scan_results.subdomains %}
                <div class="section">
                    <h2>Subdomains</h2>
                    <table>
                        <tr>
                            <th>Subdomain</th>
                            <th>IP Address</th>
                        </tr>
                        {% for subdomain in scan_results.subdomains %}
                        <tr>
                            <td>{{ subdomain.subdomain }}</td>
                            <td>{{ subdomain.ip }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                </div>
                {% endif %}
                
                {% if scan_results.vulnerabilities %}
                <div class="section">
                    <h2>Vulnerabilities</h2>
                    {% for vuln in scan_results.vulnerabilities %}
                    <div class="vulnerability {{ vuln.severity|lower }}">
                        <h3>{{ vuln.type }}</h3>
                        <p><strong>Severity:</strong> {{ vuln.severity }}</p>
                        <p><strong>Description:</strong> {{ vuln.description }}</p>
                        {% if vuln.header %}
                        <p><strong>Header:</strong> {{ vuln.header }}</p>
                        {% endif %}
                        {% if vuln.value %}
                        <p><strong>Value:</strong> {{ vuln.value }}</p>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
                
                <div class="footer">
                    <p>Generated by {{ company_name }}</p>
                    <p>© {{ current_year }} {{ company_name }}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Create a Jinja2 template
        template = Template(html_template)
        
        # Format scan time
        scan_time = datetime.fromtimestamp(scan_results.get("scan_time", time.time())).strftime("%Y-%m-%d %H:%M:%S")
        
        # Render the template with the results
        html_report = template.render(
            target=target,
            scan_results=scan_results,
            scan_time=scan_time,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            current_year=datetime.now().year,
            company_name=config.get("company_name", "CyberWolf Security"),
            company_logo=config.get("company_logo", ""),
            include_executive_summary=config.get("include_executive_summary", True)
        )
        
        return html_report
    
    def _generate_pdf_html(self, target: str, scan_results: Dict[str, Any], config: Dict[str, Any]) -> str:
        """Generate PDF-friendly HTML from scan results"""
        # Get the HTML report
        html_report = self._generate_html_report(target, scan_results, config)
        
        # Add print-friendly CSS and auto-print JavaScript
        pdf_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {target} (PDF)</title>
            <style>
                @media print {{
                    @page {{
                        size: A4;
                        margin: 1cm;
                    }}
                    body {{
                        font-size: 12pt;
                    }}
                    .no-print {{
                        display: none;
                    }}
                }}
                .print-button {{
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    padding: 10px 20px;
                    background-color: #3498db;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    z-index: 1000;
                }}
                .print-button:hover {{
                    background-color: #2980b9;
                }}
                .print-instructions {{
                    position: fixed;
                    top: 70px;
                    right: 20px;
                    width: 300px;
                    padding: 15px;
                    background-color: #f8f9fa;
                    border-radius: 5px;
                    border: 1px solid #ddd;
                    z-index: 1000;
                }}
            </style>
            <script>
                function printReport() {{
                    document.querySelector('.no-print').style.display = 'none';
                    window.print();
                    setTimeout(function() {{
                        document.querySelector('.no-print').style.display = 'block';
                    }}, 1000);
                }}
            </script>
        </head>
        <body>
            <div class="no-print">
                <button class="print-button" onclick="printReport()">Print / Save as PDF</button>
                <div class="print-instructions">
                    <h3>To save as PDF:</h3>
                    <ol>
                        <li>Click the "Print / Save as PDF" button</li>
                        <li>In the print dialog, select "Save as PDF" as the destination</li>
                        <li>Click "Save" and choose where to save the PDF file</li>
                    </ol>
                </div>
            </div>
            
            {html_report}
        </body>
        </html>
        """
        
        return pdf_html
