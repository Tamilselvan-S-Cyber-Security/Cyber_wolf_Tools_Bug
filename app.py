import streamlit as st
import pandas as pd
from security_analyzer import PluginManager
from utils.validator import validate_domain
import json
import logging
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx
import trafilatura
import io
import zipfile
import base64
from urllib.parse import urlparse
from plugins.site_cloner import SiteCloner
from jinja2 import Template

# Import advanced plugin system
from core.advanced_plugin_manager import AdvancedPluginManager

def datetime_handler(obj):
    """Handle datetime serialization for JSON"""
    if hasattr(obj, 'isoformat'):
        return obj.isoformat()
    elif isinstance(obj, datetime):
        return obj.isoformat()
    else:
        return str(obj)

def create_vulnerability_charts(df):
    """Create visualization charts for vulnerability data"""
    st.subheader("Vulnerability Analysis Visualizations")

    # Prepare data for visualizations
    module_counts = df['Module'].value_counts()

    # Create tabs for different visualizations
    tab1, tab2, tab3, tab4 = st.tabs(["Distribution", "Timeline", "Severity", "Correlation"])

    with tab1:
        # Pie chart of vulnerabilities by module
        fig_pie = px.pie(values=module_counts.values, names=module_counts.index,
                        title="ECP Technology")
        st.plotly_chart(fig_pie)

        # Histogram of finding types
        fig_hist = px.histogram(df, x="Finding Type",
                              title="Distribution of Finding Types")
        st.plotly_chart(fig_hist)

    with tab2:
        # Timeline of discoveries (assuming timestamp is available)
        df['Timestamp'] = pd.Timestamp.now()  # Replace with actual timestamps when available
        fig_line = px.line(df, x="Timestamp", y="Module",
                          title="Vulnerability Discovery Timeline")
        st.plotly_chart(fig_line)

    with tab3:
        # Severity analysis
        severity_data = df['Value'].str.contains('High|Medium|Low').value_counts()
        fig_severity = px.bar(x=severity_data.index, y=severity_data.values,
                            title="Vulnerability Severity Distribution")
        st.plotly_chart(fig_severity)

    with tab4:
        # Scatter plot of related findings
        fig_scatter = px.scatter(df, x="Module", y="Finding Type",
                               title="Correlation between Modules and Finding Types")
        st.plotly_chart(fig_scatter)

def visualize_site_structure(site_structure):
    """Create network graph visualization for site structure"""
    st.subheader("Website Structure Visualization")

    # Create network graph
    G = nx.DiGraph()
    for edge in site_structure['edges']:
        G.add_edge(edge['source'], edge['target'])

    # Get position layout
    pos = nx.spring_layout(G)

    # Create edges trace
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines')

    # Create nodes trace
    node_x = []
    node_y = []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers',
        hoverinfo='text',
        marker=dict(
            size=10,
            color='#00b4d8',
            line_width=2))

    # Create figure
    fig = go.Figure(data=[edge_trace, node_trace],
                   layout=go.Layout(
                       showlegend=False,
                       hovermode='closest',
                       margin=dict(b=20,l=5,r=5,t=40),
                       title="Website Link Structure",
                       annotations=[ dict(
                           text="",
                           showarrow=False,
                           xref="paper", yref="paper") ],
                       xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                       yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                   )

    st.plotly_chart(fig)

def convert_to_dataframe(results):
    """Convert analysis results to a pandas DataFrame"""
    data = []
    total_vulnerabilities = 0

    for module, findings in results.items():
        if isinstance(findings, dict):
            # Count vulnerabilities
            if 'total_vulnerabilities' in findings:
                total_vulnerabilities += findings['total_vulnerabilities']

            # Flatten dictionary findings
            for key, value in findings.items():
                if isinstance(value, (list, dict)):
                    # Use custom JSON encoder for datetime objects
                    value = json.dumps(value, default=datetime_handler)
                elif isinstance(value, datetime):
                    value = value.isoformat()
                data.append({
                    'Module': module,
                    'Finding Type': key,
                    'Value': value
                })
        elif isinstance(findings, list):
            # Handle list findings
            for finding in findings:
                data.append({
                    'Module': module,
                    'Finding Type': 'scan_result',
                    'Value': json.dumps(finding, default=datetime_handler)
                })

    return pd.DataFrame(data), total_vulnerabilities

def clone_website(url: str, options: dict = None) -> tuple:
    """Clone website content using site cloner with advanced options"""
    try:
        cloner = SiteCloner()
        parsed_url = urlparse(url)

        # Set default options if none provided
        if not options:
            options = {
                'max_depth': 2,
                'rate_limit': 1.0,
                'download_assets': True,
                'protocol': parsed_url.scheme or 'https'
            }

        site_structure = cloner.run(parsed_url.netloc, options=options)

        # Generate text summary
        text_content = f"Website Clone Report for {url}\n"
        text_content += f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        text_content += f"Total Pages: {site_structure['total_pages']}\n"
        text_content += f"Total Files: {site_structure['total_files']}\n"
        text_content += f"Total Links: {site_structure['total_links']}\n"
        text_content += f"Security Issues: {len(site_structure['security_issues'])}\n\n"

        text_content += "Downloaded Files:\n"
        for url, info in site_structure['downloaded_files'].items():
            text_content += f"\n{url} ({info['content_type']}, {info['size']} bytes)"

        # Use the HTML report generated by the cloner
        html_content = site_structure['reports']['html_report']

        # Create sitemap content
        sitemap_content = site_structure['reports']['sitemap_xml']

        # Create security report
        security_content = "Security Issues Report\n\n"
        if site_structure['security_issues']:
            for issue in site_structure['security_issues']:
                security_content += f"URL: {issue['url']}\n"
                security_content += f"Type: {issue['type']}\n"
                security_content += f"Severity: {issue['severity']}\n"
                security_content += f"Description: {issue['description']}\n"
                security_content += f"Details: {issue.get('details', 'N/A')}\n\n"
        else:
            security_content += "No security issues found."

        return text_content, html_content, sitemap_content, security_content, site_structure
    except Exception as e:
        logging.error(f"Error cloning website: {str(e)}", exc_info=True)
        st.error(f"Error cloning website: {str(e)}")
        return None, None, None, None, None

def create_downloadable_zip(site_structure: dict, url: str) -> bytes:
    """Create a ZIP file containing the cloned website content and reports"""
    zip_buffer = io.BytesIO()

    try:
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Save summary text
            text_content = f"Website Clone Report for {url}\n"
            text_content += f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            text_content += f"Total Pages: {site_structure['total_pages']}\n"
            text_content += f"Total Files: {site_structure['total_files']}\n"
            text_content += f"Total Links: {site_structure['total_links']}\n"
            text_content += f"Security Issues: {len(site_structure['security_issues'])}\n\n"

            zf.writestr('summary.txt', text_content)

            # Save HTML report
            zf.writestr('report.html', site_structure['reports']['html_report'])

            # Save sitemap
            zf.writestr('sitemap.xml', site_structure['reports']['sitemap_xml'])

            # Save security issues report
            security_content = "Security Issues Report\n\n"
            if site_structure['security_issues']:
                for issue in site_structure['security_issues']:
                    security_content += f"URL: {issue['url']}\n"
                    security_content += f"Type: {issue['type']}\n"
                    security_content += f"Severity: {issue['severity']}\n"
                    security_content += f"Description: {issue['description']}\n"
                    security_content += f"Details: {issue.get('details', 'N/A')}\n\n"
            else:
                security_content += "No security issues found."

            zf.writestr('security_issues.txt', security_content)

            # Create a directory for downloaded files
            file_dir = 'downloaded_files/'

            # Save a list of all downloaded files
            files_list = "Downloaded Files:\n\n"
            for url, info in site_structure['downloaded_files'].items():
                files_list += f"{url} ({info['content_type']}, {info['size']} bytes)\n"

            zf.writestr(file_dir + 'files_list.txt', files_list)

            # Save a JSON representation of the site structure
            site_structure_copy = site_structure.copy()
            # Remove the actual file contents to keep the JSON small
            if 'downloaded_files' in site_structure_copy:
                for url, info in site_structure_copy['downloaded_files'].items():
                    if 'content' in info:
                        del info['content']

            zf.writestr(file_dir + 'site_structure.json', json.dumps(site_structure_copy, default=datetime_handler, indent=2))

    except Exception as e:
        logging.error(f"Error creating ZIP file: {str(e)}", exc_info=True)
        return None

    return zip_buffer.getvalue()

def generate_website_pdf_report(html_content: str) -> bytes:
    """Generate a PDF-friendly HTML report for website cloning"""
    # Add print-friendly CSS and auto-print JavaScript
    print_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Website Clone Report (PDF)</title>
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

        {html_content}
    </body>
    </html>
    """

    return print_html.encode('utf-8')

def generate_apk_html_report(results: dict) -> str:
    """Generate an HTML report for APK analysis results"""
    # HTML template for the report
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>APK Analysis Report - {{ results.package }}</title>
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
            .file-list {
                max-height: 300px;
                overflow-y: auto;
                background-color: #f8f9fa;
                padding: 10px;
                border-radius: 5px;
            }
            .footer {
                text-align: center;
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #eee;
                color: #7f8c8d;
            }
            pre {
                background-color: #f8f9fa;
                padding: 10px;
                border-radius: 5px;
                overflow-x: auto;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>APK Security Analysis Report</h1>
                <p>Generated on {{ timestamp }}</p>
            </div>

            <div class="section">
                <h2>Application Information</h2>
                <div class="info-box">
                    <div class="info-item">
                        <h3>App Name</h3>
                        <p>{{ results.app_name }}</p>
                    </div>
                    <div class="info-item">
                        <h3>Package</h3>
                        <p>{{ results.package }}</p>
                    </div>
                    <div class="info-item">
                        <h3>Version</h3>
                        <p>{{ results.version.name }} ({{ results.version.code }})</p>
                    </div>
                </div>
            </div>

            {% if results.min_sdk or results.target_sdk %}
            <div class="section">
                <h2>SDK Information</h2>
                <div class="info-box">
                    <div class="info-item">
                        <h3>Min SDK</h3>
                        <p>{{ results.min_sdk }}</p>
                    </div>
                    <div class="info-item">
                        <h3>Target SDK</h3>
                        <p>{{ results.target_sdk }}</p>
                    </div>
                </div>
            </div>
            {% endif %}

            {% if results.permissions %}
            <div class="section">
                <h2>Permissions Analysis</h2>
                <div class="info-box">
                    <div class="info-item">
                        <h3>Total Permissions</h3>
                        <p>{{ results.permissions.total_permissions }}</p>
                    </div>
                    <div class="info-item">
                        <h3>Dangerous Permissions</h3>
                        <p>{{ results.permissions.dangerous_permissions|length }}</p>
                    </div>
                </div>

                {% if results.permissions.dangerous_permissions %}
                <h3>Dangerous Permissions List</h3>
                <ul>
                    {% for perm in results.permissions.dangerous_permissions %}
                    <li>{{ perm }}</li>
                    {% endfor %}
                </ul>
                {% endif %}

                {% if results.permissions.all_permissions %}
                <h3>All Permissions</h3>
                <div class="file-list">
                    <ul>
                        {% for perm in results.permissions.all_permissions %}
                        <li>{{ perm }}</li>
                        {% endfor %}
                    </ul>
                </div>
                {% endif %}
            </div>
            {% endif %}

            {% if results.vulnerabilities %}
            <div class="section">
                <h2>Vulnerability Analysis</h2>
                <h3>Total Vulnerabilities: {{ results.total_vulnerabilities }}</h3>

                {% for vuln in results.vulnerabilities %}
                <div class="vulnerability {{ vuln.severity|lower }}">
                    <h3>{{ vuln.name }} ({{ vuln.severity }})</h3>
                    <p><strong>Type:</strong> {{ vuln.type }}</p>
                    <p><strong>Description:</strong> {{ vuln.description }}</p>

                    {% if vuln.components %}
                    <h4>Affected Components:</h4>
                    <ul>
                        {% for comp in vuln.components %}
                        <li>{{ comp }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}

                    {% if vuln.files %}
                    <h4>Affected Files:</h4>
                    <ul>
                        {% for file in vuln.files %}
                        <li>{{ file }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
            {% endif %}

            {% if results.libraries %}
            <div class="section">
                <h2>Native Libraries</h2>
                <p>Total Libraries: {{ results.libraries.total_libraries }}</p>

                {% if results.libraries.libraries %}
                <div class="file-list">
                    <ul>
                        {% for lib in results.libraries.libraries %}
                        <li>{{ lib }}</li>
                        {% endfor %}
                    </ul>
                </div>
                {% endif %}
            </div>
            {% endif %}

            {% if results.extracted_files %}
            <div class="section">
                <h2>Extracted Files</h2>
                <p>Total Files: {{ results.extracted_files|length }}</p>

                {% set file_types = {} %}
                {% for file in results.extracted_files %}
                    {% set file_type = file.type|default('Other') %}
                    {% if file_type not in file_types %}
                        {% set _ = file_types.update({file_type: []}) %}
                    {% endif %}
                    {% set _ = file_types[file_type].append(file) %}
                {% endfor %}

                {% for file_type, files in file_types.items() %}
                <h3>{{ file_type }} Files ({{ files|length }})</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Path</th>
                            <th>Size</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for file in files %}
                        <tr>
                            <td>{{ file.path }}</td>
                            <td>
                                {% if file.size < 1024*1024 %}
                                    {{ (file.size/1024)|round(1) }} KB
                                {% else %}
                                    {{ (file.size/(1024*1024))|round(1) }} MB
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% endfor %}
            </div>
            {% endif %}

            <div class="footer">
                <p>Generated by CyberWolfScanner APK Analyzer</p>
                <p>© {{ current_year }} CyberWolfScanner</p>
            </div>
        </div>
    </body>
    </html>
    """

    # Create a Jinja2 template
    template = Template(html_template)

    # Render the template with the results
    html_report = template.render(
        results=results,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        current_year=datetime.now().year
    )

    return html_report

def generate_pdf_from_html(html_content: str) -> bytes:
    """
    Generate a PDF from HTML content using browser print functionality

    Since we can't directly generate PDFs on the server without additional dependencies,
    we'll create an HTML file with print-friendly CSS and JavaScript that will
    automatically open the print dialog when opened.
    """
    # Add print-friendly CSS and auto-print JavaScript
    print_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>APK Analysis Report (PDF)</title>
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

        {html_content}
    </body>
    </html>
    """

    return print_html.encode('utf-8')

def main():
    st.set_page_config(
        page_title="CyberWolf Scanner",
        page_icon="�",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    st.title("CyberWolf Scanner")
    st.markdown("A comprehensive security analysis tool")

    # Create tabs for different functionalities
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Security Analysis",
        "Website Cloner",
        "APK Analysis",
        "File Analysis",
        "Advanced Plugins"
    ])

    with tab1:
        # URL Input
        target_domain = st.text_input("Enter target domain (e.g., example.com)")
        port_range = st.text_input("Enter port range (e.g., 1-100)", value="1-100")

        if st.button("Start Analysis"):
            if not target_domain:
                st.error("Please enter a target domain")
                return

            if not validate_domain(target_domain):
                st.error("Invalid domain format")
                return

            # Show progress
            with st.spinner("Running security analysis..."):
                plugin_manager = PluginManager()
                results = {}

                # Create progress bars for each plugin
                progress_text = st.empty()
                progress_bar = st.progress(0)
                plugins = plugin_manager.get_plugins()
                total_plugins = len(plugins)

                for idx, plugin in enumerate(plugins, 1):
                    progress_text.text(f"Running {plugin.name}...")
                    try:
                        plugin_results = plugin.run(target_domain, port_range)
                        results[plugin.name] = plugin_results
                    except Exception as e:
                        results[plugin.name] = {'error': str(e)}
                    progress_bar.progress(idx / total_plugins)

            # Display results
            st.header("Analysis Results")

            # Convert results to DataFrame for easier handling
            df, total_vulnerabilities = convert_to_dataframe(results)

            # Display summary metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Vulnerabilities Found", total_vulnerabilities)
            with col2:
                st.metric("Modules Run", len(results))
            with col3:
                high_severity = df[df['Value'].str.contains('High', na=False)].shape[0]
                st.metric("High Severity Issues", high_severity)

            # Create visualizations
            create_vulnerability_charts(df)

            # Display site structure if available
            if "Website Structure Analysis" in results:
                visualize_site_structure(results["Website Structure Analysis"])

            # Display results in expandable sections
            for module in df['Module'].unique():
                with st.expander(f"{module} Results", expanded=True):
                    module_data = df[df['Module'] == module]

                    # Special handling for URL Path Scanner results
                    if module == "URL Path Scanner":
                        vulnerable_paths = module_data[module_data['Finding Type'] == 'vulnerable_paths']
                        if not vulnerable_paths.empty:
                            st.subheader("Vulnerable URLs Found")
                            paths_data = json.loads(vulnerable_paths.iloc[0]['Value'])
                            paths_df = pd.DataFrame(paths_data)
                            st.dataframe(paths_df)
                    else:
                        st.dataframe(module_data[['Finding Type', 'Value']])

            # Export options
            st.header("Export Results")
            col1, col2 = st.columns(2)

            # Export to CSV
            with col1:
                csv = df.to_csv(index=False)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"security_analysis_{target_domain}_{timestamp}.csv"
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=filename,
                    mime="text/csv"
                )

            # Export to HTML
            with col2:
                html = df.to_html(index=False)
                html_filename = f"security_analysis_{target_domain}_{timestamp}.html"
                st.download_button(
                    label="Download HTML",
                    data=html,
                    file_name=html_filename,
                    mime="text/html"
                )

    with tab2:
        st.header("Website Cloner")
        st.markdown("Clone and download website content for offline analysis")

        # Create two columns for the URL input and advanced options
        col1, col2 = st.columns([2, 1])

        with col1:
            clone_url = st.text_input("Enter website URL to clone (e.g., https://example.com)")

        # Advanced options in an expander
        with st.expander("Advanced Options"):
            max_depth = st.slider("Crawl Depth", min_value=1, max_value=5, value=2,
                                help="Maximum depth to crawl from the starting URL")

            rate_limit = st.slider("Rate Limit (seconds)", min_value=0.1, max_value=5.0, value=1.0, step=0.1,
                                 help="Time to wait between requests to avoid overloading the server")

            download_assets = st.checkbox("Download Assets (CSS, JS, Images)", value=True,
                                       help="Download static assets like CSS, JavaScript, and images")

            protocol = st.radio("Protocol", ["https", "http"], horizontal=True,
                             help="Protocol to use for the initial connection")

        if st.button("Clone Website"):
            if not clone_url:
                st.error("Please enter a URL to clone")
            else:
                # Prepare options
                options = {
                    'max_depth': max_depth,
                    'rate_limit': rate_limit,
                    'download_assets': download_assets,
                    'protocol': protocol
                }

                with st.spinner("Cloning website..."):
                    text_content, html_content, sitemap_content, security_content, site_structure = clone_website(clone_url, options)

                    if text_content and html_content and site_structure:
                        st.success("Website cloned successfully!")

                        # Display summary metrics
                        st.subheader("Summary")
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("Pages", site_structure['total_pages'])
                        with col2:
                            st.metric("Files", site_structure['total_files'])
                        with col3:
                            st.metric("Links", site_structure['total_links'])
                        with col4:
                            st.metric("Security Issues", len(site_structure['security_issues']))

                        # Create tabs for different views
                        tabs = st.tabs(["Pages", "Assets", "Security Issues", "Sitemap", "Preview"])

                        # Pages tab
                        with tabs[0]:
                            if site_structure['sitemap']:
                                pages_df = pd.DataFrame([
                                    {
                                        'URL': page['url'],
                                        'Title': page.get('title', 'No title'),
                                        'Content Type': page.get('content_type', 'Unknown'),
                                        'Size (KB)': round(page.get('size', 0) / 1024, 1)
                                    }
                                    for page in site_structure['sitemap']
                                    if page.get('content_type') and 'text/html' in page.get('content_type')
                                ])

                                if not pages_df.empty:
                                    st.dataframe(pages_df)
                                else:
                                    st.info("No HTML pages found")
                            else:
                                st.info("No pages information available")

                        # Assets tab
                        with tabs[1]:
                            assets = [
                                {
                                    'URL': url,
                                    'Content Type': info['content_type'],
                                    'Size (KB)': round(info['size'] / 1024, 1)
                                }
                                for url, info in site_structure['downloaded_files'].items()
                                if 'text/html' not in info['content_type']
                            ]

                            if assets:
                                assets_df = pd.DataFrame(assets)
                                st.dataframe(assets_df)
                            else:
                                st.info("No assets downloaded")

                        # Security Issues tab
                        with tabs[2]:
                            if site_structure['security_issues']:
                                for issue in site_structure['security_issues']:
                                    severity_color = {
                                        'High': 'red',
                                        'Medium': 'orange',
                                        'Low': 'green'
                                    }.get(issue['severity'], 'blue')

                                    with st.expander(f"{issue['type']} - {issue['severity']} ({issue['url']})"):
                                        st.markdown(f"**Description:** {issue['description']}")
                                        st.markdown(f"**URL:** {issue['url']}")
                                        st.markdown(f"**Severity:** :{severity_color}[{issue['severity']}]")
                                        if 'details' in issue:
                                            st.code(issue['details'])
                            else:
                                st.success("No security issues found")

                        # Sitemap tab
                        with tabs[3]:
                            st.code(sitemap_content, language='xml')

                        # Preview tab
                        with tabs[4]:
                            st.components.v1.html(html_content, height=600, scrolling=True)

                        # Create download section
                        st.subheader("Export Results")

                        col1, col2, col3 = st.columns(3)

                        # ZIP download with all content
                        with col1:
                            zip_content = create_downloadable_zip(site_structure, clone_url)
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            domain = urlparse(clone_url).netloc

                            st.download_button(
                                label="Download Complete Report (ZIP)",
                                data=zip_content,
                                file_name=f"cloned_site_{domain}_{timestamp}.zip",
                                mime="application/zip"
                            )

                        # HTML report download
                        with col2:
                            st.download_button(
                                label="Download HTML Report",
                                data=html_content,
                                file_name=f"cloned_site_{domain}_{timestamp}.html",
                                mime="text/html"
                            )

                        # PDF report download
                        with col3:
                            pdf_html = generate_website_pdf_report(html_content)
                            st.download_button(
                                label="Download PDF Report",
                                data=pdf_html,
                                file_name=f"cloned_site_{domain}_{timestamp}_pdf.html",
                                mime="text/html"
                            )

    with tab3:
        st.header("APK Security Analysis")
        st.markdown("Upload an Android APK file for security analysis")

        uploaded_file = st.file_uploader("Choose an APK file", type=['apk'])

        if uploaded_file is not None:
            with st.spinner("Analyzing APK..."):
                try:
                    # Get APK content
                    apk_bytes = uploaded_file.read()

                    # Initialize plugin manager and run APK analysis
                    plugin_manager = PluginManager()
                    apk_analyzer = next((p for p in plugin_manager.get_plugins()
                                      if p.name == "APK Security Analysis"), None)

                    if apk_analyzer:
                        results = apk_analyzer.run(apk_data=apk_bytes)

                        if 'error' in results:
                            st.error(f"Analysis failed: {results['error']}")

                            # If we have extracted files info, show it even if there was an error
                            if 'extracted_files' in results:
                                st.success("APK was extracted successfully for basic analysis")

                                # Display extracted files information
                                st.subheader("Extracted Files")

                                # Group files by type
                                file_types = {}
                                for file_info in results['extracted_files']:
                                    file_type = file_info.get('type', 'Other')
                                    if file_type not in file_types:
                                        file_types[file_type] = []
                                    file_types[file_type].append(file_info)

                                # Display file type tabs
                                file_type_tabs = st.tabs(list(file_types.keys()))
                                for i, (file_type, files) in enumerate(file_types.items()):
                                    with file_type_tabs[i]:
                                        # Convert to DataFrame for display
                                        df = pd.DataFrame(files)
                                        # Format size as KB or MB
                                        if 'size' in df.columns:
                                            df['size'] = df['size'].apply(lambda x: f"{x/1024:.1f} KB" if x < 1024*1024 else f"{x/(1024*1024):.1f} MB")
                                        st.dataframe(df)

                                # Display vulnerabilities if found
                                if 'vulnerabilities' in results and results['vulnerabilities']:
                                    st.subheader("Vulnerabilities Found")
                                    for vuln in results['vulnerabilities']:
                                        with st.expander(f"{vuln['name']} ({vuln['severity']})"):
                                            st.write(f"Type: {vuln['type']}")
                                            st.write(f"Description: {vuln['description']}")
                                            if 'files' in vuln:
                                                st.write("Affected Files:")
                                                for file in vuln['files']:
                                                    st.code(file)

                                # Add export options for extracted files
                                st.subheader("Export Results")
                                col1, col2, col3 = st.columns(3)

                                # JSON export
                                with col1:
                                    json_results = json.dumps(results, indent=2)
                                    st.download_button(
                                        label="Download JSON Report",
                                        data=json_results,
                                        file_name=f"apk_extraction_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                        mime="application/json"
                                    )

                                # HTML export
                                with col2:
                                    html_report = generate_apk_html_report(results)
                                    st.download_button(
                                        label="Download HTML Report",
                                        data=html_report,
                                        file_name=f"apk_extraction_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                                        mime="text/html"
                                    )

                                # PDF export (via HTML with print functionality)
                                with col3:
                                    pdf_html = generate_pdf_from_html(generate_apk_html_report(results))
                                    st.download_button(
                                        label="Download PDF Report",
                                        data=pdf_html,
                                        file_name=f"apk_extraction_{datetime.now().strftime('%Y%m%d_%H%M%S')}_pdf.html",
                                        mime="text/html"
                                    )
                        else:
                            # Display APK information
                            st.subheader("Application Information")
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric("App Name", results['app_name'])
                            with col2:
                                st.metric("Package", results['package'])
                            with col3:
                                st.metric("Version", f"{results['version']['name']} ({results['version']['code']})")

                            # Display SDK information
                            st.subheader("SDK Information")
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("Min SDK", results['min_sdk'])
                            with col2:
                                st.metric("Target SDK", results['target_sdk'])

                            # If we have extracted files info, show it
                            if 'extracted_files' in results:
                                with st.expander("View Extracted Files"):
                                    # Group files by type
                                    file_types = {}
                                    for file_info in results['extracted_files']:
                                        file_type = file_info.get('type', 'Other')
                                        if file_type not in file_types:
                                            file_types[file_type] = []
                                        file_types[file_type].append(file_info)

                                    # Display file type tabs
                                    file_type_tabs = st.tabs(list(file_types.keys()))
                                    for i, (file_type, files) in enumerate(file_types.items()):
                                        with file_type_tabs[i]:
                                            # Convert to DataFrame for display
                                            df = pd.DataFrame(files)
                                            # Format size as KB or MB
                                            if 'size' in df.columns:
                                                df['size'] = df['size'].apply(lambda x: f"{x/1024:.1f} KB" if x < 1024*1024 else f"{x/(1024*1024):.1f} MB")
                                            st.dataframe(df)

                            # Display permissions
                            st.subheader("Permissions Analysis")
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("Total Permissions", results['permissions']['total_permissions'])
                            with col2:
                                st.metric("Dangerous Permissions",
                                        len(results['permissions']['dangerous_permissions']))

                            with st.expander("View Dangerous Permissions"):
                                for perm in results['permissions']['dangerous_permissions']:
                                    st.warning(perm)

                            # Display vulnerabilities
                            st.subheader("Vulnerability Analysis")
                            st.metric("Total Vulnerabilities", results['total_vulnerabilities'])

                            if results['vulnerabilities']:
                                for vuln in results['vulnerabilities']:
                                    with st.expander(f"{vuln['name']} ({vuln['severity']})"):
                                        st.write(f"Type: {vuln['type']}")
                                        st.write(f"Description: {vuln['description']}")
                                        if 'components' in vuln:
                                            st.write("Affected Components:")
                                            for comp in vuln['components']:
                                                st.code(comp)

                            # Display libraries
                            st.subheader("Native Libraries")
                            st.metric("Total Libraries", results['libraries']['total_libraries'])
                            with st.expander("View Libraries"):
                                for lib in results['libraries']['libraries']:
                                    st.code(lib)

                            # Export results
                            st.subheader("Export Results")

                            # Create a row of export buttons
                            col1, col2, col3 = st.columns(3)

                            # JSON export
                            with col1:
                                json_results = json.dumps(results, indent=2)
                                st.download_button(
                                    label="Download JSON Report",
                                    data=json_results,
                                    file_name=f"apk_analysis_{results['package']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                    mime="application/json"
                                )

                            # HTML export
                            with col2:
                                html_report = generate_apk_html_report(results)
                                st.download_button(
                                    label="Download HTML Report",
                                    data=html_report,
                                    file_name=f"apk_analysis_{results['package']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                                    mime="text/html"
                                )

                            # PDF export (via HTML with print functionality)
                            with col3:
                                pdf_html = generate_pdf_from_html(generate_apk_html_report(results))
                                st.download_button(
                                    label="Download PDF Report",
                                    data=pdf_html,
                                    file_name=f"apk_analysis_{results['package']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_pdf.html",
                                    mime="text/html"
                                )
                    else:
                        st.error("APK Analyzer plugin not found")
                except Exception as e:
                    st.error(f"Error analyzing APK: {str(e)}")

    with tab4:
        st.header("File Analysis")
        st.markdown("Upload files for security analysis and vulnerability detection")

        # File uploader
        uploaded_file = st.file_uploader("Choose a file for analysis", type=None, accept_multiple_files=False)

        # Advanced options in an expander
        with st.expander("Analysis Options"):
            analyze_metadata = st.checkbox("Analyze Metadata", value=True,
                                        help="Extract and analyze file metadata")

            analyze_code = st.checkbox("Analyze Code", value=True,
                                    help="Perform code analysis for security issues")

            extract_archives = st.checkbox("Extract Archives", value=True,
                                        help="Extract and analyze archive contents")

            max_file_size = st.slider("Maximum File Size (MB)", min_value=1, max_value=500, value=50,
                                    help="Maximum file size to analyze in MB")

        if uploaded_file is not None:
            # Create a temporary file to analyze
            with st.spinner("Analyzing file..."):
                try:
                    # Save uploaded file to a temporary location
                    import tempfile
                    import os

                    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp_file:
                        tmp_file.write(uploaded_file.getvalue())
                        temp_file_path = tmp_file.name

                    # Initialize advanced plugin manager
                    plugin_manager = AdvancedPluginManager()

                    # Load the FileAnalyzer plugin
                    file_analyzer = None
                    for plugin_class_name in plugin_manager.plugin_classes:
                        if "FileAnalyzer" in plugin_class_name:
                            file_analyzer = plugin_manager.load_plugin(plugin_class_name)
                            break

                    if file_analyzer:
                        # Configure the plugin
                        file_analyzer.configure({
                            "analyze_metadata": analyze_metadata,
                            "analyze_code": analyze_code,
                            "extract_archives": extract_archives,
                            "max_file_size": max_file_size
                        })

                        # Run the analysis
                        results = file_analyzer.execute(temp_file_path)

                        # Display results
                        st.success(f"Analysis of {uploaded_file.name} completed!")

                        # Display file information
                        st.subheader("File Information")
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("File Name", results["file_name"])
                        with col2:
                            file_size_kb = results["file_size"] / 1024
                            file_size_mb = file_size_kb / 1024
                            size_str = f"{file_size_kb:.2f} KB" if file_size_mb < 1 else f"{file_size_mb:.2f} MB"
                            st.metric("File Size", size_str)
                        with col3:
                            st.metric("File Type", results["file_type"])

                        # Display file hashes
                        st.subheader("File Hashes")
                        col1, col2 = st.columns(2)
                        with col1:
                            st.code(f"MD5: {results['hashes']['md5']}")
                            st.code(f"SHA1: {results['hashes']['sha1']}")
                        with col2:
                            st.code(f"SHA256: {results['hashes']['sha256']}")

                        # Display metadata if available
                        if results["metadata"] and analyze_metadata:
                            st.subheader("Metadata")
                            metadata_df = pd.DataFrame([
                                {"Key": key, "Value": value}
                                for key, value in results["metadata"].items()
                            ])
                            st.dataframe(metadata_df)

                        # Display security issues if found
                        if results["security_issues"]:
                            st.subheader("Security Issues")
                            for issue in results["security_issues"]:
                                severity_color = {
                                    "High": "red",
                                    "Medium": "orange",
                                    "Low": "green"
                                }.get(issue["severity"], "blue")

                                with st.expander(f"{issue['type']} - :{severity_color}[{issue['severity']}]"):
                                    st.markdown(f"**Description:** {issue['description']}")
                                    if "line_number" in issue:
                                        st.markdown(f"**Line:** {issue['line_number']}")
                                    if "code" in issue:
                                        st.code(issue["code"])
                        else:
                            st.success("No security issues found")

                        # Display extracted files if available
                        if results["extracted_files"] and extract_archives:
                            st.subheader("Extracted Files")
                            extracted_df = pd.DataFrame([
                                {
                                    "File Name": os.path.basename(file["path"]),
                                    "File Type": file["type"],
                                    "Size": f"{file['size']/1024:.2f} KB" if file['size'] < 1024*1024 else f"{file['size']/(1024*1024):.2f} MB"
                                }
                                for file in results["extracted_files"]
                            ])
                            st.dataframe(extracted_df)

                        # Export options
                        st.subheader("Export Results")
                        col1, col2, col3 = st.columns(3)

                        # JSON export
                        with col1:
                            json_results = json.dumps(results, default=datetime_handler, indent=2)
                            st.download_button(
                                label="Download JSON Report",
                                data=json_results,
                                file_name=f"file_analysis_{results['file_name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                mime="application/json"
                            )

                        # HTML export
                        with col2:
                            # Generate HTML report
                            html_report = generate_file_analysis_html_report(results)
                            st.download_button(
                                label="Download HTML Report",
                                data=html_report,
                                file_name=f"file_analysis_{results['file_name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                                mime="text/html"
                            )

                        # PDF export (via HTML with print functionality)
                        with col3:
                            pdf_html = generate_pdf_from_html(generate_file_analysis_html_report(results))
                            st.download_button(
                                label="Download PDF Report",
                                data=pdf_html,
                                file_name=f"file_analysis_{results['file_name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_pdf.html",
                                mime="text/html"
                            )
                    else:
                        st.error("File Analyzer plugin not found")

                    # Clean up the temporary file
                    os.unlink(temp_file_path)

                except Exception as e:
                    st.error(f"Error analyzing file: {str(e)}")
                    import traceback
                    st.code(traceback.format_exc())

    with tab5:
        st.header("Advanced Plugins")
        st.markdown("Manage and run advanced security analysis plugins")

        # Initialize advanced plugin manager
        plugin_manager = AdvancedPluginManager()

        # Create tabs for plugin management and execution
        plugin_tab1, plugin_tab2 = st.tabs(["Available Plugins", "Run Plugin"])

        with plugin_tab1:
            st.subheader("Available Plugins")

            # Get all available plugins
            available_plugins = []
            for plugin_class_name, plugin_class in plugin_manager.plugin_classes.items():
                try:
                    plugin_instance = plugin_class()
                    available_plugins.append({
                        "name": plugin_instance.name,
                        "description": plugin_instance.metadata.description,
                        "version": plugin_instance.metadata.version,
                        "author": plugin_instance.metadata.author,
                        "category": plugin_instance.metadata.category.name,
                        "class_name": plugin_class_name
                    })
                except Exception as e:
                    st.warning(f"Error loading plugin {plugin_class_name}: {str(e)}")

            # Display plugins in a table
            if available_plugins:
                plugins_df = pd.DataFrame(available_plugins)
                st.dataframe(plugins_df)
            else:
                st.info("No plugins available")

        with plugin_tab2:
            st.subheader("Run Plugin")

            # Plugin selection
            plugin_options = [p["name"] for p in available_plugins]
            if plugin_options:
                selected_plugin_name = st.selectbox("Select Plugin", plugin_options)

                # Get the selected plugin details
                selected_plugin = next((p for p in available_plugins if p["name"] == selected_plugin_name), None)

                if selected_plugin:
                    st.markdown(f"**Description:** {selected_plugin['description']}")
                    st.markdown(f"**Version:** {selected_plugin['version']}")
                    st.markdown(f"**Author:** {selected_plugin['author']}")
                    st.markdown(f"**Category:** {selected_plugin['category']}")

                    # Load the plugin
                    plugin = plugin_manager.load_plugin(selected_plugin["class_name"])

                    if plugin:
                        # Get plugin configuration schema
                        config_schema = plugin.metadata.config_schema

                        # Create configuration inputs
                        st.subheader("Plugin Configuration")
                        config_values = {}

                        for key, schema in config_schema.items():
                            if schema["type"] == "string":
                                config_values[key] = st.text_input(
                                    schema["description"],
                                    value=schema.get("default", "")
                                )
                            elif schema["type"] == "number":
                                config_values[key] = st.slider(
                                    schema["description"],
                                    min_value=schema.get("minimum", 0),
                                    max_value=schema.get("maximum", 100),
                                    value=schema.get("default", 0)
                                )
                            elif schema["type"] == "boolean":
                                config_values[key] = st.checkbox(
                                    schema["description"],
                                    value=schema.get("default", False)
                                )

                        # Target input
                        st.subheader("Target")
                        target_type = st.radio("Target Type", ["URL/Domain", "File Upload", "Text Input"])

                        target = None
                        if target_type == "URL/Domain":
                            target = st.text_input("Enter URL or domain")
                        elif target_type == "File Upload":
                            uploaded_file = st.file_uploader("Upload target file")
                            if uploaded_file:
                                # Save to temporary file
                                import tempfile
                                import os
                                with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp_file:
                                    tmp_file.write(uploaded_file.getvalue())
                                    target = tmp_file.name
                        else:  # Text Input
                            target = st.text_area("Enter text to analyze")

                        # Run button
                        if st.button("Run Plugin") and target:
                            with st.spinner(f"Running {selected_plugin_name}..."):
                                try:
                                    # Configure the plugin
                                    plugin.configure(config_values)

                                    # Run the plugin
                                    results = plugin.execute(target)

                                    # Display results
                                    st.success(f"Plugin {selected_plugin_name} executed successfully!")

                                    # Display results in JSON format
                                    st.subheader("Results")
                                    st.json(results)

                                    # Export options
                                    st.subheader("Export Results")
                                    col1, col2 = st.columns(2)

                                    # JSON export
                                    with col1:
                                        json_results = json.dumps(results, default=datetime_handler, indent=2)
                                        st.download_button(
                                            label="Download JSON Report",
                                            data=json_results,
                                            file_name=f"{selected_plugin_name.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                            mime="application/json"
                                        )

                                    # HTML export
                                    with col2:
                                        # Generate a simple HTML report
                                        html_report = f"""
                                        <!DOCTYPE html>
                                        <html>
                                        <head>
                                            <title>{selected_plugin_name} Report</title>
                                            <style>
                                                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                                                h1 {{ color: #2c3e50; }}
                                                pre {{ background-color: #f8f9fa; padding: 10px; border-radius: 5px; }}
                                            </style>
                                        </head>
                                        <body>
                                            <h1>{selected_plugin_name} Report</h1>
                                            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                                            <h2>Results</h2>
                                            <pre>{json.dumps(results, default=datetime_handler, indent=2)}</pre>
                                        </body>
                                        </html>
                                        """

                                        st.download_button(
                                            label="Download HTML Report",
                                            data=html_report,
                                            file_name=f"{selected_plugin_name.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                                            mime="text/html"
                                        )

                                    # Clean up temporary file if needed
                                    if target_type == "File Upload" and target:
                                        try:
                                            os.unlink(target)
                                        except:
                                            pass

                                except Exception as e:
                                    st.error(f"Error running plugin: {str(e)}")
                                    import traceback
                                    st.code(traceback.format_exc())
                    else:
                        st.error(f"Failed to load plugin {selected_plugin_name}")
            else:
                st.info("No plugins available to run")

def generate_file_analysis_html_report(results: dict) -> str:
    """Generate an HTML report for file analysis results"""
    # HTML template for the report
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>File Analysis Report - {{ results.file_name }}</title>
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
            .file-list {
                max-height: 300px;
                overflow-y: auto;
                background-color: #f8f9fa;
                padding: 10px;
                border-radius: 5px;
            }
            .footer {
                text-align: center;
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #eee;
                color: #7f8c8d;
            }
            pre {
                background-color: #f8f9fa;
                padding: 10px;
                border-radius: 5px;
                overflow-x: auto;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>File Analysis Report</h1>
                <p>Generated on {{ timestamp }}</p>
            </div>

            <div class="section">
                <h2>File Information</h2>
                <div class="info-box">
                    <div class="info-item">
                        <h3>File Name</h3>
                        <p>{{ results.file_name }}</p>
                    </div>
                    <div class="info-item">
                        <h3>File Type</h3>
                        <p>{{ results.file_type }}</p>
                    </div>
                    <div class="info-item">
                        <h3>File Size</h3>
                        <p>
                            {% if results.file_size < 1024*1024 %}
                                {{ (results.file_size/1024)|round(1) }} KB
                            {% else %}
                                {{ (results.file_size/(1024*1024))|round(1) }} MB
                            {% endif %}
                        </p>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>File Hashes</h2>
                <div class="info-box">
                    <div class="info-item">
                        <h3>MD5</h3>
                        <p>{{ results.hashes.md5 }}</p>
                    </div>
                    <div class="info-item">
                        <h3>SHA1</h3>
                        <p>{{ results.hashes.sha1 }}</p>
                    </div>
                    <div class="info-item">
                        <h3>SHA256</h3>
                        <p>{{ results.hashes.sha256 }}</p>
                    </div>
                </div>
            </div>

            {% if results.metadata %}
            <div class="section">
                <h2>Metadata</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Key</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for key, value in results.metadata.items() %}
                        <tr>
                            <td>{{ key }}</td>
                            <td>{{ value }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}

            {% if results.security_issues %}
            <div class="section">
                <h2>Security Issues</h2>
                <h3>Total Issues: {{ results.security_issues|length }}</h3>

                {% for issue in results.security_issues %}
                <div class="vulnerability {{ issue.severity|lower }}">
                    <h3>{{ issue.type }} ({{ issue.severity }})</h3>
                    <p><strong>Description:</strong> {{ issue.description }}</p>

                    {% if issue.line_number %}
                    <p><strong>Line:</strong> {{ issue.line_number }}</p>
                    {% endif %}

                    {% if issue.code %}
                    <h4>Code:</h4>
                    <pre>{{ issue.code }}</pre>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
            {% endif %}

            {% if results.extracted_files %}
            <div class="section">
                <h2>Extracted Files</h2>
                <p>Total Files: {{ results.extracted_files|length }}</p>

                <table>
                    <thead>
                        <tr>
                            <th>File Name</th>
                            <th>Type</th>
                            <th>Size</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for file in results.extracted_files %}
                        <tr>
                            <td>{{ file.path.split('/')[-1] }}</td>
                            <td>{{ file.type }}</td>
                            <td>
                                {% if file.size < 1024*1024 %}
                                    {{ (file.size/1024)|round(1) }} KB
                                {% else %}
                                    {{ (file.size/(1024*1024))|round(1) }} MB
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}

            <div class="footer">
                <p>Generated by CyberWolfScanner File Analyzer</p>
                <p>© {{ current_year }} CyberWolfScanner</p>
            </div>
        </div>
    </body>
    </html>
    """

    # Create a Jinja2 template
    template = Template(html_template)

    # Render the template with the results
    html_report = template.render(
        results=results,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        current_year=datetime.now().year
    )

    return html_report

if __name__ == "__main__":
    main()