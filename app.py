import streamlit as st
import pandas as pd
from security_analyzer import PluginManager
from utils.validator import validate_domain
import json
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx
import trafilatura
import io
import zipfile
from urllib.parse import urlparse
from plugins.site_cloner import SiteCloner

def datetime_handler(obj):
    """Handle datetime serialization for JSON"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f'Object of type {obj.__class__.__name__} is not JSON serializable')

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
                        title="Cyber Wolf")
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

def clone_website(url: str) -> tuple:
    """Clone website content using site cloner"""
    try:
        cloner = SiteCloner()
        site_structure = cloner.run(urlparse(url).netloc)
        
        text_content = f"Downloaded {len(site_structure['downloaded_files'])} files\n"
        for url, info in site_structure['downloaded_files'].items():
            text_content += f"\n{url} ({info['content_type']}, {info['size']} bytes)"
        
        html_content = f"<h2>Downloaded Files</h2><ul>"
        for url, info in site_structure['downloaded_files'].items():
            html_content += f"<li><a href='{url}'>{url}</a> ({info['content_type']}, {info['size']} bytes)</li>"
        html_content += "</ul>"
        
        return text_content, html_content
    except Exception as e:
        st.error(f"Error cloning website: {str(e)}")
        return None, None

def create_downloadable_zip(text_content: str, html_content: str, url: str) -> bytes:
    """Create a ZIP file containing the cloned website content"""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Save text content
        zf.writestr('content.txt', text_content or '')
        # Save HTML content
        zf.writestr('content.html', html_content or '')

    return zip_buffer.getvalue()

def main():
    st.set_page_config(
        page_title="Cyber Wolf",
        page_icon="🕷️",
        layout="wide"
    )

    st.title("ECP Security Tool")
    st.markdown("**The security tool Developed by Cyber Wolf **")
    st.markdown("A modular security analysis framework for bug finding and vulnerability assessment")

    # Create tabs for different functionalities
    tab1, tab2, tab3 = st.tabs(["Security Analysis", "Website Cloner", "APK Analysis"])

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

        clone_url = st.text_input("Enter website URL to clone (e.g., https://example.com)")

        if st.button("Clone Website"):
            if not clone_url:
                st.error("Please enter a URL to clone")
            else:
                with st.spinner("Cloning website..."):
                    text_content, html_content = clone_website(clone_url)

                    if text_content and html_content:
                        st.success("Website cloned successfully!")

                        # Preview the content
                        with st.expander("Preview Extracted Text"):
                            st.text(text_content[:1000] + "..." if len(text_content) > 1000 else text_content)

                        # Create download buttons
                        zip_content = create_downloadable_zip(text_content, html_content, clone_url)
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        domain = clone_url.split('//')[-1].split('/')[0]

                        st.download_button(
                            label="Download Cloned Content (ZIP)",
                            data=zip_content,
                            file_name=f"cloned_site_{domain}_{timestamp}.zip",
                            mime="application/zip"
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
                            json_results = json.dumps(results, indent=2)
                            st.download_button(
                                label="Download Analysis Report (JSON)",
                                data=json_results,
                                file_name=f"apk_analysis_{results['package']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                mime="application/json"
                            )
                    else:
                        st.error("APK Analyzer plugin not found")
                except Exception as e:
                    st.error(f"Error analyzing APK: {str(e)}")

if __name__ == "__main__":
    main()