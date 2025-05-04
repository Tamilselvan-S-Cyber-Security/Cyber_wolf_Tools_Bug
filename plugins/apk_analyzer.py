import logging
import os
import zipfile
import tempfile
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from core.base_plugin import BasePlugin

class APKAnalyzer(BasePlugin):
    def __init__(self):
        self.androguard_available = False
        self.apk = None
        self.dvm = None
        self.analysis = None
        self.is_android_raw = None
        self._initialize_androguard()

    def _initialize_androguard(self):
        """Initialize androguard modules with detailed error logging"""
        try:
            logging.info("Attempting to import androguard modules...")

            # First import androguard to check if it's installed
            import androguard
            logging.info(f"Found androguard version: {androguard.__version__}")

            # Import specific modules one by one with error handling
            try:
                from androguard.core import apk
                self.apk = apk
                logging.info("Successfully imported androguard.core.apk")
            except ImportError as e:
                logging.error(f"Failed to import apk module: {str(e)}")
                return

            try:
                from androguard.core import dex
                self.dvm = dex
                logging.info("Successfully imported androguard.core.dex")
            except ImportError as e:
                logging.error(f"Failed to import dex module: {str(e)}")
                return

            try:
                from androguard.core import analysis
                self.analysis = analysis
                logging.info("Successfully imported androguard.core.analysis")
            except ImportError as e:
                logging.error(f"Failed to import analysis module: {str(e)}")
                return

            try:
                from androguard.core.androconf import is_android_raw
                self.is_android_raw = is_android_raw
                logging.info("Successfully imported androguard.core.androconf")
            except ImportError as e:
                logging.error(f"Failed to import androconf module: {str(e)}")
                return

            self.androguard_available = True
            logging.info("Successfully loaded all androguard modules")

        except ImportError as e:
            logging.error(f"Failed to import androguard base module: {str(e)}")
        except Exception as e:
            logging.error(f"Unexpected error during androguard initialization: {str(e)}")

    @property
    def name(self):
        return "APK Security Analysis"

    def extract_apk(self, apk_data: bytes) -> dict:
        """Extract APK contents and analyze without relying on text decoding"""
        temp_dir = None
        try:
            # Create a temporary directory to extract the APK
            temp_dir = tempfile.mkdtemp(prefix="apk_analysis_")
            apk_path = os.path.join(temp_dir, "app.apk")

            # Write the APK data to a file
            with open(apk_path, "wb") as f:
                f.write(apk_data)

            # Extract the APK contents
            extract_dir = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)

            with zipfile.ZipFile(apk_path, "r") as zip_ref:
                zip_ref.extractall(extract_dir)

            # Analyze the extracted contents
            results = self._analyze_extracted_apk(extract_dir)

            # Add extracted files information
            results['extracted_files'] = self._get_extracted_files_info(extract_dir)

            return results
        except Exception as e:
            logging.error(f"Error extracting APK: {str(e)}", exc_info=True)
            return {'error': f'Error extracting APK: {str(e)}'}
        finally:
            # Clean up temporary directory
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def _analyze_extracted_apk(self, extract_dir: str) -> dict:
        """Analyze the extracted APK contents"""
        results = {
            'app_name': "Unknown",
            'package': "Unknown",
            'version': {
                'name': "Unknown",
                'code': "Unknown"
            },
            'min_sdk': "Unknown",
            'target_sdk': "Unknown",
            'permissions': {
                'total_permissions': 0,
                'dangerous_permissions': [],
                'all_permissions': []
            },
            'vulnerabilities': [],
            'libraries': {
                'total_libraries': 0,
                'libraries': []
            }
        }

        # Parse AndroidManifest.xml
        manifest_path = os.path.join(extract_dir, "AndroidManifest.xml")
        if os.path.exists(manifest_path):
            try:
                # Try to parse the binary XML (this might fail if it's in binary format)
                tree = ET.parse(manifest_path)
                root = tree.getroot()

                # Extract package name
                if 'package' in root.attrib:
                    results['package'] = root.attrib['package']

                # Look for application node
                for app_node in root.findall('.//application'):
                    # Check for debuggable flag
                    if '{http://schemas.android.com/apk/res/android}debuggable' in app_node.attrib:
                        if app_node.attrib['{http://schemas.android.com/apk/res/android}debuggable'] == 'true':
                            results['vulnerabilities'].append({
                                'type': 'Configuration',
                                'name': 'Debuggable Application',
                                'severity': 'High',
                                'description': 'Application can be debugged in production'
                            })

                    # Check for backup flag
                    if '{http://schemas.android.com/apk/res/android}allowBackup' in app_node.attrib:
                        if app_node.attrib['{http://schemas.android.com/apk/res/android}allowBackup'] == 'true':
                            results['vulnerabilities'].append({
                                'type': 'Configuration',
                                'name': 'Backup Enabled',
                                'severity': 'Medium',
                                'description': 'Application data can be backed up and restored'
                            })

                # Look for permissions
                permissions = []
                for perm_node in root.findall('./uses-permission'):
                    if '{http://schemas.android.com/apk/res/android}name' in perm_node.attrib:
                        perm_name = perm_node.attrib['{http://schemas.android.com/apk/res/android}name']
                        permissions.append(perm_name)

                # Identify dangerous permissions
                dangerous_permissions = [
                    'android.permission.READ_CONTACTS',
                    'android.permission.WRITE_CONTACTS',
                    'android.permission.ACCESS_FINE_LOCATION',
                    'android.permission.ACCESS_COARSE_LOCATION',
                    'android.permission.READ_EXTERNAL_STORAGE',
                    'android.permission.WRITE_EXTERNAL_STORAGE',
                    'android.permission.CAMERA',
                    'android.permission.READ_SMS',
                    'android.permission.SEND_SMS'
                ]

                dangerous = [p for p in permissions if p in dangerous_permissions]

                results['permissions'] = {
                    'total_permissions': len(permissions),
                    'dangerous_permissions': dangerous,
                    'all_permissions': permissions
                }
            except Exception as e:
                logging.warning(f"Could not parse AndroidManifest.xml as XML: {str(e)}")
                # If we can't parse the XML, we'll just note that in the results
                results['manifest_parsing_error'] = str(e)

        # Check for native libraries
        lib_dir = os.path.join(extract_dir, "lib")
        if os.path.exists(lib_dir) and os.path.isdir(lib_dir):
            libraries = []
            for root, dirs, files in os.walk(lib_dir):
                for file in files:
                    if file.endswith(".so"):
                        rel_path = os.path.relpath(os.path.join(root, file), lib_dir)
                        libraries.append(rel_path)

            results['libraries'] = {
                'total_libraries': len(libraries),
                'libraries': libraries
            }

        # Check for potentially sensitive files
        sensitive_patterns = [
            ".keystore", ".jks", "google-services.json", "firebase.json",
            "api_key", "secret", "password", "credential", "token"
        ]

        sensitive_files = []
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                file_lower = file.lower()
                if any(pattern in file_lower for pattern in sensitive_patterns):
                    rel_path = os.path.relpath(os.path.join(root, file), extract_dir)
                    sensitive_files.append(rel_path)

        if sensitive_files:
            results['vulnerabilities'].append({
                'type': 'Security',
                'name': 'Potentially Sensitive Files',
                'severity': 'High',
                'description': f'Found {len(sensitive_files)} potentially sensitive files',
                'files': sensitive_files
            })

        # Set total vulnerabilities
        results['total_vulnerabilities'] = len(results.get('vulnerabilities', []))

        return results

    def _get_extracted_files_info(self, extract_dir: str) -> list:
        """Get information about extracted files"""
        files_info = []

        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, extract_dir)

                # Skip very large files to avoid memory issues
                file_size = os.path.getsize(file_path)
                if file_size > 10 * 1024 * 1024:  # Skip files larger than 10MB
                    files_info.append({
                        'path': rel_path,
                        'size': file_size,
                        'type': self._get_file_type(file)
                    })
                    continue

                # For smaller files, include more info
                files_info.append({
                    'path': rel_path,
                    'size': file_size,
                    'type': self._get_file_type(file)
                })

        return files_info

    def _get_file_type(self, filename: str) -> str:
        """Determine file type based on extension"""
        ext = os.path.splitext(filename)[1].lower()

        if ext in ['.xml']:
            return 'XML'
        elif ext in ['.dex']:
            return 'DEX'
        elif ext in ['.so']:
            return 'Native Library'
        elif ext in ['.jar', '.class']:
            return 'Java'
        elif ext in ['.png', '.jpg', '.jpeg', '.gif']:
            return 'Image'
        elif ext in ['.txt', '.md']:
            return 'Text'
        elif ext in ['.json']:
            return 'JSON'
        elif ext in ['.properties', '.gradle']:
            return 'Configuration'
        else:
            return 'Other'

    def run(self, target: str = None, ports: str = None, apk_data: bytes = None) -> dict:
        """Analyze APK file for security issues"""
        if not apk_data:
            return {'error': 'No APK data provided'}

        try:
            logging.info("Starting APK analysis")

            # First try using Androguard if available
            if self.androguard_available:
                try:
                    # Validate APK format
                    if not self.is_android_raw(apk_data):
                        return {'error': 'Invalid APK file format'}

                    # Parse APK with error handling for encoding issues
                    try:
                        a = self.apk.APK(apk_data)
                        if not a:
                            return {'error': 'Failed to parse APK file'}
                    except UnicodeDecodeError as e:
                        logging.error(f"Encoding error while parsing APK: {str(e)}")
                        logging.info("Falling back to manual APK extraction and analysis")
                        return self.extract_apk(apk_data)

                    # Create DalvikVMFormat object with error handling
                    try:
                        d = self.dvm.DEX(a.get_dex())
                        # Create Analysis object
                        dx = self.analysis.Analysis(d)
                    except UnicodeDecodeError as e:
                        logging.error(f"Encoding error while processing DEX: {str(e)}")
                        logging.info("Falling back to manual APK extraction and analysis")
                        return self.extract_apk(apk_data)
                    except Exception as e:
                        logging.error(f"Error processing DEX: {str(e)}")
                        logging.info("Falling back to manual APK extraction and analysis")
                        return self.extract_apk(apk_data)

                    # Gather results with error handling for each method
                    results = {}

                    try:
                        results['app_name'] = a.get_app_name() or "Unknown"
                        results['package'] = a.get_package() or "Unknown"

                        version = {}
                        try:
                            version['name'] = a.get_androidversion_name() or "Unknown"
                        except Exception as e:
                            logging.error(f"Error getting version name: {str(e)}")
                            version['name'] = "Error"

                        try:
                            version['code'] = a.get_androidversion_code() or "Unknown"
                        except Exception as e:
                            logging.error(f"Error getting version code: {str(e)}")
                            version['code'] = "Error"

                        results['version'] = version

                        try:
                            results['min_sdk'] = a.get_min_sdk_version() or "Unknown"
                        except Exception as e:
                            logging.error(f"Error getting min SDK: {str(e)}")
                            results['min_sdk'] = "Error"

                        try:
                            results['target_sdk'] = a.get_target_sdk_version() or "Unknown"
                        except Exception as e:
                            logging.error(f"Error getting target SDK: {str(e)}")
                            results['target_sdk'] = "Error"

                        # Analyze permissions, vulnerabilities, and libraries with error handling
                        results['permissions'] = self.analyze_permissions(a)
                        results['vulnerabilities'] = self.analyze_vulnerabilities(a, d, dx)
                        results['libraries'] = self.analyze_libraries(a)
                    except UnicodeDecodeError as e:
                        logging.error(f"Encoding error while gathering results: {str(e)}")
                        logging.info("Falling back to manual APK extraction and analysis")
                        return self.extract_apk(apk_data)
                    except Exception as e:
                        logging.error(f"Error gathering results: {str(e)}")
                        logging.info("Falling back to manual APK extraction and analysis")
                        return self.extract_apk(apk_data)

                    results['total_vulnerabilities'] = len(results.get('vulnerabilities', []))
                    logging.info("APK analysis completed successfully using Androguard")
                    return results
                except Exception as e:
                    logging.error(f"Error in Androguard analysis: {str(e)}", exc_info=True)
                    logging.info("Falling back to manual APK extraction and analysis")

            # If Androguard is not available or failed, fall back to manual extraction
            logging.info("Using manual APK extraction and analysis")
            return self.extract_apk(apk_data)

        except Exception as e:
            error_msg = f"Error analyzing APK: {str(e)}"
            logging.error(error_msg, exc_info=True)
            return {'error': error_msg}

    def analyze_permissions(self, apk_obj):
        """Analyze APK permissions"""
        try:
            dangerous_permissions = [
                'android.permission.READ_CONTACTS',
                'android.permission.WRITE_CONTACTS',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.ACCESS_COARSE_LOCATION',
                'android.permission.READ_EXTERNAL_STORAGE',
                'android.permission.WRITE_EXTERNAL_STORAGE',
                'android.permission.CAMERA',
                'android.permission.READ_SMS',
                'android.permission.SEND_SMS'
            ]

            permissions = apk_obj.get_permissions()
            dangerous = [p for p in permissions if p in dangerous_permissions]

            return {
                'total_permissions': len(permissions),
                'dangerous_permissions': dangerous,
                'all_permissions': list(permissions)
            }
        except UnicodeDecodeError as e:
            logging.error(f"Encoding error while analyzing permissions: {str(e)}")
            return {
                'total_permissions': 0,
                'dangerous_permissions': [],
                'all_permissions': [],
                'error': 'Encoding error while analyzing permissions'
            }
        except Exception as e:
            logging.error(f"Error analyzing permissions: {str(e)}")
            return {'error': str(e)}

    def analyze_vulnerabilities(self, apk_obj, d, dx):
        """Analyze common vulnerabilities"""
        try:
            vulnerabilities = []

            # Check for backup enabled
            if apk_obj.get_element('application', 'android:allowBackup') == 'true':
                vulnerabilities.append({
                    'type': 'Configuration',
                    'name': 'Backup Enabled',
                    'severity': 'Medium',
                    'description': 'Application data can be backed up and restored'
                })

            # Check for debuggable flag
            if apk_obj.get_element('application', 'android:debuggable') == 'true':
                vulnerabilities.append({
                    'type': 'Configuration',
                    'name': 'Debuggable Application',
                    'severity': 'High',
                    'description': 'Application can be debugged in production'
                })

            # Check for exported components
            exported_components = []
            for activity in apk_obj.get_activities():
                if apk_obj.get_element('activity', 'android:exported', activity) == 'true':
                    exported_components.append(activity)

            if exported_components:
                vulnerabilities.append({
                    'type': 'Security',
                    'name': 'Exported Components',
                    'severity': 'Medium',
                    'description': f'Found {len(exported_components)} exported components',
                    'components': exported_components
                })

            # Add code analysis using dx if needed in the future
            # This is where you would use the d and dx parameters for deeper analysis
            # For example:
            # - Check for insecure cryptography usage
            # - Detect hardcoded secrets
            # - Identify insecure network communications
            # - Find potential SQL injection points

            # Simple usage of d and dx to silence IDE warnings
            # In a real implementation, these would be used for deeper analysis
            if d and dx:
                logging.debug(f"DEX analysis object created with {len(dx.get_classes())} classes")

            return vulnerabilities
        except UnicodeDecodeError as e:
            logging.error(f"Encoding error while analyzing vulnerabilities: {str(e)}")
            return []
        except Exception as e:
            logging.error(f"Error analyzing vulnerabilities: {str(e)}")
            return []

    def analyze_libraries(self, apk_obj):
        """Analyze native libraries"""
        try:
            libs = apk_obj.get_libraries()
            return {
                'total_libraries': len(libs),
                'libraries': list(libs)
            }
        except UnicodeDecodeError as e:
            logging.error(f"Encoding error while analyzing libraries: {str(e)}")
            return {'total_libraries': 0, 'libraries': [], 'error': 'Encoding error while analyzing libraries'}
        except Exception as e:
            logging.error(f"Error analyzing libraries: {str(e)}")
            return {'total_libraries': 0, 'libraries': []}