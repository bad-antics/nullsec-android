#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════
 NULLSEC Android APK ANALYZER
 Comprehensive Android application package analysis
 @author bad-antics | discord.gg/killers
═══════════════════════════════════════════════════════════════════
"""

import os
import sys
import zipfile
import xml.etree.ElementTree as ET
import hashlib
import json
import argparse
import re
import struct
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime

VERSION = "2.0.0"
AUTHOR = "bad-antics"
DISCORD = "discord.gg/killers"

BANNER = """
╭──────────────────────────────────────────╮
│      🤖 NULLSEC ANDROID APK ANALYZER    │
│      ═══════════════════════════════    │
│                                          │
│   📦 APK Package Analysis                │
│   🔍 Manifest Inspection                 │
│   🛡️  Security Assessment                │
│                                          │
│          bad-antics | NullSec            │
╰──────────────────────────────────────────╯
"""

# ═══════════════════════════════════════════════════════════════════
# License Management
# ═══════════════════════════════════════════════════════════════════

class LicenseTier:
    FREE = 0
    PREMIUM = 1
    ENTERPRISE = 2

class License:
    def __init__(self, key: str = ""):
        self.key = key
        self.tier = LicenseTier.FREE
        self.valid = False
        
        if self._validate(key):
            self.valid = True
            self.key = key
    
    def _validate(self, key: str) -> bool:
        if not key or len(key) != 24:
            return False
        if not key.startswith("NAND-"):
            return False
        
        type_code = key[5:7]
        if type_code == "PR":
            self.tier = LicenseTier.PREMIUM
        elif type_code == "EN":
            self.tier = LicenseTier.ENTERPRISE
        return True
    
    @property
    def tier_name(self) -> str:
        if self.tier == LicenseTier.PREMIUM:
            return "Premium ⭐"
        elif self.tier == LicenseTier.ENTERPRISE:
            return "Enterprise 💎"
        return "Free"
    
    @property
    def is_premium(self) -> bool:
        return self.valid and self.tier != LicenseTier.FREE


# ═══════════════════════════════════════════════════════════════════
# Console Helpers
# ═══════════════════════════════════════════════════════════════════

class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"

def print_success(msg: str):
    print(f"{Colors.GREEN}✅ {msg}{Colors.RESET}")

def print_error(msg: str):
    print(f"{Colors.RED}❌ {msg}{Colors.RESET}")

def print_warning(msg: str):
    print(f"{Colors.YELLOW}⚠️  {msg}{Colors.RESET}")

def print_info(msg: str):
    print(f"{Colors.CYAN}ℹ️  {msg}{Colors.RESET}")

def print_header(title: str):
    print("\n═══════════════════════════════════════════")
    print(f"  {title}")
    print("═══════════════════════════════════════════\n")


# ═══════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════

@dataclass
class AppInfo:
    package_name: str = ""
    version_name: str = ""
    version_code: int = 0
    min_sdk: int = 0
    target_sdk: int = 0
    app_name: str = ""
    debuggable: bool = False
    allow_backup: bool = True

@dataclass
class Component:
    name: str
    type: str  # activity, service, receiver, provider
    exported: bool
    intent_filters: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)

@dataclass
class SecurityFinding:
    severity: str  # Critical, High, Medium, Low, Info
    category: str
    title: str
    description: str
    recommendation: str = ""

@dataclass 
class AnalysisResult:
    app_info: AppInfo
    permissions: List[str]
    dangerous_permissions: List[str]
    components: List[Component]
    exported_components: List[Component]
    security_findings: List[SecurityFinding]
    native_libs: List[str]
    file_hashes: Dict[str, str]
    file_count: int
    total_size: int


# ═══════════════════════════════════════════════════════════════════
# Android Manifest Parser
# ═══════════════════════════════════════════════════════════════════

# Android namespace
ANDROID_NS = '{http://schemas.android.com/apk/res/android}'

# Dangerous permissions list
DANGEROUS_PERMISSIONS = [
    'android.permission.READ_CALENDAR',
    'android.permission.WRITE_CALENDAR',
    'android.permission.CAMERA',
    'android.permission.READ_CONTACTS',
    'android.permission.WRITE_CONTACTS',
    'android.permission.GET_ACCOUNTS',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.ACCESS_BACKGROUND_LOCATION',
    'android.permission.RECORD_AUDIO',
    'android.permission.READ_PHONE_STATE',
    'android.permission.READ_PHONE_NUMBERS',
    'android.permission.CALL_PHONE',
    'android.permission.ANSWER_PHONE_CALLS',
    'android.permission.READ_CALL_LOG',
    'android.permission.WRITE_CALL_LOG',
    'android.permission.ADD_VOICEMAIL',
    'android.permission.USE_SIP',
    'android.permission.PROCESS_OUTGOING_CALLS',
    'android.permission.BODY_SENSORS',
    'android.permission.SEND_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.READ_SMS',
    'android.permission.RECEIVE_WAP_PUSH',
    'android.permission.RECEIVE_MMS',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.MANAGE_EXTERNAL_STORAGE',
]


class AXMLParser:
    """Simple Android Binary XML Parser."""
    
    def __init__(self, data: bytes):
        self.data = data
        self.position = 0
        
    def parse(self) -> Optional[str]:
        """Parse AXML to plain XML string."""
        # Check for AXML magic
        if self.data[:4] != b'\x03\x00\x08\x00':
            # Might be plain XML
            try:
                return self.data.decode('utf-8')
            except:
                return None
        
        # This is a simplified parser
        # For full parsing, use androguard or similar
        return None


# ═══════════════════════════════════════════════════════════════════
# APK Analyzer
# ═══════════════════════════════════════════════════════════════════

class APKAnalyzer:
    def __init__(self, apk_path: str, license: License):
        self.apk_path = apk_path
        self.license = license
        self.result = None
        self.manifest_xml = None
        
    def analyze(self) -> Optional[AnalysisResult]:
        """Perform full APK analysis."""
        if not os.path.exists(self.apk_path):
            print_error(f"File not found: {self.apk_path}")
            return None
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                # Parse manifest
                app_info = self._parse_manifest(apk)
                if not app_info:
                    print_error("Could not parse AndroidManifest.xml")
                    return None
                
                # Extract permissions
                permissions = self._extract_permissions(apk)
                dangerous_perms = [p for p in permissions if p in DANGEROUS_PERMISSIONS]
                
                # Extract components
                components = self._extract_components(apk)
                exported = [c for c in components if c.exported]
                
                # Security analysis
                security_findings = self._security_analysis(app_info, permissions, components)
                
                # Native libraries
                native_libs = self._list_native_libs(apk)
                
                # File hashes
                file_hashes = self._compute_hashes(apk) if self.license.is_premium else {}
                
                # File stats
                file_count = len(apk.namelist())
                total_size = sum(info.file_size for info in apk.infolist())
                
                self.result = AnalysisResult(
                    app_info=app_info,
                    permissions=permissions,
                    dangerous_permissions=dangerous_perms,
                    components=components,
                    exported_components=exported,
                    security_findings=security_findings,
                    native_libs=native_libs,
                    file_hashes=file_hashes,
                    file_count=file_count,
                    total_size=total_size
                )
                
                return self.result
                
        except zipfile.BadZipFile:
            print_error("Invalid APK file (not a valid ZIP archive)")
            return None
        except Exception as e:
            print_error(f"Analysis failed: {e}")
            return None
    
    def _parse_manifest(self, apk: zipfile.ZipFile) -> Optional[AppInfo]:
        """Parse AndroidManifest.xml."""
        app_info = AppInfo()
        
        try:
            # Read manifest
            with apk.open('AndroidManifest.xml') as f:
                data = f.read()
            
            # Try to parse as binary XML or plain XML
            parser = AXMLParser(data)
            xml_str = parser.parse()
            
            if xml_str:
                self.manifest_xml = xml_str
                root = ET.fromstring(xml_str)
            else:
                # Use placeholder values for binary XML
                # In production, use androguard for proper parsing
                app_info.package_name = "Binary manifest (use apktool to decode)"
                return app_info
            
            # Extract info from manifest
            app_info.package_name = root.get('package', 'Unknown')
            app_info.version_name = root.get(f'{ANDROID_NS}versionName', 'Unknown')
            
            version_code = root.get(f'{ANDROID_NS}versionCode', '0')
            app_info.version_code = int(version_code) if version_code.isdigit() else 0
            
            # SDK versions
            uses_sdk = root.find('uses-sdk')
            if uses_sdk is not None:
                min_sdk = uses_sdk.get(f'{ANDROID_NS}minSdkVersion', '0')
                target_sdk = uses_sdk.get(f'{ANDROID_NS}targetSdkVersion', '0')
                app_info.min_sdk = int(min_sdk) if min_sdk.isdigit() else 0
                app_info.target_sdk = int(target_sdk) if target_sdk.isdigit() else 0
            
            # Application element
            application = root.find('application')
            if application is not None:
                app_info.debuggable = application.get(f'{ANDROID_NS}debuggable', 'false').lower() == 'true'
                app_info.allow_backup = application.get(f'{ANDROID_NS}allowBackup', 'true').lower() != 'false'
                app_info.app_name = application.get(f'{ANDROID_NS}label', '')
            
            return app_info
            
        except Exception as e:
            print_warning(f"Manifest parse error: {e}")
            # Return basic info
            app_info.package_name = "Unable to parse (binary XML)"
            return app_info
    
    def _extract_permissions(self, apk: zipfile.ZipFile) -> List[str]:
        """Extract requested permissions."""
        permissions = []
        
        if not self.manifest_xml:
            return permissions
        
        try:
            root = ET.fromstring(self.manifest_xml)
            
            for uses_perm in root.findall('uses-permission'):
                perm = uses_perm.get(f'{ANDROID_NS}name', '')
                if perm:
                    permissions.append(perm)
                    
        except Exception:
            pass
        
        return permissions
    
    def _extract_components(self, apk: zipfile.ZipFile) -> List[Component]:
        """Extract app components."""
        components = []
        
        if not self.manifest_xml:
            return components
        
        try:
            root = ET.fromstring(self.manifest_xml)
            application = root.find('application')
            
            if application is None:
                return components
            
            component_types = [
                ('activity', 'Activity'),
                ('service', 'Service'),
                ('receiver', 'Broadcast Receiver'),
                ('provider', 'Content Provider')
            ]
            
            for tag, comp_type in component_types:
                for elem in application.findall(tag):
                    name = elem.get(f'{ANDROID_NS}name', '')
                    exported = elem.get(f'{ANDROID_NS}exported', '')
                    
                    # Exported default depends on intent-filters
                    intent_filters = []
                    for intent in elem.findall('intent-filter'):
                        for action in intent.findall('action'):
                            action_name = action.get(f'{ANDROID_NS}name', '')
                            if action_name:
                                intent_filters.append(action_name)
                    
                    # Determine exported status
                    if exported == 'true':
                        is_exported = True
                    elif exported == 'false':
                        is_exported = False
                    else:
                        # If has intent-filters and targetSdk < 31, default is true
                        is_exported = len(intent_filters) > 0
                    
                    # Get permission requirements
                    perms = []
                    perm = elem.get(f'{ANDROID_NS}permission', '')
                    if perm:
                        perms.append(perm)
                    
                    components.append(Component(
                        name=name,
                        type=comp_type,
                        exported=is_exported,
                        intent_filters=intent_filters,
                        permissions=perms
                    ))
                    
        except Exception:
            pass
        
        return components
    
    def _security_analysis(self, app_info: AppInfo, permissions: List[str], 
                          components: List[Component]) -> List[SecurityFinding]:
        """Perform security analysis."""
        findings = []
        
        # Check debuggable
        if app_info.debuggable:
            findings.append(SecurityFinding(
                severity="Critical",
                category="Build Configuration",
                title="Application is Debuggable",
                description="The android:debuggable flag is set to true",
                recommendation="Set android:debuggable to false in release builds"
            ))
        
        # Check backup
        if app_info.allow_backup:
            findings.append(SecurityFinding(
                severity="Medium",
                category="Data Security",
                title="Backup Allowed",
                description="Application data can be backed up via ADB",
                recommendation="Set android:allowBackup to false or implement BackupAgent"
            ))
        
        # Check target SDK
        if app_info.target_sdk > 0 and app_info.target_sdk < 28:
            findings.append(SecurityFinding(
                severity="Medium",
                category="SDK Version",
                title="Low Target SDK",
                description=f"Target SDK {app_info.target_sdk} is below recommended level",
                recommendation="Target SDK 28 or higher for security improvements"
            ))
        
        # Check dangerous permissions
        dangerous_count = sum(1 for p in permissions if p in DANGEROUS_PERMISSIONS)
        if dangerous_count > 5:
            findings.append(SecurityFinding(
                severity="Medium",
                category="Permissions",
                title="Excessive Dangerous Permissions",
                description=f"App requests {dangerous_count} dangerous permissions",
                recommendation="Review if all permissions are necessary"
            ))
        
        # Check exported components
        exported_activities = [c for c in components if c.exported and c.type == 'Activity' and not c.permissions]
        if len(exported_activities) > 3:
            findings.append(SecurityFinding(
                severity="High",
                category="Components",
                title="Multiple Unprotected Exported Activities",
                description=f"{len(exported_activities)} activities are exported without permission",
                recommendation="Add android:permission or set android:exported=false"
            ))
        
        # Check for exported content providers
        exported_providers = [c for c in components if c.exported and c.type == 'Content Provider' and not c.permissions]
        for provider in exported_providers:
            findings.append(SecurityFinding(
                severity="High",
                category="Components",
                title=f"Exported Content Provider: {provider.name}",
                description="Content provider is exported without permission protection",
                recommendation="Add android:permission or android:readPermission/writePermission"
            ))
        
        # Check for INTERNET + dangerous combo
        has_internet = 'android.permission.INTERNET' in permissions
        has_sms = any('SMS' in p for p in permissions)
        has_contacts = any('CONTACTS' in p for p in permissions)
        
        if has_internet and (has_sms or has_contacts):
            findings.append(SecurityFinding(
                severity="Medium",
                category="Permissions",
                title="Potentially Sensitive Permission Combination",
                description="App has INTERNET with SMS or CONTACTS permissions",
                recommendation="Verify these permissions are used legitimately"
            ))
        
        return findings
    
    def _list_native_libs(self, apk: zipfile.ZipFile) -> List[str]:
        """List native libraries."""
        libs = []
        
        for name in apk.namelist():
            if name.startswith('lib/') and name.endswith('.so'):
                lib_name = os.path.basename(name)
                arch = name.split('/')[1] if '/' in name else 'unknown'
                libs.append(f"{arch}/{lib_name}")
        
        return list(set(libs))
    
    def _compute_hashes(self, apk: zipfile.ZipFile) -> Dict[str, str]:
        """Compute file hashes (Premium)."""
        hashes = {}
        
        # Hash the APK itself
        with open(self.apk_path, 'rb') as f:
            hashes['apk_md5'] = hashlib.md5(f.read()).hexdigest()
            f.seek(0)
            hashes['apk_sha256'] = hashlib.sha256(f.read()).hexdigest()
        
        # Hash key files
        for name in ['classes.dex', 'AndroidManifest.xml']:
            if name in apk.namelist():
                with apk.open(name) as f:
                    hashes[f'{name}_sha256'] = hashlib.sha256(f.read()).hexdigest()
        
        return hashes
    
    def print_report(self):
        """Print analysis report."""
        if not self.result:
            print_error("No analysis results available")
            return
        
        r = self.result
        
        print_header("🤖 APP INFORMATION")
        print(f"  Package:        {r.app_info.package_name}")
        print(f"  Version:        {r.app_info.version_name} ({r.app_info.version_code})")
        print(f"  Min SDK:        API {r.app_info.min_sdk}")
        print(f"  Target SDK:     API {r.app_info.target_sdk}")
        print(f"  Debuggable:     {'🔴 YES' if r.app_info.debuggable else '🟢 NO'}")
        print(f"  Backup:         {'⚠️ Allowed' if r.app_info.allow_backup else '✅ Disabled'}")
        print(f"  Files:          {r.file_count}")
        print(f"  Total Size:     {r.total_size / 1024 / 1024:.2f} MB")
        
        if r.permissions:
            print_header("🔐 PERMISSIONS")
            for perm in r.permissions:
                is_dangerous = perm in DANGEROUS_PERMISSIONS
                icon = "⚠️ " if is_dangerous else "  "
                print(f"  {icon}{perm}")
        
        print(f"\n  Total: {len(r.permissions)} ({len(r.dangerous_permissions)} dangerous)")
        
        if r.exported_components:
            print_header("📤 EXPORTED COMPONENTS")
            for comp in r.exported_components:
                protected = "🔒" if comp.permissions else "⚠️"
                print(f"  {protected} [{comp.type}] {comp.name}")
                if comp.intent_filters:
                    for intent in comp.intent_filters[:3]:
                        print(f"      → {intent}")
        
        if r.native_libs:
            print_header("📚 NATIVE LIBRARIES")
            for lib in r.native_libs:
                print(f"  • {lib}")
        
        if r.security_findings:
            print_header("🛡️  SECURITY FINDINGS")
            
            # Sort by severity
            severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
            sorted_findings = sorted(r.security_findings, 
                                    key=lambda x: severity_order.get(x.severity, 5))
            
            for finding in sorted_findings:
                icon = {
                    'Critical': '🔴',
                    'High': '🟠', 
                    'Medium': '🟡',
                    'Low': '🟢',
                    'Info': 'ℹ️'
                }.get(finding.severity, '⚪')
                
                print(f"  {icon} [{finding.severity}] {finding.title}")
                print(f"      {finding.description}")
                if finding.recommendation:
                    print(f"      → {finding.recommendation}")
                print()
        
        if r.file_hashes and self.license.is_premium:
            print_header("🔏 FILE HASHES")
            for name, hash_val in r.file_hashes.items():
                print(f"  {name}:")
                print(f"    {hash_val}")
        elif not self.license.is_premium:
            print_header("🔏 FILE HASHES")
            print_warning(f"Hash computation is a Premium feature: {DISCORD}")
        
        print()
    
    def export_json(self, output_path: str):
        """Export analysis results to JSON."""
        if not self.result:
            print_error("No analysis results to export")
            return
        
        if not self.license.is_premium:
            print_warning(f"JSON export is a Premium feature: {DISCORD}")
            return
        
        data = {
            "app_info": asdict(self.result.app_info),
            "permissions": self.result.permissions,
            "dangerous_permissions": self.result.dangerous_permissions,
            "components": [asdict(c) for c in self.result.components],
            "exported_components": [asdict(c) for c in self.result.exported_components],
            "security_findings": [asdict(f) for f in self.result.security_findings],
            "native_libs": self.result.native_libs,
            "file_hashes": self.result.file_hashes,
            "file_count": self.result.file_count,
            "total_size": self.result.total_size,
            "analysis_date": datetime.now().isoformat(),
            "analyzer_version": VERSION
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print_success(f"Report exported to {output_path}")


# ═══════════════════════════════════════════════════════════════════
# Interactive Menu
# ═══════════════════════════════════════════════════════════════════

def interactive_mode(license: License):
    """Interactive analysis mode."""
    
    while True:
        tier_badge = "⭐" if license.is_premium else "🆓"
        
        print(f"\n  📋 NullSec Android APK Analyzer {tier_badge}\n")
        print("  [1] Analyze APK File")
        print("  [2] Export Report (Premium)")
        print("  [3] Enter License Key")
        print("  [0] Exit")
        
        try:
            choice = input("\n  Select: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        
        if choice == "1":
            apk_path = input("  APK file path: ").strip()
            if apk_path:
                analyzer = APKAnalyzer(apk_path, license)
                print_info("Analyzing APK file...")
                if analyzer.analyze():
                    analyzer.print_report()
        
        elif choice == "2":
            apk_path = input("  APK file path: ").strip()
            output_path = input("  Output JSON path: ").strip() or "report.json"
            if apk_path:
                analyzer = APKAnalyzer(apk_path, license)
                if analyzer.analyze():
                    analyzer.export_json(output_path)
        
        elif choice == "3":
            key = input("  License key: ").strip()
            license = License(key)
            if license.valid:
                print_success(f"License activated: {license.tier_name}")
            else:
                print_warning("Invalid license key")
        
        elif choice == "0":
            break
        
        else:
            print_error("Invalid option")


# ═══════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="NullSec Android APK Analyzer")
    parser.add_argument("apk", nargs="?", help="APK file to analyze")
    parser.add_argument("-k", "--key", help="License key")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    args = parser.parse_args()
    
    if not args.quiet:
        print(f"{Colors.CYAN}{BANNER}{Colors.RESET}")
        print(f"  Version {VERSION} | {AUTHOR}")
        print(f"  🔑 Premium: {DISCORD}\n")
    
    license = License(args.key) if args.key else License()
    
    if license.valid and not args.quiet:
        print_success(f"License activated: {license.tier_name}")
    
    if args.apk:
        # CLI mode
        analyzer = APKAnalyzer(args.apk, license)
        if analyzer.analyze():
            if not args.quiet:
                analyzer.print_report()
            if args.output:
                analyzer.export_json(args.output)
    else:
        # Interactive mode
        interactive_mode(license)
    
    if not args.quiet:
        print("\n─────────────────────────────────────────")
        print("  🤖 NullSec Android APK Analyzer")
        print(f"  🔑 Premium: {DISCORD}")
        print(f"  👤 Author: {AUTHOR}")
        print("─────────────────────────────────────────\n")


if __name__ == "__main__":
    main()
