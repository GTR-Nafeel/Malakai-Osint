"""
Network Scanner Module

Active network reconnaissance using Nmap and passive scanning with Shodan.
Correlates both active and passive scan results for comprehensive network exposure analysis.
"""

import subprocess
import re
import json
import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

from modules.threat_intelligence import ThreatIntelligence
from config import SHODAN_API_KEY, REQUEST_TIMEOUT


class NetworkScanner:
    """
    Comprehensive network scanner combining Nmap (active) and Shodan (passive).
    Intelligently correlates results to identify infrastructure inconsistencies.
    """
    
    def __init__(self):
        self.threat_intel = ThreatIntelligence()
        self.shodan_key = SHODAN_API_KEY
        self.nmap_available = NMAP_AVAILABLE
    
    def run_nmap_scan(self, target: str, arguments: str = "-sV --script vuln -A") -> Dict:
        """
        Execute active Nmap scan with service detection and vulnerability scripts.
        
        Args:
            target: IP address or hostname to scan
            arguments: Nmap arguments (default: service version detection + vuln scripts)
        
        Returns:
            dict with ports, services, vulnerabilities, OS info
        """
        result = {
            'target': target,
            'scan_type': 'nmap_active',
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'ports': [],
            'services': [],
            'vulnerabilities': [],
            'os_detection': [],
            'device_type': None,
            'error': None
        }
        
        if not self.nmap_available:
            result['error'] = 'Nmap library not available. Install: pip install python-nmap'
            return result
        
        try:
            nm = nmap.PortScanner()
            print(f"[*] Running Nmap scan on {target} with args: {arguments}")
            
            # Run the scan
            nm.scan(hosts=target, arguments=arguments)
            result['success'] = True
            
            # Parse results
            for host in nm.all_hosts():
                if nm[host].state() != 'up':
                    continue
                
                # Extract open ports and services
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    
                    for port in ports:
                        port_state = nm[host][proto][port]['state']
                        
                        if port_state == 'open':
                            service_info = {
                                'port': port,
                                'protocol': proto,
                                'state': port_state,
                                'service': nm[host][proto][port].get('name', 'unknown'),
                                'product': nm[host][proto][port].get('product', 'N/A'),
                                'version': nm[host][proto][port].get('version', 'N/A'),
                                'extrainfo': nm[host][proto][port].get('extrainfo', 'N/A'),
                                'ostype': nm[host][proto][port].get('ostype', 'N/A')
                            }
                            result['ports'].append(port)
                            result['services'].append(service_info)
                
                # Extract OS detection
                if 'osmatch' in nm[host]:
                    for osmatch in nm[host]['osmatch']:
                        os_info = {
                            'name': osmatch['name'],
                            'accuracy': osmatch['accuracy'],
                            'cpe': osmatch.get('cpe', [])
                        }
                        result['os_detection'].append(os_info)
                
                # Extract script results (vulnerabilities)
                if 'hostscript' in nm[host]:
                    for script in nm[host]['hostscript']:
                        if 'vuln' in script.get('id', '').lower():
                            result['vulnerabilities'].append({
                                'script': script['id'],
                                'output': script['output'][:200]  # Truncate for display
                            })
            
            # Deduplicate and sort ports
            result['ports'] = sorted(list(set(result['ports'])))
            
        except subprocess.CalledProcessError as e:
            result['error'] = f"Nmap execution failed: {str(e)}"
        except Exception as e:
            result['error'] = f"Nmap scan error: {str(e)}"
        
        return result
    
    def query_shodan_ip_passive(self, target: str) -> Dict:
        """
        Passive Shodan scan with enhanced data extraction.
        Reuses ThreatIntelligence Shodan integration.
        
        Returns:
            dict with ports, services, historical data, ISP/ASN info
        """
        result = {
            'target': target,
            'scan_type': 'shodan_passive',
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'ports': [],
            'services': [],
            'tags': [],
            'first_seen': None,
            'last_seen': None,
            'vulnerabilities': [],
            'isp': None,
            'asn': None,
            'hostnames': [],
            'error': None
        }
        
        try:
            if not self.shodan_key:
                result['error'] = 'Shodan API key not configured'
                return result
            
            # Use ThreatIntelligence module for Shodan queries
            shodan_result = self.threat_intel.query_shodan_ip(target)
            
            if shodan_result.get('error'):
                result['error'] = shodan_result['error']
                return result
            
            result['success'] = shodan_result.get('found', False)
            result['ports'] = shodan_result.get('ports', [])
            result['vulnerabilities'] = shodan_result.get('vulnerabilities', [])
            result['isp'] = shodan_result.get('organization')
            result['hostnames'] = shodan_result.get('hostnames', [])
            
            # Extract services from Shodan
            if 'services' in shodan_result:
                result['services'] = shodan_result['services']
            
            # Query additional Shodan details via direct API for historical data
            result.update(self._get_shodan_detailed_info(target))
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _get_shodan_detailed_info(self, ip: str) -> Dict:
        """
        Get additional Shodan details: tags, first seen, last seen, ASN.
        """
        additional_info = {
            'tags': [],
            'first_seen': None,
            'last_seen': None,
            'asn': None,
            'country': None
        }
        
        try:
            # This would require direct Shodan API calls
            # For now, we'll note it as an enhancement
            pass
        except Exception:
            pass
        
        return additional_info
    
    def merge_results(self, nmap_result: Dict, shodan_result: Dict) -> Dict:
        """
        Intelligently merge active Nmap and passive Shodan scan results.
        Identify discrepancies indicating internal-only services or recently exposed ports.
        
        Returns:
            dict with merged ports, service discrepancies, risk assessment
        """
        merged = {
            'target': nmap_result.get('target', shodan_result.get('target')),
            'scan_time': datetime.now().isoformat(),
            'active_scan': nmap_result.get('success', False),
            'passive_scan': shodan_result.get('success', False),
            'ports': {
                'nmap_only': [],
                'shodan_only': [],
                'both': [],
                'all': []
            },
            'services': [],
            'discrepancies': {
                'internal_likely': [],      # Seen by Nmap but not Shodan (internal/firewall)
                'recently_exposed': [],     # Seen by Shodan but not Nmap (recently opened)
                'filtered': [],             # Shodan knows but Nmap sees filtered/closed
            },
            'risk_assessment': {
                'unexpected_ports': [],     # Ports that shouldn't be open
                'service_versions': [],     # Outdated or vulnerable versions
                'exposure_score': 0
            },
            'summary': {}
        }
        
        try:
            nmap_ports = set(nmap_result.get('ports', []))
            shodan_ports = set(shodan_result.get('ports', []))
            
            # Categorize ports
            merged['ports']['both'] = list(nmap_ports & shodan_ports)
            merged['ports']['nmap_only'] = list(nmap_ports - shodan_ports)
            merged['ports']['shodan_only'] = list(shodan_ports - nmap_ports)
            merged['ports']['all'] = sorted(list(nmap_ports | shodan_ports))
            
            # Analyze discrepancies
            if merged['ports']['nmap_only']:
                merged['discrepancies']['internal_likely'] = {
                    'ports': sorted(merged['ports']['nmap_only']),
                    'reason': 'Open in Nmap but not indexed by Shodan - likely internal/firewalled',
                    'count': len(merged['ports']['nmap_only'])
                }
            
            if merged['ports']['shodan_only']:
                merged['discrepancies']['recently_exposed'] = {
                    'ports': sorted(merged['ports']['shodan_only']),
                    'reason': 'Indexed by Shodan but not responding to Nmap - possibly filtered/recently closed',
                    'count': len(merged['ports']['shodan_only'])
                }
            
            # Merge service information
            nmap_services = {s['port']: s for s in nmap_result.get('services', [])}
            shodan_services = shodan_result.get('services', [])
            
            for service_port in merged['ports']['all']:
                service_entry = {
                    'port': service_port,
                    'nmap': None,
                    'shodan': None,
                    'discrepancy': None
                }
                
                if service_port in nmap_services:
                    service_entry['nmap'] = nmap_services[service_port]
                
                # Find matching Shodan service
                for shodan_svc in shodan_services:
                    if shodan_svc.get('port') == service_port:
                        service_entry['shodan'] = shodan_svc
                        break
                
                # Detect version discrepancies
                if service_entry['nmap'] and service_entry['shodan']:
                    nmap_version = service_entry['nmap'].get('version', '')
                    shodan_version = service_entry['shodan'].get('banner', '')
                    if nmap_version and shodan_version and nmap_version not in shodan_version:
                        service_entry['discrepancy'] = 'Version mismatch between scans'
                
                merged['services'].append(service_entry)
            
            # Risk assessment
            # Check for common unexpected ports
            unexpected_ports = {22, 23, 3389, 445, 139}  # SSH, Telnet, RDP, SMB
            for port in merged['ports']['all']:
                if port in unexpected_ports and port not in [80, 443]:
                    merged['risk_assessment']['unexpected_ports'].append(port)
            
            # Check for outdated services
            for service in merged['services']:
                nmap_svc = service.get('nmap')
                if nmap_svc:
                    product = nmap_svc.get('product', '').lower()
                    version = nmap_svc.get('version', '')
                    
                    # Flag known outdated versions
                    if any(old in version for old in ['1.x', '2.x', '3.x', '4.x']):
                        merged['risk_assessment']['service_versions'].append({
                            'port': service['port'],
                            'service': nmap_svc.get('service'),
                            'version': version,
                            'risk': 'Potentially outdated'
                        })
            
            # Calculate exposure score
            exposure_score = 0
            exposure_score += len(merged['ports']['all']) * 2  # 2 pts per port
            exposure_score += len(merged['risk_assessment']['unexpected_ports']) * 15
            exposure_score += len(merged['risk_assessment']['service_versions']) * 10
            exposure_score += len(merged['discrepancies']['recently_exposed'].get('ports', [])) * 8
            
            merged['risk_assessment']['exposure_score'] = min(100, exposure_score)
            
            # Generate summary
            merged['summary'] = {
                'total_ports': len(merged['ports']['all']),
                'nmap_ports': len(nmap_ports),
                'shodan_ports': len(shodan_ports),
                'ports_in_both': len(merged['ports']['both']),
                'internal_likely_count': len(merged['ports']['nmap_only']),
                'recently_exposed_count': len(merged['ports']['shodan_only']),
                'exposure_score': merged['risk_assessment']['exposure_score'],
                'vulnerabilities_found': len(nmap_result.get('vulnerabilities', [])),
                'os_confidence': max([int(os.get('accuracy', 0)) for os in nmap_result.get('os_detection', [])], default=0)
            }
        
        except Exception as e:
            merged['error'] = str(e)
        
        return merged
    
    def format_output(self, merged_result: Dict) -> Dict:
        """
        Format scan results into clean, report-style dictionary.
        
        Returns:
            dict with formatted sections: overview, ports, services, risks, insights
        """
        output = {
            'report_title': f"Network Reconnaissance Report - {merged_result.get('target')}",
            'scan_datetime': merged_result.get('scan_time'),
            'overview': {},
            'ports_and_services': {
                'summary': {},
                'all_ports': [],
                'discrepancies': {}
            },
            'vulnerabilities': {
                'critical': [],
                'high': [],
                'medium': [],
                'count': 0
            },
            'infrastructure_insights': {
                'likely_internal': [],
                'recently_exposed': [],
                'filtering_detected': False
            },
            'risk_summary': {
                'exposure_score': 0,
                'risk_level': 'unknown',
                'unexpected_ports': [],
                'outdated_services': []
            },
            'recommendations': []
        }
        
        try:
            # Overview
            summary = merged_result.get('summary', {})
            output['overview'] = {
                'active_scan_success': merged_result.get('active_scan', False),
                'passive_scan_success': merged_result.get('passive_scan', False),
                'total_ports_discovered': summary.get('total_ports', 0),
                'services_identified': len(merged_result.get('services', [])),
                'ports_visible_in_both_scans': summary.get('ports_in_both', 0)
            }
            
            # Ports and services
            output['ports_and_services']['summary'] = {
                'nmap_discovered': summary.get('nmap_ports', 0),
                'shodan_indexed': summary.get('shodan_ports', 0),
                'overlap': summary.get('ports_in_both', 0),
                'internal_only': summary.get('internal_likely_count', 0),
                'recently_exposed': summary.get('recently_exposed_count', 0)
            }
            
            # Format port list
            for service in merged_result.get('services', []):
                port_entry = {
                    'port': service.get('port'),
                    'nmap': self._format_service(service.get('nmap')),
                    'shodan': self._format_service(service.get('shodan')),
                    'both_scans': service.get('port') in merged_result.get('ports', {}).get('both', []),
                    'discrepancy': service.get('discrepancy')
                }
                output['ports_and_services']['all_ports'].append(port_entry)
            
            # Discrepancies
            discrepancies = merged_result.get('discrepancies', {})
            if discrepancies.get('internal_likely'):
                output['infrastructure_insights']['likely_internal'] = discrepancies['internal_likely']
                output['recommendations'].append(
                    f"⚠️  Found {discrepancies['internal_likely'].get('count', 0)} ports internal-only (Nmap sees, Shodan doesn't). "
                    "These may be firewalled or internal-only services. Verify access controls."
                )
            
            if discrepancies.get('recently_exposed'):
                output['infrastructure_insights']['recently_exposed'] = discrepancies['recently_exposed']
                output['recommendations'].append(
                    f"🔍 {discrepancies['recently_exposed'].get('count', 0)} ports indexed by Shodan but not responding. "
                    "May indicate recently closed ports or rate-limiting. Re-scan if important."
                )
            
            # Vulnerabilities (from Nmap vuln scripts)
            # In real scenario, would parse and categorize by severity
            
            # Risk summary
            risk_assessment = merged_result.get('risk_assessment', {})
            output['risk_summary'] = {
                'exposure_score': risk_assessment.get('exposure_score', 0),
                'risk_level': self._calculate_risk_level(risk_assessment.get('exposure_score', 0)),
                'unexpected_ports': risk_assessment.get('unexpected_ports', []),
                'outdated_services': risk_assessment.get('service_versions', [])
            }
            
            # Add recommendations based on findings
            if risk_assessment.get('unexpected_ports'):
                output['recommendations'].append(
                    f"🚨 Found {len(risk_assessment['unexpected_ports'])} unexpected open ports. "
                    "Review firewall rules and service configurations."
                )
            
            if risk_assessment.get('service_versions'):
                output['recommendations'].append(
                    "📦 Outdated service versions detected. Schedule security patches."
                )
            
            if risk_assessment.get('exposure_score', 0) > 60:
                output['recommendations'].append(
                    "🔴 HIGH EXPOSURE: Consider network segmentation and stricter firewall policies."
                )
        
        except Exception as e:
            output['error'] = str(e)
        
        return output
    
    def _format_service(self, service_data: Optional[Dict]) -> Optional[Dict]:
        """Format service data for clean output."""
        if not service_data:
            return None
        
        if 'product' in service_data:  # Nmap format
            return {
                'service': service_data.get('service'),
                'product': service_data.get('product'),
                'version': service_data.get('version'),
                'extrainfo': service_data.get('extrainfo')
            }
        elif 'banner' in service_data:  # Shodan format
            return {
                'service': service_data.get('service'),
                'banner': service_data.get('banner'),
                'source': 'shodan'
            }
        
        return service_data
    
    def _calculate_risk_level(self, score: int) -> str:
        """Convert exposure score to risk level."""
        if score >= 80:
            return '🔴 CRITICAL'
        elif score >= 60:
            return '🟠 HIGH'
        elif score >= 40:
            return '🟡 MEDIUM'
        elif score >= 20:
            return '🟢 LOW'
        else:
            return '✅ MINIMAL'
    
    def run_full_network_scan(self, target: str, nmap_args: str = "-sV --script vuln -A") -> Dict:
        """
        Execute full network reconnaissance combining active and passive scans.
        
        Returns:
            formatted report-style dictionary
        """
        print(f"\n[*] Starting full network reconnaissance on {target}")
        
        results = {
            'target': target,
            'scan_timestamp': datetime.now().isoformat(),
            'nmap': {},
            'shodan': {},
            'merged': {},
            'formatted_report': {}
        }
        
        # Run active scan (Nmap)
        if self.nmap_available:
            print("[*] Executing active scan (Nmap)...")
            results['nmap'] = self.run_nmap_scan(target, nmap_args)
        else:
            print("[-] Nmap not available - skipping active scan")
            results['nmap'] = {'error': 'Nmap not installed'}
        
        # Run passive scan (Shodan)
        print("[*] Executing passive scan (Shodan)...")
        results['shodan'] = self.query_shodan_ip_passive(target)
        
        # Merge results
        print("[*] Correlating scan results...")
        results['merged'] = self.merge_results(results['nmap'], results['shodan'])
        
        # Format output
        print("[*] Generating report...")
        results['formatted_report'] = self.format_output(results['merged'])
        
        return results
