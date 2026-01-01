"""
Threat Intelligence Integration Module

Integrates Shodan and VirusTotal APIs for comprehensive threat analysis
"""

import requests
import time
import json
from typing import Dict, List, Optional
from config import (
    SHODAN_API_KEY, SHODAN_BASE_URL, SHODAN_RATE_LIMIT,
    VIRUSTOTAL_API_KEY, VIRUSTOTAL_BASE_URL, VIRUSTOTAL_RATE_LIMIT,
    REQUEST_TIMEOUT, REQUEST_HEADERS
)


class ThreatIntelligence:
    """Threat Intelligence API wrapper for Shodan and VirusTotal"""
    
    def __init__(self):
        self.shodan_key = SHODAN_API_KEY
        self.vt_key = VIRUSTOTAL_API_KEY
        self.session = requests.Session()
        self.session.headers.update(REQUEST_HEADERS)
        self.last_shodan_call = 0
        self.last_vt_call = 0
    
    def query_shodan_ip(self, ip_address: str) -> Dict:
        """
        Query Shodan for IP address information.
        
        Returns:
            dict with open ports, services, hostnames, vulnerabilities
        """
        result = {
            'ip': ip_address,
            'found': False,
            'ports': [],
            'services': [],
            'hostnames': [],
            'vulnerabilities': [],
            'organization': None,
            'error': None
        }
        
        try:
            # Rate limiting
            elapsed = time.time() - self.last_shodan_call
            if elapsed < SHODAN_RATE_LIMIT:
                time.sleep(SHODAN_RATE_LIMIT - elapsed)
            
            url = f"{SHODAN_BASE_URL}/host/{ip_address}"
            params = {'key': self.shodan_key, 'minify': True}
            
            response = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)
            self.last_shodan_call = time.time()
            
            if response.status_code == 200:
                data = response.json()
                result['found'] = True
                result['ports'] = data.get('ports', [])
                result['organization'] = data.get('org', None)
                result['hostnames'] = data.get('hostnames', [])
                
                # Extract services from data
                if 'data' in data:
                    for service in data['data']:
                        service_info = {
                            'port': service.get('port'),
                            'protocol': service.get('_shodan', {}).get('module', 'unknown'),
                            'banner': service.get('product', 'N/A')
                        }
                        result['services'].append(service_info)
                
                # Extract vulnerabilities (CVEs)
                if 'vulns' in data:
                    result['vulnerabilities'] = list(data['vulns'].keys())[:5]  # Top 5
            
            elif response.status_code == 401:
                result['error'] = 'Invalid Shodan API key'
            elif response.status_code == 404:
                result['error'] = 'IP not found in Shodan database'
            else:
                result['error'] = f'API error: {response.status_code}'
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def query_shodan_domain(self, domain: str) -> Dict:
        """
        Query Shodan for domain information (DNS lookup + host search).
        
        Returns:
            dict with associated IPs and their details
        """
        result = {
            'domain': domain,
            'found': False,
            'associated_ips': [],
            'error': None
        }
        
        try:
            # Rate limiting
            elapsed = time.time() - self.last_shodan_call
            if elapsed < SHODAN_RATE_LIMIT:
                time.sleep(SHODAN_RATE_LIMIT - elapsed)
            
            # Query DNS lookup
            url = f"{SHODAN_BASE_URL}/dns/resolve"
            params = {'key': self.shodan_key, 'hostnames': domain}
            
            response = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)
            self.last_shodan_call = time.time()
            
            if response.status_code == 200:
                data = response.json()
                if domain in data:
                    ip = data[domain]
                    result['found'] = True
                    
                    # Query host details for this IP
                    host_result = self.query_shodan_ip(ip)
                    result['associated_ips'].append({
                        'ip': ip,
                        'host_info': host_result
                    })
            
            elif response.status_code == 401:
                result['error'] = 'Invalid Shodan API key'
            else:
                result['error'] = f'API error: {response.status_code}'
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def query_virustotal_domain(self, domain: str) -> Dict:
        """
        Query VirusTotal for domain reputation and analysis.
        
        Returns:
            dict with detection ratio, last analysis, categories
        """
        result = {
            'domain': domain,
            'found': False,
            'detection_ratio': '0/0',
            'malicious_votes': 0,
            'suspicious_votes': 0,
            'undetected_votes': 0,
            'categories': [],
            'last_analysis_date': None,
            'error': None
        }
        
        try:
            # Rate limiting
            elapsed = time.time() - self.last_vt_call
            if elapsed < VIRUSTOTAL_RATE_LIMIT:
                time.sleep(VIRUSTOTAL_RATE_LIMIT - elapsed)
            
            url = f"{VIRUSTOTAL_BASE_URL}/domains/{domain}"
            headers = {'x-apikey': self.vt_key}
            
            response = self.session.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            self.last_vt_call = time.time()
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                result['found'] = True
                
                # Get last analysis stats
                last_analysis = attributes.get('last_analysis_stats', {})
                result['malicious_votes'] = last_analysis.get('malicious', 0)
                result['suspicious_votes'] = last_analysis.get('suspicious', 0)
                result['undetected_votes'] = last_analysis.get('undetected', 0)
                
                # Calculate detection ratio
                total = sum(last_analysis.values())
                if total > 0:
                    detected = result['malicious_votes'] + result['suspicious_votes']
                    result['detection_ratio'] = f"{detected}/{total}"
                
                # Get categories
                categories = attributes.get('categories', {})
                result['categories'] = list(categories.values()) if categories else []
                
                # Get last analysis date
                last_analysis_date = attributes.get('last_analysis_date')
                if last_analysis_date:
                    from datetime import datetime
                    result['last_analysis_date'] = datetime.fromtimestamp(last_analysis_date).isoformat()
            
            elif response.status_code == 401:
                result['error'] = 'Invalid VirusTotal API key'
            elif response.status_code == 404:
                result['error'] = 'Domain not found in VirusTotal'
            else:
                result['error'] = f'API error: {response.status_code}'
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def query_virustotal_ip(self, ip_address: str) -> Dict:
        """
        Query VirusTotal for IP reputation and analysis.
        
        Returns:
            dict with detection ratio, ASN, country
        """
        result = {
            'ip': ip_address,
            'found': False,
            'detection_ratio': '0/0',
            'malicious_votes': 0,
            'suspicious_votes': 0,
            'asn': None,
            'country': None,
            'error': None
        }
        
        try:
            # Rate limiting
            elapsed = time.time() - self.last_vt_call
            if elapsed < VIRUSTOTAL_RATE_LIMIT:
                time.sleep(VIRUSTOTAL_RATE_LIMIT - elapsed)
            
            url = f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip_address}"
            headers = {'x-apikey': self.vt_key}
            
            response = self.session.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            self.last_vt_call = time.time()
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                result['found'] = True
                
                # Get last analysis stats
                last_analysis = attributes.get('last_analysis_stats', {})
                result['malicious_votes'] = last_analysis.get('malicious', 0)
                result['suspicious_votes'] = last_analysis.get('suspicious', 0)
                
                # Calculate detection ratio
                total = sum(last_analysis.values())
                if total > 0:
                    detected = result['malicious_votes'] + result['suspicious_votes']
                    result['detection_ratio'] = f"{detected}/{total}"
                
                # Get ASN and country
                result['asn'] = attributes.get('asn')
                result['country'] = attributes.get('country')
            
            elif response.status_code == 401:
                result['error'] = 'Invalid VirusTotal API key'
            elif response.status_code == 404:
                result['error'] = 'IP not found in VirusTotal'
            else:
                result['error'] = f'API error: {response.status_code}'
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def bulk_threat_check(self, domain: str, ip_address: Optional[str] = None) -> Dict:
        """
        Perform comprehensive threat intelligence check on domain and optional IP.
        
        Returns:
            dict with combined results from all sources
        """
        results = {
            'domain': domain,
            'timestamp': time.time(),
            'shodan': {},
            'virustotal_domain': {},
            'virustotal_ip': {},
            'threat_score': 0,
            'overall_status': 'clean'
        }
        
        try:
            # Query Shodan for domain
            if SHODAN_API_KEY:
                results['shodan'] = self.query_shodan_domain(domain)
            
            # Query VirusTotal for domain
            if VIRUSTOTAL_API_KEY:
                results['virustotal_domain'] = self.query_virustotal_domain(domain)
            
            # Query VirusTotal for IP if provided
            if ip_address and VIRUSTOTAL_API_KEY:
                results['virustotal_ip'] = self.query_virustotal_ip(ip_address)
            
            # Calculate threat score
            threat_score = 0
            
            # Score from VirusTotal domain detection
            vt_domain = results['virustotal_domain']
            if vt_domain.get('malicious_votes', 0) > 0:
                threat_score += vt_domain['malicious_votes'] * 10
            if vt_domain.get('suspicious_votes', 0) > 0:
                threat_score += vt_domain['suspicious_votes'] * 5
            
            # Score from VirusTotal IP detection
            vt_ip = results['virustotal_ip']
            if vt_ip.get('malicious_votes', 0) > 0:
                threat_score += vt_ip['malicious_votes'] * 10
            if vt_ip.get('suspicious_votes', 0) > 0:
                threat_score += vt_ip['suspicious_votes'] * 5
            
            # Score from Shodan vulnerabilities
            shodan = results['shodan']
            if shodan.get('found') and shodan.get('associated_ips'):
                host_vulns = shodan['associated_ips'][0].get('host_info', {}).get('vulnerabilities', [])
                threat_score += len(host_vulns) * 15
            
            results['threat_score'] = min(100, threat_score)
            
            # Determine overall status
            if threat_score >= 50:
                results['overall_status'] = 'malicious'
            elif threat_score >= 25:
                results['overall_status'] = 'suspicious'
            elif threat_score > 0:
                results['overall_status'] = 'warning'
            else:
                results['overall_status'] = 'clean'
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
