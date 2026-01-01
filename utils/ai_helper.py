import json
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
import numpy as np

class AIAnalyzer:
    def __init__(self):
        self.risk_keywords = ['test', 'dev', 'staging', 'backup', 'admin', 'old']
        
    def analyze_results(self, osint_data):
        """Perform AI-powered analysis on OSINT results"""
        analysis = {
            'risk_assessment': {},
            'anomaly_detection': [],
            'pattern_analysis': {},
            'recommendations': []
        }
        
        # Risk Assessment
        analysis['risk_assessment'] = self._assess_risks(osint_data)
        
        # Anomaly Detection
        analysis['anomaly_detection'] = self._detect_anomalies(osint_data)
        
        # Pattern Analysis
        analysis['pattern_analysis'] = self._analyze_patterns(osint_data)
        
        # Generate Recommendations
        analysis['recommendations'] = self._generate_recommendations(osint_data, analysis)
        
        return analysis
    
    def _assess_risks(self, data):
        """Assess security risks based on gathered information"""
        risks = {}
        score = 0
        
        # Subdomain risks
        if 'subdomains' in data['analysis']:
            subdomains = data['analysis']['subdomains']['subdomains']
            risky_subs = [sub for sub in subdomains if any(keyword in sub.lower() for keyword in self.risk_keywords)]
            if risky_subs:
                risks['risky_subdomains'] = risky_subs
                score += len(risky_subs) * 10
        
        # DNS risks
        if 'dns_records' in data['analysis']:
            dns_data = data['analysis']['dns_records']
            if dns_data.get('zone_transfer'):
                for ns, result in dns_data['zone_transfer'].items():
                    if isinstance(result, list):
                        risks['zone_transfer_vulnerable'] = ns
                        score += 50
        
        # WHOIS risks
        if 'whois' in data['analysis']:
            whois_data = data['analysis']['whois']['parsed_data']
            if whois_data.get('registrant_name') in ['REDACTED', 'WHOISGUARD']:
                risks['privacy_service'] = True
                score += 20
        
        risks['risk_score'] = min(score, 100)
        
        if score < 30:
            risks['risk_level'] = 'LOW'
        elif score < 70:
            risks['risk_level'] = 'MEDIUM'
        else:
            risks['risk_level'] = 'HIGH'
        
        return risks
    
    def _detect_anomalies(self, data):
        """Detect anomalies in the gathered data"""
        anomalies = []
        
        # DNS anomalies
        if 'dns_records' in data['analysis']:
            dns_data = data['analysis']['dns_records']
            if len(dns_data.get('dns_servers', [])) > 6:
                anomalies.append("Unusually high number of nameservers")
        
        # Subdomain anomalies
        if 'subdomains' in data['analysis']:
            subdomains = data['analysis']['subdomains']['subdomains']
            if len(subdomains) > 100:
                anomalies.append("Very large number of subdomains")
        
        return anomalies
    
    def _analyze_patterns(self, data):
        """Analyze patterns in the data"""
        patterns = {}
        
        # Subdomain patterns
        if 'subdomains' in data['analysis']:
            subdomains = data['analysis']['subdomains']['subdomains']
            
            # Extract common prefixes
            prefixes = [sub.split('.')[0] for sub in subdomains]
            common_prefixes = {}
            for prefix in set(prefixes):
                count = prefixes.count(prefix)
                if count > 2:
                    common_prefixes[prefix] = count
            
            if common_prefixes:
                patterns['common_subdomain_patterns'] = common_prefixes
        
        return patterns
    
    def _generate_recommendations(self, data, analysis):
        """Generate security recommendations"""
        recommendations = []
        
        # Based on risk assessment
        risks = analysis['risk_assessment']
        
        if risks.get('zone_transfer_vulnerable'):
            recommendations.append("Enable zone transfer protection on nameservers")
        
        if risks.get('risky_subdomains'):
            recommendations.append("Review and secure risky subdomains")
        
        if risks['risk_score'] > 50:
            recommendations.append("Consider comprehensive security audit")
        
        # General recommendations
        recommendations.extend([
            "Ensure all services use HTTPS",
            "Implement proper DNS security (DNSSEC)",
            "Regularly update and patch services",
            "Monitor for new subdomain creations"
        ])
        
        return recommendations