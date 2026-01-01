# ssl_analyzer.py
import socket
import ssl
import json
import requests
import concurrent.futures
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding
from datetime import datetime
from urllib.parse import urlparse
import re
from typing import Dict, List, Tuple, Set, Optional
import dns.resolver
import ipaddress




class SSLAnalyzer:
    def __init__(self, timeout: int = 10):
        """
        Initialize SSL Analyzer
        
        Args:
            timeout: Timeout for SSL connections in seconds
        """
        self.timeout = timeout
        self.ct_sources = [
            "https://crt.sh/?q={domain}&output=json",
            "https://crt.sh/?q=%.{domain}&output=json",
            "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        ]
        
    def analyze_domain_certificate(self, domain: str, port: int = 443) -> Dict:
        """
        Comprehensive SSL/TLS certificate analysis for a domain
        
        Args:
            domain: Target domain
            port: SSL/TLS port (default: 443)
            
        Returns:
            Dictionary containing comprehensive certificate analysis
        """
        results = {
            'domain': domain,
            'port': port,
            'certificate_info': {},
            'subject_alternative_names': [],
            'certificate_transparency': [],
            'related_domains': [],
            'wildcard_certificates': [],
            'validation': {
                'is_valid': True,
                'errors': [],
                'warnings': []
            },
            'analysis': {
                'security_issues': [],
                'recommendations': []
            }
        }
        
        try:
            # 1. Get certificate from server
            cert_info = self._get_certificate_info(domain, port)
            # record the domain we queried so downstream checks know the target
            if isinstance(cert_info, dict):
                cert_info['domain'] = domain
            results['certificate_info'] = cert_info
            
            # 2. Extract SANs
            sans = self._extract_subject_alternative_names(cert_info)
            results['subject_alternative_names'] = sans
            
            # 3. Check for wildcard certificates
            wildcards = self._find_wildcard_certificates(sans, cert_info)
            results['wildcard_certificates'] = wildcards
            
            # 4. Query Certificate Transparency logs
            ct_logs = self._query_certificate_transparency(domain)
            results['certificate_transparency'] = ct_logs
            
            # 5. Find related domains (same certificate)
            related = self._find_related_domains(domain, sans, ct_logs)
            results['related_domains'] = related
            
            # 6. Validate certificate
            validation = self._validate_certificate(cert_info, sans)
            results['validation'] = validation
            
            # 7. Security analysis
            analysis = self._perform_security_analysis(cert_info, sans, wildcards, ct_logs)
            results['analysis'] = analysis
            
        except Exception as e:
            results['error'] = str(e)
            results['validation']['is_valid'] = False
            results['validation']['errors'].append(f"Analysis failed: {str(e)}")
            
        return results
    
    def _get_certificate_info(self, domain: str, port: int = 443) -> Dict:
        """
        RELIABLE method — always returns the real leaf cert browsers see.
        No verification, no CA bundle issues, no wrong/old certs.
        """
        try:
            # This is the gold standard — used by every serious OSINT tool
            pem_data = ssl.get_server_certificate((domain, port))
            cert = x509.load_pem_x509_certificate(pem_data.encode(), default_backend())
            return self._parse_certificate_details(cert, domain)
        except Exception as e:
            raise Exception(f"Failed to retrieve certificate: {str(e)}")
    
    def _parse_certificate_details(self, cert: x509.Certificate, domain: str) -> Dict:
        """
        Parse certificate details using cryptography library
        
        Args:
            cert: Cryptography certificate object
            domain: Original domain
            
        Returns:
            Dictionary with parsed certificate details
        """
        details = {
            'subject': {},
            'issuer': {},
            'validity': {},
            'extensions': {},
            'fingerprints': {},
            'technical_details': {}
        }
        
        try:
            # Subject information
            subject = cert.subject
            details['subject'] = {
                'common_name': self._get_attribute(subject, x509.NameOID.COMMON_NAME),
                'organization': self._get_attribute(subject, x509.NameOID.ORGANIZATION_NAME),
                'organizational_unit': self._get_attribute(subject, x509.NameOID.ORGANIZATIONAL_UNIT_NAME),
                'country': self._get_attribute(subject, x509.NameOID.COUNTRY_NAME),
                'state': self._get_attribute(subject, x509.NameOID.STATE_OR_PROVINCE_NAME),
                'locality': self._get_attribute(subject, x509.NameOID.LOCALITY_NAME),
                'email': self._get_attribute(subject, x509.NameOID.EMAIL_ADDRESS)
            }
            
            # Issuer information
            issuer = cert.issuer
            details['issuer'] = {
                'common_name': self._get_attribute(issuer, x509.NameOID.COMMON_NAME),
                'organization': self._get_attribute(issuer, x509.NameOID.ORGANIZATION_NAME),
                'organizational_unit': self._get_attribute(issuer, x509.NameOID.ORGANIZATIONAL_UNIT_NAME),
                'country': self._get_attribute(issuer, x509.NameOID.COUNTRY_NAME),
                'certificate_authority': True if 'CN=' in str(issuer) else False
            }
            
            # Validity period (ISO format)
            try:
                nvb = cert.not_valid_before
                nva = cert.not_valid_after
                details['validity'] = {
                    'not_valid_before': nvb.isoformat() if isinstance(nvb, datetime) else str(nvb),
                    'not_valid_after': nva.isoformat() if isinstance(nva, datetime) else str(nva),
                    'days_remaining': (nva - datetime.now()).days if isinstance(nva, datetime) else None,
                    'total_days': (nva - nvb).days if isinstance(nva, datetime) and isinstance(nvb, datetime) else None
                }
            except Exception:
                details['validity'] = {'not_valid_before': None, 'not_valid_after': None, 'days_remaining': None, 'total_days': None}
            
            # Serial number (provide decimal and hex)
            try:
                serial_dec = str(cert.serial_number)
                serial_hex = format(cert.serial_number, 'X')
                details['serial_number'] = {'decimal': serial_dec, 'hex': serial_hex}
            except Exception:
                details['serial_number'] = {'decimal': None, 'hex': None}
            
            # Version
            details['version'] = cert.version.name
            
            # Fingerprints
            try:
                details['fingerprints'] = {
                    'sha1': cert.fingerprint(hashes.SHA1()).hex(),
                    'sha256': cert.fingerprint(hashes.SHA256()).hex()
                }
            except Exception:
                details['fingerprints'] = {}
            
            # Signature algorithm
            details['signature_algorithm'] = cert.signature_algorithm_oid._name
            
            # Public key information
            public_key = cert.public_key()
            details['public_key'] = {
                'algorithm': public_key.__class__.__name__,
                'key_size': public_key.key_size if hasattr(public_key, 'key_size') else None,
                'exponent': getattr(public_key, 'public_numbers', {}).get('e') if hasattr(public_key, 'public_numbers') else None
            }
            
            # Certificate extensions and explicit SAN extraction
            extensions = {}
            san_list = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                if san_ext:
                    san = san_ext.value
                    # collect DNS names
                    try:
                        dns_names = san.get_values_for_type(x509.DNSName)
                    except Exception:
                        dns_names = []
                    for name in dns_names:
                        san_list.append({'type': 'DNS', 'value': name})
                    # collect IPAddresses
                    try:
                        ip_vals = san.get_values_for_type(x509.IPAddress)
                    except Exception:
                        ip_vals = []
                    for ipval in ip_vals:
                        san_list.append({'type': 'IP', 'value': str(ipval)})
                    extensions['subject_alternative_names'] = san_list
            except x509.ExtensionNotFound:
                extensions['subject_alternative_names'] = []
            
            try:
                # Key Usage
                ku_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
                if ku_ext:
                    extensions['key_usage'] = {
                        'digital_signature': ku_ext.value.digital_signature,
                        'key_encipherment': ku_ext.value.key_encipherment,
                        'key_cert_sign': ku_ext.value.key_cert_sign,
                        'crl_sign': ku_ext.value.crl_sign
                    }
            except x509.ExtensionNotFound:
                pass
            
            try:
                # Extended Key Usage
                eku_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE)
                if eku_ext:
                    extensions['extended_key_usage'] = [usage._name for usage in eku_ext.value]
            except x509.ExtensionNotFound:
                pass
            
            try:
                # Basic Constraints
                bc_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
                if bc_ext:
                    extensions['basic_constraints'] = {
                        'ca': bc_ext.value.ca,
                        'path_length': bc_ext.value.path_length
                    }
            except x509.ExtensionNotFound:
                pass
            
            details['extensions'] = extensions
            
        except Exception as e:
            details['parse_error'] = str(e)
        
        return details
    
    def _get_attribute(self, name: x509.Name, oid: x509.ObjectIdentifier) -> str:
        """Extract attribute from X.509 name"""
        try:
            attributes = name.get_attributes_for_oid(oid)
            if attributes:
                return attributes[0].value
        except:
            pass
        return ""
    
    def _extract_subject_alternative_names(self, cert_info: Dict) -> List[Dict]:
        """
        Extract and categorize Subject Alternative Names
        
        Args:
            cert_info: Certificate information dictionary
            
        Returns:
            List of categorized SANs
        """
        sans = []
        
        try:
            # Check extensions for SANs — supports both string and structured lists
            ext = cert_info.get('extensions', {}) if isinstance(cert_info, dict) else {}
            san_field = ext.get('subject_alternative_names')

            if san_field:
                # If it's a list of dicts (as produced by parser), normalize
                if isinstance(san_field, list):
                    for entry in san_field:
                        if isinstance(entry, dict):
                            val = entry.get('value')
                            typ = entry.get('type', 'DNS')
                        else:
                            # fallback: treat as DNS string
                            val = str(entry)
                            typ = 'DNS'
                        san_entry = {
                            'type': typ,
                            'value': val,
                            'is_wildcard': isinstance(val, str) and val.startswith('.*') or (isinstance(val, str) and val.startswith('*.')),
                            'category': self._categorize_san_entry(val if isinstance(val, str) else str(val))
                        }
                        sans.append(san_entry)

                # If it's a string, parse as before
                elif isinstance(san_field, str):
                    entries = san_field.split(', ')
                    for entry in entries:
                        if ':' in entry:
                            entry_type, value = entry.split(':', 1)
                            entry_type = entry_type.strip()
                            value = value.strip()
                            san_entry = {
                                'type': entry_type,
                                'value': value,
                                'is_wildcard': value.startswith('*.'),
                                'category': self._categorize_san_entry(value)
                            }
                            sans.append(san_entry)
                else:
                    # Unknown format — attempt to stringify
                    try:
                        for item in list(san_field):
                            val = item
                            san_entry = {
                                'type': 'DNS',
                                'value': str(val),
                                'is_wildcard': str(val).startswith('*.') ,
                                'category': self._categorize_san_entry(str(val))
                            }
                            sans.append(san_entry)
                    except Exception:
                        pass

        except Exception as e:
            sans.append({
                'error': f"Failed to parse SANs: {str(e)}"
            })
        
        return sans
    
    def _categorize_san_entry(self, value: str) -> str:
        """Categorize SAN entry"""
        try:
            if value.startswith('*.'):
                return 'wildcard'
            elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
                return 'ipv4'
            elif ':' in value:  # IPv6
                return 'ipv6'
            elif '@' in value:  # Email
                return 'email'
            elif value.startswith('http'):  # URL
                return 'uri'
            else:
                # Check if it's a domain
                if '.' in value and not value.startswith('*'):
                    return 'domain'
                return 'unknown'
        except:
            return 'unknown'
    
    def _find_wildcard_certificates(self, sans: List[Dict], cert_info: Dict) -> List[Dict]:
        """
        Identify wildcard certificates
        
        Args:
            sans: List of SAN entries
            cert_info: Certificate information
            
        Returns:
            List of wildcard certificate patterns
        """
        wildcards = []
        
        # Check SANs for wildcards
        for san in sans:
            if san.get('is_wildcard', False):
                wildcards.append({
                    'pattern': san['value'],
                    'type': 'san_wildcard',
                    'scope': san['value'].replace('*.', ''),
                    'coverage': self._calculate_wildcard_coverage(san['value'])
                })
        
        # Check subject CN for wildcards
        subject_cn = cert_info.get('subject', {}).get('common_name', '')
        if subject_cn.startswith('*.'):
            wildcards.append({
                'pattern': subject_cn,
                'type': 'subject_wildcard',
                'scope': subject_cn.replace('*.', ''),
                'coverage': self._calculate_wildcard_coverage(subject_cn)
            })
        
        return wildcards
    
    def _calculate_wildcard_coverage(self, wildcard_pattern: str) -> str:
        """
        Calculate the coverage scope of a wildcard certificate
        
        Args:
            wildcard_pattern: Wildcard pattern (e.g., *.example.com)
            
        Returns:
            Coverage scope description
        """
        try:
            # Remove the wildcard part
            base_domain = wildcard_pattern.replace('*.', '')
            
            # Count subdomain levels
            parts = base_domain.split('.')
            if len(parts) >= 2:
                parent_domain = '.'.join(parts[-2:])
                return f"All subdomains of {parent_domain}"
            else:
                return f"All subdomains of {base_domain}"
        except:
            return "Unknown coverage"
    
    def _query_certificate_transparency(self, domain: str) -> List[Dict]:
        """
        Query Certificate Transparency logs from multiple sources
        
        Args:
            domain: Target domain
            
        Returns:
            List of certificates from CT logs
        """
        ct_certificates = []
        
        for source in self.ct_sources:
            try:
                url = source.format(domain=domain)
                response = requests.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if isinstance(data, list):
                        # crt.sh format
                        for cert in data:
                            ct_cert = {
                                'source': 'crt.sh',
                                'id': cert.get('id'),
                                'logged_at': cert.get('entry_timestamp'),
                                'not_before': cert.get('not_before'),
                                'not_after': cert.get('not_after'),
                                'common_name': cert.get('common_name'),
                                'name_value': cert.get('name_value', ''),
                                'issuer_name': cert.get('issuer_name', ''),
                                'certificate_url': f"https://crt.sh/?id={cert.get('id')}"
                            }
                            
                            # Parse name_value into list
                            if ct_cert['name_value']:
                                names = ct_cert['name_value'].replace('\n', ',').split(',')
                                ct_cert['all_names'] = [name.strip() for name in names if name.strip()]
                            
                            ct_certificates.append(ct_cert)
                    
                    elif isinstance(data, dict) and 'issuances' in data:
                        # certspotter format
                        for cert in data['issuances']:
                            ct_cert = {
                                'source': 'certspotter',
                                'id': cert.get('id'),
                                'logged_at': cert.get('created_at'),
                                'not_before': cert.get('not_before'),
                                'not_after': cert.get('not_after'),
                                'common_name': cert.get('common_name'),
                                'dns_names': cert.get('dns_names', []),
                                'issuer_name': cert.get('issuer_name', ''),
                                'certificate_url': f"https://crt.sh/?id={cert.get('id')}"
                            }
                            ct_certificates.append(ct_cert)
                            
            except Exception as e:
                # Continue with next source
                continue
        
        # Remove duplicates based on certificate ID or common_name + not_after
        unique_certs = []
        seen = set()
        
        for cert in ct_certificates:
            key = f"{cert.get('common_name', '')}-{cert.get('not_after', '')}"
            if key not in seen:
                seen.add(key)
                unique_certs.append(cert)
        
        return unique_certs
    
    def _find_related_domains(self, domain: str, sans: List[Dict], ct_logs: List[Dict]) -> List[Dict]:
        """
        Find domains sharing the same certificate
        
        Args:
            domain: Original domain
            sans: Subject Alternative Names from current certificate
            ct_logs: Certificate Transparency logs
            
        Returns:
            List of related domains
        """
        related_domains = []
        seen_domains = set([domain])
        
        # Extract domains from current certificate SANs
        for san in sans:
            if san['type'] == 'DNS' and not san['value'].startswith('*'):
                san_domain = san['value']
                if san_domain not in seen_domains and self._is_same_organization(domain, san_domain):
                    related_domains.append({
                        'domain': san_domain,
                        'relationship': 'same_certificate_san',
                        'source': 'current_certificate'
                    })
                    seen_domains.add(san_domain)
        
        # Extract domains from CT logs
        for ct_cert in ct_logs:
            # Get all names from CT log entry
            all_names = []
            
            if 'all_names' in ct_cert:
                all_names = ct_cert['all_names']
            elif 'dns_names' in ct_cert:
                all_names = ct_cert['dns_names']
            elif 'name_value' in ct_cert:
                names = ct_cert['name_value'].replace('\n', ',').split(',')
                all_names = [name.strip() for name in names if name.strip()]
            
            for name in all_names:
                # Skip wildcards
                if name.startswith('*.'):
                    continue
                # Normalize and skip duplicates
                norm = name.strip().lower()
                if not norm or norm in seen_domains:
                    continue
                # Basic same-organization heuristic
                try:
                    if self._is_same_organization(domain, norm):
                        related_domains.append({
                            'domain': norm,
                            'relationship': 'certificate_ct_log',
                            'source': 'ct_log'
                        })
                        seen_domains.add(norm)
                except Exception:
                    # If heuristic fails, still add the domain
                    related_domains.append({
                        'domain': norm,
                        'relationship': 'certificate_ct_log',
                        'source': 'ct_log'
                    })

        return related_domains

    def _is_same_organization(self, d1: str, d2: str) -> bool:
        """
        Heuristic check whether two domains likely belong to the same organization.
        Uses eTLD+1 style comparison (last two labels) as a lightweight approximation.
        """
        try:
            def etld1(domain: str) -> str:
                parts = domain.lower().strip().split('.')
                if len(parts) >= 2:
                    return '.'.join(parts[-2:])
                return domain.lower().strip()
            return etld1(d1) == etld1(d2)
        except Exception:
            return False

    def _validate_certificate(self, cert_info: Dict, sans: List[Dict]) -> Dict:
        """
        Basic certificate validation: expiration, CN/SAN matching.

        Returns a dict with keys: is_valid (bool), errors (list), warnings (list)
        """
        validation = {
            'is_valid': True,
            'errors': [],
            'warnings': []
        }
        try:
            validity = cert_info.get('validity', {}) if isinstance(cert_info, dict) else {}
            not_before = validity.get('not_valid_before')
            not_after = validity.get('not_valid_after')
            now = datetime.now()

            # Parse ISO timestamps if they are strings
            def parse_date(v):
                if not v:
                    return None
                if isinstance(v, str):
                    try:
                        return datetime.fromisoformat(v)
                    except Exception:
                        try:
                            # Fallback: strip timezone Z
                            return datetime.fromisoformat(v.replace('Z', '+00:00'))
                        except Exception:
                            return None
                if isinstance(v, datetime):
                    return v
                return None

            nb = parse_date(not_before)
            na = parse_date(not_after)

            if na is None:
                validation['is_valid'] = False
                validation['errors'].append('Missing certificate expiry (not_valid_after)')
            else:
                if na < now:
                    validation['is_valid'] = False
                    validation['errors'].append('Certificate has expired')
                else:
                    days_left = (na - now).days
                    if days_left <= 30:
                        validation['warnings'].append(f'Certificate expires soon ({days_left} days)')

            # CN / SAN matching
            cn = cert_info.get('subject', {}).get('common_name', '') if isinstance(cert_info, dict) else ''
            domain_matches = False
            # check against CN
            if cn:
                if cn.startswith('*.'):
                    if cert_info.get('domain') and cert_info['domain'].endswith(cn.replace('*.', '')):
                        domain_matches = True
                else:
                    if cert_info.get('domain') and cn == cert_info.get('domain'):
                        domain_matches = True

            # check against SANs
            for san in sans:
                try:
                    val = san.get('value')
                    if not val:
                        continue
                    if val.startswith('*.'):
                        if cert_info.get('domain') and cert_info['domain'].endswith(val.replace('*.', '')):
                            domain_matches = True
                            break
                    else:
                        if cert_info.get('domain') and val == cert_info.get('domain'):
                            domain_matches = True
                            break
                except Exception:
                    continue

            if not domain_matches:
                validation['warnings'].append('Certificate common name or SANs do not clearly match the target domain')

        except Exception as e:
            validation['is_valid'] = False
            validation['errors'].append(f'Validation error: {str(e)}')

        return validation

    def _perform_security_analysis(self, cert_info: Dict, sans: List[Dict], wildcards: List[Dict], ct_logs: List[Dict]) -> Dict:
        """
        Lightweight security analysis on certificate properties.
        Returns a summary dict with risk_level and risk_score.
        """
        analysis = {
            'risk_level': 'low',
            'risk_score': 0,
            'notes': []
        }
        try:
            score = 0

            # Penalize wildcard certificates (higher risk)
            if wildcards:
                score += 10
                analysis['notes'].append('Wildcard certificate observed')

            # Check key size
            pk = cert_info.get('public_key', {}) if isinstance(cert_info, dict) else {}
            key_size = pk.get('key_size') if isinstance(pk, dict) else None
            if key_size and isinstance(key_size, int):
                if key_size < 2048:
                    score += 25
                    analysis['notes'].append(f'Weak public key size: {key_size}')

            # Signature algorithm
            sig = cert_info.get('signature_algorithm', '') if isinstance(cert_info, dict) else ''
            if sig and 'md5' in sig.lower():
                score += 50
                analysis['notes'].append('Weak signature algorithm (MD5)')

            # Certificate Transparency presence reduces risk slightly
            if ct_logs and len(ct_logs) > 0:
                score -= 5

            if score < 0:
                score = 0
            if score >= 50:
                level = 'high'
            elif score >= 20:
                level = 'medium'
            else:
                level = 'low'

            analysis['risk_score'] = int(score)
            analysis['risk_level'] = level
        except Exception as e:
            analysis['notes'].append(f'Analysis error: {str(e)}')

        return analysis
