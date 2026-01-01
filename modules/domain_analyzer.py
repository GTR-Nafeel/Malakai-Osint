import socket
import re
import requests
from urllib.parse import urlparse
import ssl
import warnings
import dns.reversename
import dns.resolver

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class DomainAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        # Disable SSL verification for the session
        self.session.verify = False

    def analyze_domain(self, target):
        """Comprehensive domain and IP analysis"""
        results = {
            'domain': target,
            'ip_address': None,
            'ipv6_address': None,
            'http_status': None,
            'server_info': None,
            'technologies': [],
            'ssl_info': {},
            'reverse_dns': None,
            'cdn_waf': None,
            'security_headers': {}
        }
        
        try:
            # Clean and parse target
            if not target.startswith(('http://', 'https://')):
                target = 'https://' + target
            
            parsed = urlparse(target)
            domain = parsed.netloc or parsed.path
            
            # Get IP addresses
            try:
                ipv4 = socket.gethostbyname(domain)
                results['ip_address'] = ipv4
                
                # Perform reverse DNS lookup
                results['reverse_dns'] = self._reverse_dns_lookup(ipv4)
                
                # Check for CDN/WAF
                results['cdn_waf'] = self._detect_cdn_waf(domain, ipv4)
                
            except socket.gaierror:
                results['ip_address'] = "Unable to resolve"
            
            # Try IPv6
            try:
                ipv6_info = socket.getaddrinfo(domain, None, socket.AF_INET6)
                if ipv6_info:
                    results['ipv6_address'] = ipv6_info[0][4][0]
            except:
                pass
            
            # HTTP analysis with better error handling
            try:
                response = self.session.get(target, timeout=10, allow_redirects=True)
                results['http_status'] = response.status_code
                results['server_info'] = response.headers.get('Server', 'Not detected')
                
                # Enhanced technology detection
                self._detect_technologies(response, results)
                
                # Get SSL certificate info
                self._get_ssl_info(domain, results)
                
                # Extract security headers
                results['security_headers'] = self._analyze_security_headers(response)
                
            except requests.exceptions.SSLError:
                # Try without SSL
                try:
                    target = target.replace('https://', 'http://')
                    response = self.session.get(target, timeout=10)
                    results['http_status'] = response.status_code
                    results['server_info'] = response.headers.get('Server', 'Not detected')
                    results['ssl_info'] = {'error': 'SSL certificate error'}
                except Exception as e:
                    results['http_status'] = f"Error: {str(e)}"
            except Exception as e:
                results['http_status'] = f"Error: {str(e)}"
                
        except Exception as e:
            results['error'] = str(e)
            
        return results

    def _detect_technologies(self, response, results):
        """Enhanced technology detection with better server detection"""
        tech_indicators = {
            'WordPress': ['wp-content', 'wordpress', 'wp-json'],
            'React': ['react', 'react-dom', '__NEXT_DATA__'],
            'Node.js': ['x-powered-by: express', 'node.js'],
            'Nginx': ['nginx'],
            'Apache': ['apache', 'server: apache'],
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'PHP': ['php', 'x-powered-by: php'],
            'IIS': ['microsoft-iis', 'server: iis'],
            'Litespeed': ['litespeed'],
            'Google Analytics': ['google-analytics', 'ga.js'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
            'Akamai': ['akamai', 'server: akamai'],
            'CloudFront': ['cloudfront', 'x-amz-cf-id'],
            'GitHub Pages': ['github.io', 'x-github-request-id'],
            'Netlify': ['netlify', 'x-nf-request-id']
        }
        
        content = response.text.lower()
        headers = str(response.headers).lower()
        header_dict = {k.lower(): v for k, v in response.headers.items()}
        
        # Server detection from multiple headers
        server_headers = []
        
        # Check standard Server header
        if 'server' in header_dict:
            server_headers.append(f"Server: {header_dict['server']}")
            
        # Check X-Powered-By header
        if 'x-powered-by' in header_dict:
            server_headers.append(f"Powered by: {header_dict['x-powered-by']}")
            
        # Check Via header (proxies)
        if 'via' in header_dict:
            server_headers.append(f"Via: {header_dict['via']}")
            
        # Check X-Served-By header
        if 'x-served-by' in header_dict:
            server_headers.append(f"Served by: {header_dict['x-served-by']}")
        
        # Set server info
        if server_headers:
            results['server_info'] = " | ".join(server_headers)
        else:
            # Try to infer from other evidence
            if 'akamai' in content or 'akamai' in headers:
                results['server_info'] = "Akamai (inferred from content)"
            elif 'cloudflare' in headers:
                results['server_info'] = "Cloudflare (inferred)"
            else:
                results['server_info'] = "Not specified in headers"
        
        # Technology detection
        detected_tech = []
        for tech, indicators in tech_indicators.items():
            for indicator in indicators:
                if indicator in content or indicator in headers:
                    if tech not in detected_tech:
                        detected_tech.append(tech)
                        break
        
        results['technologies'] = detected_tech
    
    def _get_ssl_info(self, domain, results):
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    results['ssl_info'] = {
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'expires': cert.get('notAfter', 'Unknown'),
                        'version': cert.get('version', 'Unknown')
                    }
        except:
            results['ssl_info'] = {'error': 'Could not retrieve SSL certificate'}

    def _reverse_dns_lookup(self, ip_address):
        """Perform comprehensive reverse DNS lookup with additional details"""
        try:
            rev_name = dns.reversename.from_address(ip_address)
            answers = dns.resolver.resolve(rev_name, "PTR", raise_on_no_answer=False)
            
            hostnames = []
            if answers:
                hostnames = [str(rdata).rstrip('.') for rdata in answers]
                return {
                    'hostnames': hostnames,
                    'success': True,
                    'reverse_dns_found': True,
                    'count': len(hostnames)
                }
            else:
                return {
                    'hostnames': [],
                    'success': False,
                    'reverse_dns_found': False,
                    'reason': 'No reverse DNS record found'
                }
        except dns.resolver.NXDOMAIN:
            return {
                'hostnames': [],
                'success': False,
                'reverse_dns_found': False,
                'reason': 'Domain does not exist'
            }
        except dns.resolver.NoAnswer:
            return {
                'hostnames': [],
                'success': False,
                'reverse_dns_found': False,
                'reason': 'No PTR records'
            }
        except Exception as e:
            return {
                'hostnames': [],
                'success': False,
                'reverse_dns_found': False,
                'reason': str(e)
            }

    def _detect_cdn_waf(self, domain, ip_address):
        """Detect CDN and WAF providers"""
        cdn_waf_indicators = {
            'Cloudflare': {
                'ips': ['1.1.1.1', '1.0.0.1'],
                'headers': ['cf-ray', 'cf-connection-ip'],
                'cname': ['cloudflare.com']
            },
            'Akamai': {
                'headers': ['akamai-origin-hop'],
                'cname': ['akamaiedge.net']
            },
            'AWS CloudFront': {
                'headers': ['x-amz-cf-id'],
                'cname': ['cloudfront.net']
            },
            'Fastly': {
                'headers': ['x-cache', 'x-served-by'],
                'cname': ['fastly.net']
            },
            'Imperva/Incapsula': {
                'headers': ['x-iinfo'],
                'cname': ['imperva.com']
            },
            'Sucuri': {
                'headers': ['x-sucuri-id'],
                'cname': ['sucuri.net']
            },
            'Mod Security': {
                'headers': ['x-mod-pagespeed']
            }
        }
        
        detected = {
            'providers': [],
            'reasons': []
        }
        
        try:
            # Check DNS CNAME
            try:
                answers = dns.resolver.resolve(domain, 'CNAME')
                for rdata in answers:
                    cname = str(rdata).rstrip('.')
                    for provider, indicators in cdn_waf_indicators.items():
                        for cname_indicator in indicators.get('cname', []):
                            if cname_indicator in cname:
                                if provider not in detected['providers']:
                                    detected['providers'].append(provider)
                                    detected['reasons'].append(f"CNAME: {cname}")
                                break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            # Check reverse DNS
            rev_dns_info = self._reverse_dns_lookup(ip_address)
            for hostname in rev_dns_info.get('hostnames', []):
                for provider, indicators in cdn_waf_indicators.items():
                    for cname_indicator in indicators.get('cname', []):
                        if cname_indicator in hostname:
                            if provider not in detected['providers']:
                                detected['providers'].append(provider)
                                detected['reasons'].append(f"Reverse DNS: {hostname}")
                            break
            
        except Exception as e:
            detected['error'] = str(e)
        
        return detected
    
    def _analyze_security_headers(self, response):
        """
        Analyze HTTP security headers and generate security score.
        
        Checks for:
        - Content-Security-Policy (CSP)
        - Strict-Transport-Security (HSTS)
        - X-Frame-Options
        - X-Content-Type-Options
        - X-Permitted-Cross-Domain-Policies
        - Referrer-Policy
        - Permissions-Policy
        - X-XSS-Protection
        """
        headers_found = {}
        headers_missing = []
        
        # Define security headers and their importance
        security_headers_config = {
            'Content-Security-Policy': {'aliases': ['csp'], 'critical': True},
            'Strict-Transport-Security': {'aliases': ['hsts'], 'critical': True},
            'X-Frame-Options': {'aliases': ['x-frame-options'], 'critical': True},
            'X-Content-Type-Options': {'aliases': ['x-content-type-options'], 'critical': True},
            'X-Permitted-Cross-Domain-Policies': {'aliases': ['x-permitted-cross-domain-policies'], 'critical': False},
            'Referrer-Policy': {'aliases': ['referrer-policy'], 'critical': False},
            'Permissions-Policy': {'aliases': ['permissions-policy'], 'critical': False},
            'X-XSS-Protection': {'aliases': ['x-xss-protection'], 'critical': False}
        }
        
        if not response or not hasattr(response, 'headers'):
            return {
                'headers_found': headers_found,
                'headers_missing': list(security_headers_config.keys()),
                'security_score': 0,
                'error': 'No response headers available'
            }
        
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        
        for header, config in security_headers_config.items():
            header_lower = header.lower()
            if header_lower in response_headers:
                value = response_headers[header_lower]
                # Truncate very long values for display
                display_value = value[:100] + '...' if len(value) > 100 else value
                headers_found[header] = display_value
            else:
                headers_missing.append(header)
        
        # Calculate security score (0-100)
        # Start with 100 and deduct points for missing headers
        security_score = 100
        
        # Critical headers missing: -15 points each
        critical_missing = [h for h in headers_missing if security_headers_config[h]['critical']]
        security_score -= len(critical_missing) * 15
        
        # Non-critical headers missing: -5 points each
        non_critical_missing = [h for h in headers_missing if not security_headers_config[h]['critical']]
        security_score -= len(non_critical_missing) * 5
        
        # Bonus for having all headers: +10 points
        if not headers_missing:
            security_score = min(100, security_score + 10)
        
        security_score = max(0, security_score)
        
        return {
            'headers_found': headers_found,
            'headers_missing': headers_missing,
            'security_score': security_score,
            'total_headers': len(headers_found),
            'critical_headers_found': sum(1 for h in headers_found if security_headers_config[h]['critical']),
            'critical_headers_total': sum(1 for h in security_headers_config if security_headers_config[h]['critical'])
        }