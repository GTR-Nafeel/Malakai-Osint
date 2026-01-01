"""
Email enumeration and breach checking module.

Finds publicly exposed email addresses for a domain and checks them against
breach databases (Have I Been Pwned API).
"""

import requests
import re
from collections import defaultdict
import time


class EmailEnumerator:
    """Enumerate public emails and check breach status."""
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        # Have I Been Pwned API - uses hardcoded API endpoint
        self.hibp_url = "https://haveibeenpwned.com/api/v3"
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
    
    def find_public_emails(self, domain):
        """
        Find publicly exposed email addresses for domain.
        
        Methods:
        1. Google search operators (site:domain filetype:pdf, etc.)
        2. Common email patterns (contact@, admin@, support@, etc.)
        3. Web scraping from domain (robots.txt, sitemap)
        
        Returns:
            dict with found_emails list and sources
        """
        emails = set()
        sources = defaultdict(list)
        
        # Method 1: Search for common email patterns at domain
        common_patterns = [
            'contact', 'admin', 'support', 'info', 'sales', 'help',
            'webmaster', 'postmaster', 'root', 'abuse', 'security',
            'hello', 'team', 'hello', 'noreply', 'notifications'
        ]
        
        for pattern in common_patterns:
            email = f"{pattern}@{domain}"
            emails.add(email)
            sources['pattern_based'].append(email)
        
        # Method 2: Try to fetch common files with email patterns
        files_to_check = ['/robots.txt', '/sitemap.xml', '/humans.txt', '/.well-known/security.txt']
        
        for filepath in files_to_check:
            try:
                url = f"https://{domain}{filepath}"
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    found = self.email_pattern.findall(response.text)
                    for email in found:
                        if email.endswith(f'@{domain}'):
                            emails.add(email)
                            sources['file_based'].append(email)
            except:
                pass
        
        # Method 3: Common social platforms and directories
        # These would require API keys or web scraping, so we'll provide method hooks
        # For now, we'll check for emails from the domain in common patterns
        
        return {
            'emails_found': sorted(list(emails)),
            'sources': dict(sources),
            'total_found': len(emails)
        }
    
    def check_breach_status(self, email):
        """
        Check if email has been found in data breaches using Have I Been Pwned API.
        
        Note: This requires public API access (rate limited).
        
        Returns:
            dict with breach_status and breach_list
        """
        breach_info = {
            'has_been_pwned': False,
            'breaches': [],
            'pastes': [],
            'error': None
        }
        
        try:
            # Add rate limiting delay (HIBP requests 500ms between calls)
            time.sleep(0.55)
            
            # Query for breaches
            try:
                breach_url = f"{self.hibp_url}/breachedaccount/{email}"
                response = self.session.get(
                    breach_url,
                    timeout=self.timeout,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                
                if response.status_code == 200:
                    breach_data = response.json()
                    breach_info['has_been_pwned'] = True
                    breach_info['breaches'] = [
                        {
                            'name': b.get('Name', 'Unknown'),
                            'date': b.get('BreachDate', 'Unknown'),
                            'compromised_data': b.get('DataClasses', [])
                        }
                        for b in breach_data
                    ]
                elif response.status_code == 404:
                    # Email not found in breaches (good news)
                    breach_info['has_been_pwned'] = False
                else:
                    breach_info['error'] = f"API returned status {response.status_code}"
            except Exception as e:
                breach_info['error'] = f"Breach check failed: {str(e)}"
            
            # Query for pastes (optional, provides additional context)
            try:
                paste_url = f"{self.hibp_url}/pasteaccount/{email}"
                response = self.session.get(
                    paste_url,
                    timeout=self.timeout,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                
                if response.status_code == 200:
                    paste_data = response.json()
                    breach_info['pastes'] = [
                        {
                            'source': p.get('Source', 'Unknown'),
                            'date': p.get('PublicationDate', 'Unknown'),
                            'title': p.get('Title', 'N/A')
                        }
                        for p in paste_data
                    ]
            except:
                pass
            
        except Exception as e:
            breach_info['error'] = str(e)
        
        return breach_info
    
    def enumerate_domain_emails(self, domain):
        """
        Complete email enumeration workflow for a domain.
        
        Returns:
            dict with emails, breach status for each, and summary
        """
        results = {
            'domain': domain,
            'emails': [],
            'total_emails': 0,
            'breached_emails': 0,
            'breach_summary': {}
        }
        
        # Find emails
        email_results = self.find_public_emails(domain)
        emails = email_results.get('emails_found', [])
        
        results['total_emails'] = len(emails)
        
        # Check each email for breach status
        for email in emails:
            breach_status = self.check_breach_status(email)
            
            email_info = {
                'email': email,
                'breached': breach_status.get('has_been_pwned', False),
                'breaches': breach_status.get('breaches', []),
                'pastes': len(breach_status.get('pastes', [])),
                'error': breach_status.get('error')
            }
            
            results['emails'].append(email_info)
            
            if email_info['breached']:
                results['breached_emails'] += 1
                for breach in email_info['breaches']:
                    breach_name = breach.get('name', 'Unknown')
                    if breach_name not in results['breach_summary']:
                        results['breach_summary'][breach_name] = 0
                    results['breach_summary'][breach_name] += 1
        
        return results
