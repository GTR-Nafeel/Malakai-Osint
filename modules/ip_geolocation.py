import requests
import socket
import json
import dns.resolver

class IPGeolocation:
    def __init__(self):
        self.services = [
            'https://ipapi.co/{ip}/json/',
            'http://ip-api.com/json/{ip}',
            'https://api.ipgeolocation.io/ipgeo?apiKey=demo&ip={ip}'
        ]

    def locate_ip(self, ip_address):
        """Get geolocation information for IP address"""
        results = {
            'ip': ip_address,
            'geolocation': {},
            'asn_info': {},
            'threat_intel': {}
        }
        
        try:
            # Validate IP
            socket.inet_aton(ip_address)
            
            # Try multiple services
            for service in self.services:
                try:
                    url = service.format(ip=ip_address)
                    response = requests.get(url, timeout=10)
                    
                    if response.status_code == 200:
                        data = response.json()
                        self._parse_geolocation_data(data, results)
                        break
                        
                except Exception as e:
                    continue
            
            # Get additional threat intelligence
            results['threat_intel'] = self._get_threat_intelligence(ip_address)
            
            # Extract ASN information
            results['asn_info'] = self._get_asn_info(ip_address)
            
        except Exception as e:
            results['error'] = str(e)
            
        return results

    def _parse_geolocation_data(self, data, results):
        """Parse geolocation data from API response"""
        # ipapi.co format
        if 'country_name' in data:
            results['geolocation'] = {
                'country': data.get('country_name'),
                'country_code': data.get('country_code'),
                'region': data.get('region'),
                'city': data.get('city'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'timezone': data.get('timezone'),
                'currency': data.get('currency'),
                'languages': data.get('languages'),
                'asn': data.get('asn'),
                'org': data.get('org')
            }
        
        # ip-api.com format
        elif 'country' in data:
            results['geolocation'] = {
                'country': data.get('country'),
                'country_code': data.get('countryCode'),
                'region': data.get('regionName'),
                'city': data.get('city'),
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
                'timezone': data.get('timezone'),
                'asn': data.get('as'),
                'org': data.get('org'),
                'isp': data.get('isp')
            }

    def _get_threat_intelligence(self, ip):
        """Basic threat intelligence lookup"""
        threat_info = {}
        
        try:
            # Check if IP is in known blocklists
            blocklists = [
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            ]
            
            # Note: These require API keys for full functionality
            # This is a placeholder for future implementation
            
        except:
            pass
            
        return threat_info

    def _get_asn_info(self, ip_address):
        """Extract detailed ASN information using DNS lookups and reverse DNS"""
        asn_info = {
            'asn': None,
            'network': None,
            'organization': None,
            'country': None,
            'source': None
        }
        
        try:
            # Use ASN lookup service via DNS (Team Cymru WHOIS)
            reverse_ip = '.'.join(reversed(ip_address.split('.')))
            query_domain = f"{reverse_ip}.origin.asn.cymru.com"
            
            try:
                answers = dns.resolver.resolve(query_domain, 'TXT')
                for answer in answers:
                    record = str(answer).strip('"')
                    # Format: "ASN | Network | Country Code | RIR | Allocation Date"
                    parts = [p.strip() for p in record.split('|')]
                    if len(parts) >= 3:
                        asn_info['asn'] = parts[0]
                        asn_info['network'] = parts[1]
                        asn_info['country'] = parts[2]
                        asn_info['source'] = 'Team Cymru'
                    break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            # Fallback: Try WHOIS ASN lookup via REST API
            if not asn_info['asn']:
                try:
                    response = requests.get(f"https://whois.arin.net/rest/ip/{ip_address}.json", timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        if 'net' in data:
                            asn_info['organization'] = data['net'].get('orgName', 'N/A')
                            asn_info['network'] = data['net'].get('netName', 'N/A')
                except Exception:
                    pass
            
        except Exception as e:
            asn_info['error'] = str(e)
        
        return asn_info