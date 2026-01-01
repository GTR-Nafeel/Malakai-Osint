import json
from datetime import datetime

class OutputFormatter:
    def display_results(self, results):
        """Display results in a formatted way"""
        print("\n" + "="*60)
        print("MALAKAI-OSINT RESULTS")
        print("="*60)
        
        target = results.get('target', 'Unknown')
        timestamp = results.get('timestamp', 'Unknown')
        
        print(f"Target: {target}")
        print(f"Scan Time: {timestamp}")
        print("="*60)
        
        analysis = results.get('analysis', {})
        
        # Domain and IP
        if 'domain_ip' in analysis:
            self._display_domain_ip(analysis['domain_ip'])
        
        # Subdomains
        if 'subdomains' in analysis:
            self._display_subdomains(analysis['subdomains'])
        
        # DNS Records
        if 'dns_records' in analysis:
            self._display_dns_records(analysis['dns_records'])
        
        # WHOIS
        if 'whois' in analysis:
            self._display_whois(analysis['whois'])
        
        # Geolocation
        if 'geolocation' in analysis:
            self._display_geolocation(analysis['geolocation'])
        
        # AI Analysis
        if 'ai_analysis' in results:
            self._display_ai_analysis(results['ai_analysis'])

        # SSL Analysis
        if 'ssl_analysis' in analysis:
            self._display_ssl_analysis(analysis['ssl_analysis'])
        
        # Email Enumeration
        if 'emails' in analysis:
            self._display_emails(analysis['emails'])
        
        # Threat Intelligence
        if 'threat_intelligence' in analysis:
            self._display_threat_intelligence(analysis['threat_intelligence'])
        
        # Network Scan
        if 'network_scan' in analysis:
            self._display_network_scan(analysis['network_scan'])

    def _display_domain_ip(self, data):
        print("\nDOMAIN & IP ANALYSIS")
        print("-" * 40)
        print(f"Domain: {data.get('domain', 'N/A')}")
        print(f"IP Address: {data.get('ip_address', 'N/A')}")
        if data.get('ipv6_address'):
            print(f"IPv6 Address: {data.get('ipv6_address')}")
        print(f"HTTP Status: {data.get('http_status', 'N/A')}")
        print(f"Server: {data.get('server_info', 'N/A')}")
        if data.get('technologies'):
            print(f"Technologies: {', '.join(data.get('technologies', []))}")
        
        # Reverse DNS
        rev_dns = data.get('reverse_dns')
        if rev_dns and rev_dns.get('success'):
            hostnames = rev_dns.get('hostnames', [])
            if hostnames:
                print(f"Reverse DNS: {', '.join(hostnames)}")
        
        # CDN/WAF Detection
        cdn_waf = data.get('cdn_waf')
        if cdn_waf and cdn_waf.get('providers'):
            print(f"CDN/WAF: {', '.join(cdn_waf['providers'])}")
            if cdn_waf.get('reasons'):
                for reason in cdn_waf['reasons'][:2]:
                    print(f"  └─ {reason}")
        
        # Security Headers
        sec_headers = data.get('security_headers', {})
        if sec_headers:
            score = sec_headers.get('security_score', 0)
            critical_found = sec_headers.get('critical_headers_found', 0)
            critical_total = sec_headers.get('critical_headers_total', 0)
            
            # Color coding for score
            if score >= 80:
                score_indicator = "🟢"
            elif score >= 60:
                score_indicator = "🟡"
            else:
                score_indicator = "🔴"
            
            print(f"\nSecurity Headers: {score_indicator} {score}/100")
            print(f"  Critical Headers: {critical_found}/{critical_total}")
            
            headers_found = sec_headers.get('headers_found', {})
            if headers_found:
                print(f"  Found ({len(headers_found)}):")
                for header, value in list(headers_found.items())[:3]:
                    print(f"    ✅ {header}")
            
            headers_missing = sec_headers.get('headers_missing', [])
            if headers_missing:
                print(f"  Missing ({len(headers_missing)}):")
                for header in headers_missing[:3]:
                    is_critical = header in ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']
                    indicator = "❌" if is_critical else "⚠️"
                    print(f"    {indicator} {header}")
    
    def _display_subdomains(self, data):
        subdomains = data.get('subdomains', [])
        print(f"\nSUBDOMAINS FOUND ({len(subdomains)})")
        print("-" * 40)
        
        if not subdomains:
            print("  No valid subdomains found")
            return
            
        for subdomain in subdomains:
            print(f"  {subdomain}")
    
    def _display_dns_records(self, data):
        print("\nDNS RECORDS")
        print("-" * 40)
        for record_type, records in data.get('records', {}).items():
            print(f"{record_type}:")
            for record in records:
                print(f"  {record}")
        
        # DMARC Record
        dmarc = data.get('dmarc')
        if dmarc:
            print(f"\nDMARC:")
            if dmarc.get('exists'):
                print(f"  ✅ Record found: {dmarc.get('record', 'N/A')}")
            else:
                print(f"  ❌ {dmarc.get('reason', 'No DMARC record')}")
        
        # DKIM Records
        dkim = data.get('dkim')
        if dkim:
            print(f"\nDKIM:")
            if dkim.get('selectors_found'):
                print(f"  ✅ Found {dkim['count']} selector(s): {', '.join(dkim['selectors_found'])}")
            else:
                print(f"  ℹ️  No common DKIM selectors found")
        
        # DNSSEC Status
        dnssec = data.get('dnssec')
        if dnssec:
            print(f"\nDNSSEC:")
            if dnssec.get('dnssec_enabled'):
                status = dnssec.get('validation_status', 'unknown')
                if status == 'properly_configured':
                    print(f"  ✅ Properly configured")
                elif status == 'missing_ds_records':
                    print(f"  ⚠️  Enabled but missing DS records")
                elif status == 'missing_dnskey_records':
                    print(f"  ⚠️  Enabled but missing DNSKEY records")
            else:
                print(f"  ❌ Not configured")
            
            if dnssec.get('records', {}).get('ds_records'):
                print(f"  DS Records: {len(dnssec['records']['ds_records'])}")
            if dnssec.get('records', {}).get('dnskey_records'):
                print(f"  DNSKEY Records: {len(dnssec['records']['dnskey_records'])}")
    
    def _display_whois(self, data):
        print("\n📋 WHOIS INFORMATION")
        print("-" * 40)
        parsed = data.get('parsed_data', {})
        source = data.get('source', 'primary')
        
        if source == 'fallback':
            print("  (Using fallback data)")
        elif source == 'basic':
            print("  (Basic info - WHOIS lookup failed)")
            
        print(f"Registrar: {parsed.get('registrar', 'N/A')}")
        print(f"Creation Date: {parsed.get('creation_date', 'N/A')}")
        print(f"Expiration Date: {parsed.get('expiration_date', 'N/A')}")
        
        name_servers = parsed.get('name_servers', ['N/A'])
        if isinstance(name_servers, list):
            print(f"Name Servers: {', '.join(name_servers)}")
        else:
            print(f"Name Servers: {name_servers}")   
    
    def _display_geolocation(self, data):
        print("\nGEOLOCATION")
        print("-" * 40)
        geo = data.get('geolocation', {})
        print(f"Country: {geo.get('country', 'N/A')}")
        print(f"City: {geo.get('city', 'N/A')}")
        print(f"ISP: {geo.get('org', 'N/A')}")
        print(f"Coordinates: {geo.get('latitude', 'N/A')}, {geo.get('longitude', 'N/A')}")
        
        # ASN Information
        asn_info = data.get('asn_info', {})
        if asn_info and asn_info.get('asn'):
            print(f"\nASN INFORMATION")
            print(f"  ASN: {asn_info.get('asn', 'N/A')}")
            print(f"  Network: {asn_info.get('network', 'N/A')}")
            print(f"  Organization: {asn_info.get('organization', 'N/A')}")
            print(f"  Country: {asn_info.get('country', 'N/A')}")
            print(f"  Source: {asn_info.get('source', 'N/A')}")
    
    def _display_ai_analysis(self, data):
        print("\nAI-POWERED ANALYSIS")
        print("-" * 40)
        
        risks = data.get('risk_assessment', {})
        print(f"Risk Level: {risks.get('risk_level', 'N/A')} ({risks.get('risk_score', 0)}/100)")
        
        if data.get('anomaly_detection'):
            print("\nAnomalies Detected:")
            for anomaly in data['anomaly_detection']:
                print(f"  - {anomaly}")
        
        if data.get('recommendations'):
            print("\nRecommendations:")
            for rec in data['recommendations']:
                print(f"  - {rec}")
    
    def save_results(self, results, filename):
        """Save results to file in JSON format"""
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        except Exception as e:
            print(f"[-] Error saving results: {e}")
 
    def _display_ssl_analysis(self, data):
        """Display SSL analysis results"""
        print("\n🔐 SSL/TLS CERTIFICATE ANALYSIS")
        print("-" * 40)
        
        if 'error' in data:
            print(f"  Error: {data['error']}")
            return
        
        cert_info = data.get('certificate_info', {})
        if cert_info:
            # Basic info
            print(f"Domain: {data.get('domain', 'N/A')}")
            print(f"Port: {data.get('port', 'N/A')}")
            
            # Issuer
            issuer = cert_info.get('issuer', {})
            print(f"Issuer: {issuer.get('common_name', 'N/A')}")
            issuer_org = issuer.get('organization') if isinstance(issuer, dict) else None
            if issuer_org:
                print(f"Issuer Organization: {issuer_org}")

            # Subject organization and location
            subject = cert_info.get('subject', {})
            subj_org = subject.get('organization') if isinstance(subject, dict) else None
            if subj_org:
                print(f"Organization: {subj_org}")
            subj_loc = []
            if isinstance(subject, dict):
                if subject.get('locality'):
                    subj_loc.append(subject.get('locality'))
                if subject.get('country'):
                    subj_loc.append(subject.get('country'))
            if subj_loc:
                print(f"Location: {', '.join(subj_loc)}")

            # Expiry
            validity = cert_info.get('validity', {})
            days_remaining = validity.get('days_remaining', 0)
            expiry_status = "✅" if days_remaining > 30 else "⚠️" if days_remaining > 0 else "❌"
            print(f"Expires: {validity.get('not_valid_after', 'N/A')} ({expiry_status} {days_remaining} days)")

            # Serial number and signature algorithm
            serial = cert_info.get('serial_number')
            if isinstance(serial, dict):
                dec = serial.get('decimal')
                hx = serial.get('hex')
                if dec:
                    if hx:
                        print(f"Serial Number: {dec} (hex: {hx})")
                    else:
                        print(f"Serial Number: {dec}")
            elif serial:
                print(f"Serial Number: {serial}")
            sigalg = cert_info.get('signature_algorithm')
            if sigalg:
                print(f"Signature Algorithm: {sigalg}")

            # SANs summary (try multiple sources if necessary)
            sans = data.get('subject_alternative_names')
            if not sans:
                # fallback to certificate_info top-level or extensions
                sans = cert_info.get('subject_alternative_names') or cert_info.get('extensions', {}).get('subject_alternative_names', [])
            if sans is None:
                sans = []
            print(f"SANs: {len(sans)} entries")
            if sans:
                for san in sans:
                    if isinstance(san, dict):
                        print(f"  - {san.get('type', '')}: {san.get('value', '')}")
                    else:
                        print(f"  - {san}")
            
            # Wildcards
            wildcards = data.get('wildcard_certificates', [])
            if wildcards:
                print(f"Wildcards: {len(wildcards)} found")
                for wc in wildcards[:2]:
                    print(f"  {wc.get('pattern', 'N/A')}")
            
            # CT Logs
            ct_logs = data.get('certificate_transparency', [])
            if ct_logs:
                print(f"CT Logs: {len(ct_logs)} certificates")
            
            # Related domains
            related = data.get('related_domains', [])
            if related:
                print(f"Related Domains: {len(related)} found")
                for rel in related[:3]:
                    print(f"  {rel.get('domain', 'N/A')}")
            
            # Validation
            validation = data.get('validation', {})
            if validation:
                print(f"Valid: {validation.get('is_valid', 'N/A')}")
                warnings = validation.get('warnings', [])
                if warnings:
                    print(f"Warnings: {len(warnings)}")
            
            # Security analysis
            security = data.get('analysis', {})
            if security:
                risk_level = security.get('risk_level', 'N/A')
                risk_score = security.get('risk_score', 0)
                color = "🟢" if risk_level == 'low' else "🟡" if risk_level == 'medium' else "🔴"
                print(f"Security Risk: {color} {risk_level} ({risk_score}/100)")
    
    def _display_emails(self, data):
        print("\n📧 EMAIL ENUMERATION & BREACH STATUS")
        print("-" * 40)
        
        total_emails = data.get('total_emails', 0)
        breached_emails = data.get('breached_emails', 0)
        emails = data.get('emails', [])
        
        if total_emails == 0:
            print("  No emails found")
            return
        
        print(f"Total Emails Found: {total_emails}")
        if breached_emails > 0:
            print(f"⚠️  Breached Emails: {breached_emails}/{total_emails}")
        else:
            print(f"✅ No breaches detected")
        
        if emails:
            print(f"\nEmails:")
            for email_info in emails:
                email = email_info.get('email', 'Unknown')
                if email_info.get('breached'):
                    print(f"  🔴 {email}")
                    breaches = email_info.get('breaches', [])
                    if breaches:
                        for breach in breaches[:2]:
                            print(f"     └─ {breach.get('name', 'Unknown')} ({breach.get('date', 'N/A')})")
                else:
                    print(f"  ✅ {email}")
        
        # Breach summary
        breach_summary = data.get('breach_summary', {})
        if breach_summary:
            print(f"\nBreach Summary:")
            for breach_name, count in sorted(breach_summary.items(), key=lambda x: x[1], reverse=True)[:3]:
                print(f"  {breach_name}: {count} email(s)")
    
    def _display_threat_intelligence(self, data):
        print("\n🔍 THREAT INTELLIGENCE ANALYSIS (Shodan + VirusTotal)")
        print("-" * 40)
        
        if data.get('error'):
            print(f"  Error: {data['error']}")
            return
        
        # Overall threat score
        threat_score = data.get('threat_score', 0)
        status = data.get('overall_status', 'unknown')
        
        if status == 'malicious':
            status_icon = "🔴"
        elif status == 'suspicious':
            status_icon = "🟠"
        elif status == 'warning':
            status_icon = "🟡"
        else:
            status_icon = "🟢"
        
        print(f"Threat Score: {status_icon} {threat_score}/100 ({status.upper()})")
        
        # VirusTotal Domain Analysis
        vt_domain = data.get('virustotal_domain', {})
        if vt_domain and not vt_domain.get('error'):
            print(f"\nVirusTotal - Domain Analysis:")
            print(f"  Detection Ratio: {vt_domain.get('detection_ratio', '0/0')}")
            if vt_domain.get('malicious_votes', 0) > 0:
                print(f"  🔴 Malicious Engines: {vt_domain['malicious_votes']}")
            if vt_domain.get('suspicious_votes', 0) > 0:
                print(f"  🟠 Suspicious Engines: {vt_domain['suspicious_votes']}")
            
            categories = vt_domain.get('categories', [])
            if categories:
                print(f"  Categories: {', '.join(categories[:3])}")
            
            last_analysis = vt_domain.get('last_analysis_date')
            if last_analysis:
                print(f"  Last Analysis: {last_analysis}")
        
        # VirusTotal IP Analysis
        vt_ip = data.get('virustotal_ip', {})
        if vt_ip and not vt_ip.get('error'):
            print(f"\nVirusTotal - IP Analysis:")
            print(f"  Detection Ratio: {vt_ip.get('detection_ratio', '0/0')}")
            if vt_ip.get('malicious_votes', 0) > 0:
                print(f"  🔴 Malicious Engines: {vt_ip['malicious_votes']}")
            if vt_ip.get('suspicious_votes', 0) > 0:
                print(f"  🟠 Suspicious Engines: {vt_ip['suspicious_votes']}")
            
            asn = vt_ip.get('asn')
            country = vt_ip.get('country')
            if asn or country:
                print(f"  ASN: {asn}, Country: {country}")
        
        # Shodan Analysis
        shodan = data.get('shodan', {})
        if shodan and not shodan.get('error'):
            print(f"\nShodan - Internet Exposure Analysis:")
            
            if shodan.get('found'):
                associated_ips = shodan.get('associated_ips', [])
                if associated_ips:
                    for ip_info in associated_ips[:1]:  # Show first IP
                        ip = ip_info.get('ip')
                        host_info = ip_info.get('host_info', {})
                        
                        if host_info.get('found'):
                            print(f"  IP: {ip}")
                            ports = host_info.get('ports', [])
                            if ports:
                                print(f"  Open Ports: {', '.join(map(str, ports[:10]))}")
                            
                            services = host_info.get('services', [])
                            if services:
                                print(f"  Services Detected: {len(services)}")
                                for svc in services[:3]:
                                    print(f"    - Port {svc.get('port')}: {svc.get('banner', 'Unknown')}")
                            
                            vulns = host_info.get('vulnerabilities', [])
                            if vulns:
                                print(f"  🔴 Vulnerabilities (CVE): {', '.join(vulns[:3])}")
            else:
                print(f"  {shodan.get('error', 'No Shodan data available')}")
    
    def _display_network_scan(self, data):
        """Display comprehensive network scan results."""
        print("\n🌐 NETWORK RECONNAISSANCE REPORT")
        print("-" * 60)
        
        if data.get('error'):
            print(f"  Error: {data['error']}")
            return
        
        # Report title and metadata
        print(f"Report: {data.get('report_title', 'N/A')}")
        print(f"Scan Time: {data.get('scan_datetime', 'N/A')}")
        
        # Overview
        print(f"\nOVERVIEW")
        overview = data.get('overview', {})
        print(f"  Active Scan (Nmap): {'✅' if overview.get('active_scan_success') else '❌'}")
        print(f"  Passive Scan (Shodan): {'✅' if overview.get('passive_scan_success') else '❌'}")
        print(f"  Total Ports Discovered: {overview.get('total_ports_discovered', 0)}")
        print(f"  Services Identified: {overview.get('services_identified', 0)}")
        print(f"  Ports in Both Scans: {overview.get('ports_visible_in_both_scans', 0)}")
        
        # Ports and Services Summary
        print(f"\nPORTS & SERVICES SUMMARY")
        port_summary = data.get('ports_and_services', {}).get('summary', {})
        print(f"  Nmap Discovered: {port_summary.get('nmap_discovered', 0)}")
        print(f"  Shodan Indexed: {port_summary.get('shodan_indexed', 0)}")
        print(f"  Overlap: {port_summary.get('overlap', 0)}")
        print(f"  Internal Only (Nmap): {port_summary.get('internal_only', 0)}")
        print(f"  Recently Exposed (Shodan): {port_summary.get('recently_exposed', 0)}")
        
        # All Ports and Services
        ports_list = data.get('ports_and_services', {}).get('all_ports', [])
        if ports_list:
            print(f"\nPORTS & SERVICES ({len(ports_list)} total)")
            for port_entry in ports_list[:15]:  # Show top 15
                port = port_entry.get('port')
                nmap_svc = port_entry.get('nmap')
                shodan_svc = port_entry.get('shodan')
                both = '✅' if port_entry.get('both_scans') else '⚠️'
                
                print(f"  {both} Port {port}:")
                if nmap_svc:
                    print(f"      Nmap: {nmap_svc.get('product', 'N/A')} {nmap_svc.get('version', '')}")
                if shodan_svc:
                    print(f"      Shodan: {shodan_svc.get('banner', 'N/A')[:50]}")
        
        # Infrastructure Insights
        insights = data.get('infrastructure_insights', {})
        if insights.get('likely_internal'):
            print(f"\n🔒 LIKELY INTERNAL PORTS (Nmap only)")
            internal = insights['likely_internal']
            print(f"  Ports: {', '.join(map(str, internal.get('ports', [])[:10]))}")
            print(f"  Reason: {internal.get('reason', 'N/A')}")
        
        if insights.get('recently_exposed'):
            print(f"\n📡 RECENTLY EXPOSED PORTS (Shodan only)")
            exposed = insights['recently_exposed']
            print(f"  Ports: {', '.join(map(str, exposed.get('ports', [])[:10]))}")
            print(f"  Reason: {exposed.get('reason', 'N/A')}")
        
        # Risk Summary
        print(f"\nRISK ASSESSMENT")
        risk = data.get('risk_summary', {})
        exposure_score = risk.get('exposure_score', 0)
        risk_level = risk.get('risk_level', 'UNKNOWN')
        print(f"  Exposure Score: {exposure_score}/100 {risk_level}")
        
        unexpected = risk.get('unexpected_ports', [])
        if unexpected:
            print(f"  🚨 Unexpected Ports Open: {', '.join(map(str, unexpected))}")
        
        outdated = risk.get('outdated_services', [])
        if outdated:
            print(f"  📦 Outdated Services: {len(outdated)}")
            for svc in outdated[:3]:
                print(f"      - Port {svc.get('port')}: {svc.get('service')} {svc.get('version')}")
        
        # Recommendations
        recommendations = data.get('recommendations', [])
        if recommendations:
            print(f"\nRECOMMENDATIONS")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec}")




