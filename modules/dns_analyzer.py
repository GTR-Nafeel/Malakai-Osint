import dns.resolver
import dns.reversename
import socket
from collections import defaultdict

class DNSAnalyzer:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR']

    def get_complete_dns_info(self, domain):
        """Get comprehensive DNS information"""
        results = {
            'domain': domain,
            'records': defaultdict(list),
            'dns_servers': [],
            'zone_transfer': None
        }
        
        try:
            # Get nameservers
            results['dns_servers'] = self._get_nameservers(domain)
            
            # Get all record types
            for record_type in self.record_types:
                try:
                    records = self._get_dns_records(domain, record_type)
                    if records:
                        results['records'][record_type] = records
                except:
                    pass
            
            # Try zone transfer
            results['zone_transfer'] = self._attempt_zone_transfer(domain, results['dns_servers'])
            
            # Extract DMARC and DKIM records
            results['dmarc'] = self._get_dmarc_record(domain)
            results['dkim'] = self._get_dkim_records(domain)
            
            # Check DNSSEC status
            results['dnssec'] = self._check_dnssec(domain)
            
        except Exception as e:
            results['error'] = str(e)
            
        return results

    def _get_nameservers(self, domain):
        """Get authoritative nameservers"""
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            return [str(ns.target) for ns in answers]
        except:
            return []

    def _get_dns_records(self, domain, record_type):
        """Get specific DNS record type"""
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records = []
            
            for answer in answers:
                if record_type == 'MX':
                    records.append({
                        'preference': answer.preference,
                        'exchange': str(answer.exchange)
                    })
                elif record_type == 'SOA':
                    records.append({
                        'mname': str(answer.mname),
                        'rname': str(answer.rname),
                        'serial': answer.serial,
                        'refresh': answer.refresh,
                        'retry': answer.retry,
                        'expire': answer.expire,
                        'minimum': answer.minimum
                    })
                else:
                    records.append(str(answer))
            
            return records
        except:
            return []

    def _attempt_zone_transfer(self, domain, nameservers):
        """Attempt DNS zone transfer"""
        zone_transfer_results = {}
        
        for ns in nameservers[:3]:  # Try first 3 nameservers
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [socket.gethostbyname(ns)]
                
                try:
                    answers = resolver.resolve(domain, 'AXFR')
                    zone_transfer_results[ns] = [str(record) for record in answers]
                except:
                    zone_transfer_results[ns] = "Zone transfer failed"
                    
            except Exception as e:
                zone_transfer_results[ns] = f"Error: {str(e)}"
        
        return zone_transfer_results

    def _get_dmarc_record(self, domain):
        """Extract DMARC record for domain with policy analysis"""
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT', raise_on_no_answer=False)
            
            for answer in answers:
                record = str(answer).strip('"')
                if record.startswith('v=DMARC1'):
                    policy_info = self._parse_dmarc_policy(record)
                    return {
                        'record': record,
                        'exists': True,
                        'policy': policy_info.get('p', 'none'),
                        'subdomain_policy': policy_info.get('sp', 'none'),
                        'alignment_dkim': policy_info.get('adkim', 'r'),
                        'alignment_spf': policy_info.get('aspf', 'r'),
                        'reporting_uri': policy_info.get('rua', 'N/A'),
                        'forensics_uri': policy_info.get('ruf', 'N/A'),
                        'percentage': policy_info.get('pct', '100')
                    }
            return {'exists': False, 'reason': 'No DMARC policy found'}
        except dns.resolver.NXDOMAIN:
            return {'exists': False, 'reason': 'No DMARC record'}
        except dns.resolver.NoAnswer:
            return {'exists': False, 'reason': 'No TXT records'}
        except Exception as e:
            return {'exists': False, 'reason': f'Error: {str(e)}'}
    
    def _parse_dmarc_policy(self, record):
        """Parse DMARC policy tags"""
        policy = {}
        tags = record.split(';')
        for tag in tags:
            tag = tag.strip()
            if '=' in tag:
                key, value = tag.split('=', 1)
                policy[key.strip()] = value.strip()
        return policy

    def _get_dkim_records(self, domain):
        """Extract DKIM records with detailed analysis and extended selectors"""
        common_selectors = [
            'default', 'selector1', 'selector2', 'selector3',
            'google', 'k1', 'k2', 'mail', 'dkim', 'dkim1', 'dkim2',
            'smtp', 'amazon', 'sendgrid', 'mandrill', 'mailgun',
            'postmark', 'sparkpost', 'office365', 'o365'
        ]
        dkim_records = {}
        
        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                answers = dns.resolver.resolve(dkim_domain, 'TXT', raise_on_no_answer=False)
                for answer in answers:
                    record = str(answer).strip('"')
                    if record.startswith('v=DKIM1'):
                        key_info = self._parse_dkim_record(record)
                        dkim_records[selector] = {
                            'found': True,
                            'key_version': key_info.get('v', '1'),
                            'algorithm': key_info.get('a', 'rsa-sha256'),
                            'key_type': key_info.get('k', 'rsa'),
                            'record_length': len(record)
                        }
                        break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception:
                continue
        
        return {
            'selectors_found': list(dkim_records.keys()),
            'records': dkim_records,
            'count': len(dkim_records),
            'selectors_checked': len(common_selectors)
        }
    
    def _parse_dkim_record(self, record):
        """Parse DKIM record tags"""
        key_info = {}
        tags = record.split(';')
        for tag in tags:
            tag = tag.strip()
            if '=' in tag:
                key, value = tag.split('=', 1)
                key_info[key.strip()] = value.strip()[:50]
        return key_info
    
    def _check_dnssec(self, domain):
        """
        Comprehensive DNSSEC validation: DS records, DNSKEY records, 
        algorithm strength, key size analysis.
        
        Returns:
            dict with dnssec_enabled, validation_status, algorithm_strength
        """
        dnssec_info = {
            'dnssec_enabled': False,
            'has_ds_records': False,
            'has_dnskey_records': False,
            'validation_status': 'not_configured',
            'algorithm_strength': 'unknown',
            'records': {
                'ds_records': [],
                'dnskey_records': [],
                'algorithms': []
            },
            'error': None
        }
        
        try:
            # Check for DS records (Delegation Signer)
            try:
                ds_answers = dns.resolver.resolve(domain, 'DS', raise_on_no_answer=False)
                if ds_answers:
                    for ds_record in ds_answers:
                        algo_name = self._get_dnssec_algorithm_name(ds_record.algorithm)
                        dnssec_info['records']['ds_records'].append({
                            'keytag': ds_record.key_tag,
                            'algorithm': ds_record.algorithm,
                            'algorithm_name': algo_name,
                            'digest_type': ds_record.digest_type,
                            'digest_type_name': self._get_dnssec_digest_name(ds_record.digest_type),
                            'digest': str(ds_record.digest)[:64] + '...' if len(str(ds_record.digest)) > 64 else str(ds_record.digest)
                        })
                    dnssec_info['has_ds_records'] = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            
            # Check for DNSKEY records
            try:
                dnskey_answers = dns.resolver.resolve(domain, 'DNSKEY', raise_on_no_answer=False)
                if dnskey_answers:
                    for dnskey_record in dnskey_answers:
                        algo_name = self._get_dnssec_algorithm_name(dnskey_record.algorithm)
                        key_size = len(str(dnskey_record.key)) * 4
                        dnssec_info['records']['dnskey_records'].append({
                            'flags': dnskey_record.flags,
                            'key_type': 'KSK' if dnskey_record.flags == 257 else 'ZSK',
                            'protocol': dnskey_record.protocol,
                            'algorithm': dnskey_record.algorithm,
                            'algorithm_name': algo_name,
                            'estimated_key_size': key_size,
                            'key': str(dnskey_record.key)[:50] + '...'
                        })
                        if algo_name not in dnssec_info['records']['algorithms']:
                            dnssec_info['records']['algorithms'].append(algo_name)
                    dnssec_info['has_dnskey_records'] = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            
            # Determine DNSSEC status and algorithm strength
            if dnssec_info['has_ds_records'] and dnssec_info['has_dnskey_records']:
                dnssec_info['dnssec_enabled'] = True
                dnssec_info['validation_status'] = 'properly_configured'
                dnssec_info['algorithm_strength'] = self._assess_dnssec_strength(dnssec_info['records']['algorithms'])
            elif dnssec_info['has_dnskey_records']:
                dnssec_info['dnssec_enabled'] = True
                dnssec_info['validation_status'] = 'missing_ds_records'
                dnssec_info['algorithm_strength'] = self._assess_dnssec_strength(dnssec_info['records']['algorithms'])
            elif dnssec_info['has_ds_records']:
                dnssec_info['dnssec_enabled'] = True
                dnssec_info['validation_status'] = 'incomplete_chain'
            
        except Exception as e:
            dnssec_info['error'] = str(e)
        
        return dnssec_info
    
    def _get_dnssec_algorithm_name(self, algo_num):
        """Map DNSSEC algorithm number to name"""
        algos = {
            1: 'RSAMD5', 3: 'DSA', 5: 'RSASHA1', 6: 'DSANSEC3SHA1',
            7: 'RSASHA1NSEC3', 8: 'RSASHA256', 10: 'RSASHA512',
            12: 'ECCGOST', 13: 'ECDSAP256SHA256', 14: 'ECDSAP384SHA384',
            15: 'ED25519', 16: 'ED448'
        }
        return algos.get(algo_num, f'Unknown({algo_num})')
    
    def _get_dnssec_digest_name(self, digest_num):
        """Map DNSSEC digest type to name"""
        digests = {1: 'SHA-1', 2: 'SHA-256', 3: 'GOST', 4: 'SHA-384'}
        return digests.get(digest_num, f'Unknown({digest_num})')
    
    def _assess_dnssec_strength(self, algorithms):
        """Assess DNSSEC algorithm strength"""
        strong_algos = {'RSASHA256', 'RSASHA512', 'ECDSAP256SHA256', 'ECDSAP384SHA384', 'ED25519', 'ED448'}
        weak_algos = {'RSAMD5', 'RSASHA1'}
        
        if not algorithms:
            return 'unknown'
        
        if any(algo in strong_algos for algo in algorithms):
            return 'strong'
        elif any(algo in weak_algos for algo in algorithms):
            return 'weak'
        else:
            return 'moderate'