# malakai.py
#!/usr/bin/env python3
"""
Malakai-Osint - Advanced OSINT Tool with AI/ML Capabilities
Author: Your Name
Version: 1.0
"""

import argparse
from html import parser
import json
import sys
from datetime import datetime
import socket
from modules.domain_analyzer import DomainAnalyzer
from modules.subdomain_discovery import SubdomainDiscoverer
from modules.dns_analyzer import DNSAnalyzer
from modules.whois_lookup import WhoisLookup
from modules.ip_geolocation import IPGeolocation
from modules.ssl_analyzer import SSLAnalyzer
from modules.email_enum import EmailEnumerator
from modules.threat_intelligence import ThreatIntelligence
from modules.network_scanner import NetworkScanner
from utils.output_formatter import OutputFormatter
from utils.ai_helper import AIAnalyzer

import subprocess
import re
import shlex
import os

# Optional OpenAI integration (graceful if not installed or not configured)
try:
    import openai
    from config import OPENAI_API_KEY, OPENAI_MODEL, OPENAI_TEMPERATURE
    OPENAI_AVAILABLE = True
except Exception:
    OPENAI_AVAILABLE = False

# Terminal colors (use colorama for cross-platform ANSI support)
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    CMD_COLOR = Fore.YELLOW
    AI_COLOR = Fore.CYAN
    OUT_COLOR = Fore.GREEN
    ERR_COLOR = Fore.RED
    PROMPT_COLOR = Fore.MAGENTA
    HEADING_COLOR = Fore.BLUE
except Exception:
    # colorama not available -> fall back to no-op values
    CMD_COLOR = AI_COLOR = OUT_COLOR = ERR_COLOR = PROMPT_COLOR = HEADING_COLOR = ''
    Style = type('S', (), {'RESET_ALL': ''})

class MalakaiOSINT:
    def __init__(self):
        self.banner = """
███╗   ███╗ █████╗ ██╗      █████╗ ██╗  ██╗ █████╗ ██╗
████╗ ████║██╔══██╗██║     ██╔══██╗██║ ██╔╝██╔══██╗██║
██╔████╔██║███████║██║     ███████║█████╔╝ ███████║██║
██║╚██╔╝██║██╔══██║██║     ██╔══██║██╔═██╗ ██╔══██║██║
██║ ╚═╝ ██║██║  ██║███████╗██║  ██║██║  ██╗██║  ██║██║
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝

            AI Cybersecurity Framework v1.0
               Crafted by: Nafeel Masood
        """
        # Print banner safely. On some Windows consoles printing wide unicode
        # characters can raise a UnicodeEncodeError inside colorama/wrappers.
        # Try a normal print first; if that fails, write UTF-8 bytes to the
        # underlying buffer with replacement for unencodable characters.
        try:
            print(self.banner)
        except Exception:
            try:
                # Prefer writing to the buffer using the console's encoding
                enc = getattr(sys.stdout, 'encoding', None) or 'utf-8'
                sys.stdout.buffer.write(self.banner.encode(enc, errors='replace'))
                sys.stdout.buffer.write(b"\n")
            except Exception:
                try:
                    # Last-resort: force-encode as utf-8 and decode with replacements
                    print(self.banner.encode('utf-8', errors='replace').decode('utf-8', errors='replace'))
                except Exception:
                    # If everything else fails, silently continue without banner
                    pass

        self.domain_analyzer = DomainAnalyzer()
        self.subdomain_discoverer = SubdomainDiscoverer()
        self.dns_analyzer = DNSAnalyzer()
        self.whois_lookup = WhoisLookup()
        self.ip_geolocation = IPGeolocation()
        self.ssl_analyzer = SSLAnalyzer()
        self.email_enumerator = EmailEnumerator()
        self.threat_intelligence = ThreatIntelligence()
        self.network_scanner = NetworkScanner()
        self.output_formatter = OutputFormatter()
        self.ai_analyzer = AIAnalyzer()

    def run_complete_analysis(self, target, output_file=None, use_ai=False, ssl_analysis=False):
        """Run complete OSINT analysis on target"""
        print(f"[*] Starting comprehensive analysis for: {target}")
        print("[*] This may take a few minutes...\n")
        
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'analysis': {}
        }

        try:
            # 1. Domain and IP Analysis
            print("[1/6] Performing Domain and IP Analysis...")
            results['analysis']['domain_ip'] = self.domain_analyzer.analyze_domain(target)
            
            # 2. Subdomain Discovery
            print("[2/6] Discovering Subdomains...")
            results['analysis']['subdomains'] = self.subdomain_discoverer.discover_subdomains(target)
            
            # 3. DNS Information
            print("[3/6] Gathering DNS Records...")
            results['analysis']['dns_records'] = self.dns_analyzer.get_complete_dns_info(target)
            
            # 4. WHOIS Lookup
            print("[4/6] Performing WHOIS Lookup...")
            results['analysis']['whois'] = self.whois_lookup.get_whois_info(target)
            
            # 5. IP Geolocation
            print("[5/6] IP Geolocation Analysis...")
            if 'ip_address' in results['analysis']['domain_ip']:
                ip = results['analysis']['domain_ip']['ip_address']
                results['analysis']['geolocation'] = self.ip_geolocation.locate_ip(ip)
            
            # 6. Email Enumeration and Breach Checking
            print("[6/6] 📧 Email Enumeration and Breach Check...")
            try:
                email_results = self.email_enumerator.enumerate_domain_emails(target)
                results['analysis']['emails'] = email_results
            except Exception as e:
                print(f"[-] Email enumeration failed: {e}")
                results['analysis']['emails'] = {'error': str(e)}
            
            # 7. Threat Intelligence (Shodan + VirusTotal)
            print("[7/7] 🔍 Querying Threat Intelligence (Shodan + VirusTotal)...")
            try:
                ip = results['analysis']['domain_ip'].get('ip_address')
                threat_results = self.threat_intelligence.bulk_threat_check(target, ip)
                results['analysis']['threat_intelligence'] = threat_results
            except Exception as e:
                print(f"[-] Threat intelligence check failed: {e}")
                results['analysis']['threat_intelligence'] = {'error': str(e)}
            
            # AI Analysis if requested
            if use_ai:
                print("\n[AI] Performing AI-Powered Analysis...")
                results['ai_analysis'] = self.ai_analyzer.analyze_results(results)

            # SSL/TLS Analysis if requested
            if ssl_analysis:
                try:
                    print("[8/8] 🔐 Performing SSL/TLS Certificate Analysis...")
                    ssl_results = self.ssl_analyzer.analyze_domain_certificate(target)
                    results['analysis']['ssl_analysis'] = ssl_results
                except Exception as e:
                    print(f"[-] SSL analysis failed: {e}")
                    results['analysis']['ssl_analysis'] = {'error': str(e)}

        except Exception as e:
            print(f"[-] Error during analysis: {e}")
            return None

        # Display results
        self.output_formatter.display_results(results)
        
        # Save to file if specified
        if output_file:
            self.output_formatter.save_results(results, output_file)
            print(f"\n[+] Results saved to: {output_file}")

        return results

    def run_specific_module(self, target, module_name, output_file=None):
        """Run a specific module by name and display/save results.

        Supported module_name values: 'domain', 'subdomains', 'dns', 'whois',
        'geo', 'emails', 'threat_intelligence', 'ssl'
        """
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'analysis': {}
        }

        try:
            if module_name == 'domain':
                results['analysis']['domain_ip'] = self.domain_analyzer.analyze_domain(target)

            elif module_name == 'subdomains':
                results['analysis']['subdomains'] = self.subdomain_discoverer.discover_subdomains(target)

            elif module_name == 'dns':
                results['analysis']['dns_records'] = self.dns_analyzer.get_complete_dns_info(target)

            elif module_name == 'whois':
                results['analysis']['whois'] = self.whois_lookup.get_whois_info(target)

            elif module_name == 'geo':
                try:
                    ip = socket.gethostbyname(target)
                except Exception:
                    ip = target
                results['analysis']['geolocation'] = self.ip_geolocation.locate_ip(ip)

            elif module_name == 'emails':
                results['analysis']['emails'] = self.email_enumerator.enumerate_domain_emails(target)

            elif module_name == 'threat_intelligence':
                try:
                    ip = socket.gethostbyname(target)
                except Exception:
                    ip = target
                results['analysis']['threat_intelligence'] = self.threat_intelligence.bulk_threat_check(target, ip)

            elif module_name == 'ssl':
                results['analysis']['ssl'] = self.ssl_analyzer.analyze_domain_certificate(target)

            else:
                results['analysis'][module_name] = {'error': 'Unknown module'}

        except Exception as e:
            results['analysis'][module_name] = {'error': str(e)}

        # Display and optionally save
        try:
            self.output_formatter.display_results(results)
        except Exception:
            pass

        if output_file:
            try:
                self.output_formatter.save_results(results, output_file)
                print(f"\n[+] Results saved to: {output_file}")
            except Exception:
                pass

        return results

    def run_network_scan(self, target, output_file=None, nmap_args="-sV --script vuln -A"):
        """
        Execute comprehensive network reconnaissance combining Nmap and Shodan.
        
        Args:
            target: IP address to scan
            output_file: Optional file to save results
            nmap_args: Arguments to pass to Nmap
        
        Returns:
            Formatted network scan report
        """
        print(f"[*] Running comprehensive network scan on: {target}\n")
        
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scan_type': 'network_reconnaissance',
            'result': None
        }
        
        try:
            # Run full network scan (Nmap + Shodan)
            results['result'] = self.network_scanner.run_full_network_scan(target, nmap_args)
            print("[+] Network Scan Complete")
            
        except Exception as e:
            print(f"[-] Network scan error: {e}")
            results['error'] = str(e)
            return None
        
        # Display formatted report
        self.output_formatter.display_results({'target': target, 'analysis': {'network_scan': results['result'].get('formatted_report')}})
        
        # Save to file if specified
        if output_file:
            self.output_formatter.save_results(results, output_file)
            print(f"\n[+] Results saved to: {output_file}")
        
        return results


def _start_ai_chat(malakai: MalakaiOSINT):
    """Start an interactive AI chatbot loop that can run shell commands on demand.

    Commands:
      - run <cmd>    : execute a shell command and show output
      - !<cmd>       : shortcut to run a shell command
      - nmap help    : print a few recommended nmap templates
      - history      : not implemented (placeholder)
      - exit / quit  : leave the chat
    """
    ai = malakai.ai_analyzer
    print(HEADING_COLOR + "\n=== Malakai AI Chat ===" + Style.RESET_ALL)
    print(AI_COLOR + "Type natural questions. To execute shell commands type 'run <cmd>' or prefix with '!'." + Style.RESET_ALL)
    print(PROMPT_COLOR + "Type 'nmap help' to show suggested nmap templates. Type 'exit' to quit.\n" + Style.RESET_ALL)

    # Conversation history and logging
    chat_history = []  # list of (role, content)
    log_path = os.path.join(os.path.dirname(__file__), 'ai_chat.log')

    def _write_log(line: str):
        try:
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(f"{datetime.now().isoformat()} {line}\n")
        except Exception:
            pass

    def _append_history(role: str, content: str):
        chat_history.append((role, content))
        _write_log(f"{role.upper()}: {content}")

    def _get_suggestions(topic: str):
        """Generate suggestions based on a topic."""
        # Try LLM-backed suggestions if available
        suggestions = []
        if OPENAI_AVAILABLE and (OPENAI_API_KEY or os.getenv('OPENAI_API_KEY')):
            try:
                openai.api_key = OPENAI_API_KEY or os.getenv('OPENAI_API_KEY')
                system_msg = (
                    "You are Malakai assistant. Provide 3 concise suggestion lines (one per line) for actions or commands the user can run given the topic. "
                    "Prefer safe, legal actions and include suggested command examples when relevant."
                )
                resp = openai.ChatCompletion.create(
                    model=OPENAI_MODEL,
                    messages=[
                        {"role": "system", "content": system_msg},
                        {"role": "user", "content": topic}
                    ],
                    temperature=0.2,
                    max_tokens=300,
                )
                text = resp.choices[0].message.get('content', '').strip()
                for line in text.splitlines():
                    line = line.strip()
                    if line:
                        suggestions.append(line)
                if suggestions:
                    return suggestions
            except Exception:
                pass

        # Heuristic fallback suggestions
        t = topic.lower()
        if 'port' in t:
            return [
                'Quick top-ports scan: nmap --top-ports 100 -sV -T4 <target>',
                'Full port scan: nmap -p- -sV -T4 <target> (slow/conspicuous)',
                'Passive Shodan lookup: python malakai.py <target> --network'
            ]
        if 'ssl' in t or 'certificate' in t:
            return [
                'SSL cipher enumeration: nmap --script ssl-enum-ciphers -p 443 <target>',
                'Check certificate details with SSL analyzer: python malakai.py <target> --ssl',
                'Quick TLS test: openssl s_client -connect <target>:443'
            ]
        # default generic suggestions
        return [
            'Passive reconnaissance: python malakai.py <target> --network',
            'Quick domain overview: python malakai.py <target>',
            'Run a top-ports nmap scan: nmap --top-ports 100 -sV -T4 <target>'
        ]

    def _interpret_nl_command(nl_text: str):
        q = nl_text.lower()
        # find a domain or IP-like token
        dom_match = re.search(r"([a-z0-9\-\.]+\.[a-z]{2,})", nl_text, re.IGNORECASE)
        ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", nl_text)
        target = None
        if ip_match:
            target = ip_match.group(0)
        elif dom_match:
            target = dom_match.group(0)

        # PORTS & NETWORK SCANNING
        if re.search(r'open ports|find open ports|show open ports|list open ports|scan for open ports|port scan', q):
            if re.search(r'all ports|every port|-p-|full port|complete', q):
                if target:
                    return (f"nmap -p- -sV -T4 {target}", f"Full port scan on {target}")
                return (None, "Missing target for full port scan")
            else:
                if target:
                    return (f"nmap --top-ports 100 -sV -T4 {target}", f"Top ports scan on {target}")
                return (None, "Missing target for top-ports scan")

        # VULNERABILITY SCANNING
        if re.search(r'vulnerab|vuln|weakness|exploit|cve', q):
            if target:
                return (f"nmap --script vuln -p 1-10000 {target}", f"Vulnerability scan on {target}")
            return (None, "Missing target for vulnerability scan")

        # SSL/TLS & CERTIFICATE ANALYSIS
        if re.search(r'ssl|tls|certificate|cert|cipher|https|443', q):
            if target:
                return (f"nmap --script ssl-enum-ciphers -p 443 {target}", f"SSL/TLS cipher analysis on {target}")
            return (None, "Missing target for SSL analysis")

        # WHOIS & DOMAIN REGISTRATION
        if re.search(r'whois|registr|owner|register|domain info', q):
            if target:
                return (f"python malakai.py {target} --module whois", f"WHOIS lookup for {target}")
            return (None, "Missing target for WHOIS lookup")

        # DNS & NAME RESOLUTION
        if re.search(r'dns|name server|nameserver|mx record|a record|resolve', q):
            if target:
                return (f"python malakai.py {target} --module dns", f"DNS resolution and records for {target}")
            return (None, "Missing target for DNS lookup")

        # SUBDOMAIN DISCOVERY
        if re.search(r'subdomain|enumerate subdomain|find subdomain', q):
            if target:
                return (f"python malakai.py {target} --module subdomains", f"Subdomain enumeration for {target}")
            return (None, "Missing target for subdomain discovery")

        # EMAIL ENUMERATION
        if re.search(r'email|mail|user enum|user discover', q):
            if target:
                return (f"python malakai.py {target} --module emails", f"Email enumeration for {target}")
            return (None, "Missing target for email enumeration")

        # THREAT INTELLIGENCE (Shodan, VirusTotal)
        if re.search(r'threat|shodan|virustotal|passive|reputat|history', q):
            if target:
                return (f"python malakai.py {target} --module threat_intelligence", f"Threat intelligence check (Shodan/VirusTotal) for {target}")
            return (None, "Missing target for threat intelligence")

        # GEOLOCATION
        if re.search(r'geoloc|location|country|where|geoip|ip loc', q):
            if target:
                return (f"python malakai.py {target} --module geo", f"IP geolocation lookup for {target}")
            return (None, "Missing target for geolocation")

        # NETWORK RECONNAISSANCE (combined)
        if re.search(r'network recon|passive recon|osint|complete scan|full analysis|all modules', q):
            if target:
                return (f"python malakai.py {target}", f"Complete OSINT analysis on {target}")
            return (None, "Missing target for complete analysis")

        # SHODAN / PASSIVE
        if re.search(r'shodan|passive', q):
            if target:
                return (f"python malakai.py {target} --network", f"Passive network lookup (Shodan) for {target}")
            return (None, "Missing target for passive Shodan lookup")

        # PING / ICMP
        if re.search(r'\bping\b|ping scan|icmp', q):
            if target:
                # Use platform-appropriate ping count flag
                if sys.platform.startswith('win'):
                    return (f"ping -n 4 {target}", f"Ping (ICMP) check on {target}")
                else:
                    return (f"ping -c 4 {target}", f"Ping (ICMP) check on {target}")
            return (None, "Missing target for ping check")

        # fallback: look for explicit nmap usage
        m = re.search(r'nmap (.+)', q)
        if m and target:
            args = m.group(1).strip()
            if target not in args:
                return (f"nmap {args} {target}", f"Nmap with args: {args} on {target}")
            return (f"nmap {args}", f"Nmap with args: {args}")

        return (None, None)

    def _extract_target(text: str):
        """Extract domain or IP from text."""
        dom_match = re.search(r"([a-z0-9\-\.]+\.[a-z]{2,})", text, re.IGNORECASE)
        ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
        if ip_match:
            return ip_match.group(0)
        elif dom_match:
            return dom_match.group(0)
        return None

    def _offer_target_modules(target: str):
        """Interactive module selection menu for a target."""
        print(HEADING_COLOR + f"\nAvailable modules for {target}:" + Style.RESET_ALL)
        modules = [
            ('1', 'Domain & IP Analysis', f"python malakai.py {target} --module domain"),
            ('2', 'Subdomain Enumeration', f"python malakai.py {target} --module subdomains"),
            ('3', 'DNS Records Lookup', f"python malakai.py {target} --module dns"),
            ('4', 'WHOIS Lookup', f"python malakai.py {target} --module whois"),
            ('5', 'IP Geolocation', f"python malakai.py {target} --module geo"),
            ('6', 'Email Enumeration', f"python malakai.py {target} --module emails"),
            ('7', 'Threat Intelligence (Shodan/VirusTotal)', f"python malakai.py {target} --module threat_intelligence"),
            ('8', 'Network Reconnaissance (Nmap + Shodan)', f"python malakai.py {target} --network"),
            ('9', 'SSL/TLS Certificate Analysis', f"python malakai.py {target} --ssl"),
            ('a', 'Complete OSINT Analysis (All Modules)', f"python malakai.py {target}"),
            ('n', 'Port Scan (Top 100, Nmap)', f"nmap --top-ports 100 -sV -T4 {target}"),
            ('v', 'Vulnerability Scan (Nmap NSE)', f"nmap --script vuln -p 1-10000 {target}"),
        ]
        
        for choice, desc, _ in modules:
            print(CMD_COLOR + f"  {choice}) {desc}" + Style.RESET_ALL)
        
        try:
            selection = input(f"{PROMPT_COLOR}Select module(s) to run (e.g., 1,3,8 or 'a' for all): {Style.RESET_ALL}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return None
        
        if not selection or selection == 'n':
            return None
        
        selected_cmds = []
        if selection == 'a':
            # Run all
            selected_cmds = [cmd for _, _, cmd in modules if cmd != modules[-1][2]]  # exclude 'a' itself
        else:
            # Parse comma-separated choices
            for part in selection.replace(' ', '').split(','):
                part = part.strip()
                if part:
                    for choice, desc, cmd in modules:
                        if part == choice and cmd:
                            selected_cmds.append(cmd)
                            break
        
        return selected_cmds

        # Try LLM-backed suggestions if available
        suggestions = []
        if OPENAI_AVAILABLE and (OPENAI_API_KEY or os.getenv('OPENAI_API_KEY')):
            try:
                openai.api_key = OPENAI_API_KEY or os.getenv('OPENAI_API_KEY')
                system_msg = (
                    "You are Malakai assistant. Provide 3 concise suggestion lines (one per line) for actions or commands the user can run given the topic. "
                    "Prefer safe, legal actions and include suggested command examples when relevant."
                )
                resp = openai.ChatCompletion.create(
                    model=OPENAI_MODEL,
                    messages=[
                        {"role": "system", "content": system_msg},
                        {"role": "user", "content": topic}
                    ],
                    temperature=0.2,
                    max_tokens=300,
                )
                text = resp.choices[0].message.get('content', '').strip()
                for line in text.splitlines():
                    line = line.strip()
                    if line:
                        suggestions.append(line)
                if suggestions:
                    return suggestions
            except Exception:
                pass

        # Heuristic fallback suggestions
        t = topic.lower()
        if 'port' in t:
            return [
                'Quick top-ports scan: nmap --top-ports 100 -sV -T4 <target>',
                'Full port scan: nmap -p- -sV -T4 <target> (slow/conspicuous)',
                'Passive Shodan lookup: python malakai.py <target> --network'
            ]
        if 'ssl' in t or 'certificate' in t:
            return [
                'SSL cipher enumeration: nmap --script ssl-enum-ciphers -p 443 <target>',
                'Check certificate details with SSL analyzer: python malakai.py <target> --ssl',
                'Quick TLS test: openssl s_client -connect <target>:443'
            ]
        # default generic suggestions
        return [
            'Passive reconnaissance: python malakai.py <target> --network',
            'Quick domain overview: python malakai.py <target>',
            'Run a top-ports nmap scan: nmap --top-ports 100 -sV -T4 <target>'
        ]

    while True:
        try:
            prompt = input(f"{PROMPT_COLOR}AI> {Style.RESET_ALL}").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n" + ERR_COLOR + "Exiting AI chat." + Style.RESET_ALL)
            break

        if not prompt:
            continue
        if prompt.lower() in ('exit', 'quit'):
            print(ERR_COLOR + "Exiting AI chat." + Style.RESET_ALL)
            break

        # record user message in history/log
        try:
            _append_history('user', prompt)
        except Exception:
            pass

        # Check if this is an explicit "run" or "!" command request (raw shell syntax)
        # vs. a natural language request with action intent
        is_explicit_run = prompt.lower().startswith('run ') or prompt.startswith('!')
        
        # If explicit run/!, extract the command part
        if is_explicit_run:
            if prompt.lower().startswith('run '):
                raw_cmd = prompt[4:].strip()
            else:  # starts with !
                raw_cmd = prompt[1:].strip()
            
            # Try to interpret the raw command first (it might be NL)
            print(CMD_COLOR + f"[Requested] {raw_cmd}\n" + Style.RESET_ALL)
            interpreted_cmd, reason = _interpret_nl_command(raw_cmd)
            
            if interpreted_cmd:
                # Successfully interpreted as a command
                print(CMD_COLOR + f"Interpreted command: {interpreted_cmd} ({reason})" + Style.RESET_ALL)
                try:
                    confirm = input(f"{PROMPT_COLOR}Execute interpreted command? (y/N): {Style.RESET_ALL}").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    confirm = 'n'

                if confirm != 'y':
                    print(ERR_COLOR + "Cancelled. Command not executed." + Style.RESET_ALL)
                    continue
                exec_cmd = interpreted_cmd
            else:
                # No interpretation; assume it's a raw shell command
                print(CMD_COLOR + f"No NL interpretation found. Treating as raw shell command." + Style.RESET_ALL)
                try:
                    confirm = input(f"{PROMPT_COLOR}Execute raw command? (y/N): {Style.RESET_ALL}").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    confirm = 'n'
                if confirm != 'y':
                    print(ERR_COLOR + "Cancelled. Command not executed." + Style.RESET_ALL)
                    continue
                exec_cmd = raw_cmd

            # run the decided command
            print(CMD_COLOR + f"[Running] {exec_cmd}\n" + Style.RESET_ALL)
            try:
                completed = subprocess.run(exec_cmd, shell=True, capture_output=True, text=True, timeout=600)
                out = completed.stdout.strip()
                err = completed.stderr.strip()
                if out:
                    print(OUT_COLOR + "--- STDOUT ---" + Style.RESET_ALL)
                    print(out)
                if err:
                    print(ERR_COLOR + "--- STDERR ---" + Style.RESET_ALL)
                    print(err)
                if not out and not err:
                    print("(no output)")
                # append assistant execution summary to history/log (truncate large outputs)
                try:
                    summary = f"Ran: {exec_cmd} | stdout_len={len(out)} stderr_len={len(err)}"
                    _append_history('assistant', summary)
                except Exception:
                    pass
            except subprocess.TimeoutExpired:
                print(ERR_COLOR + "Command timed out (over 600s)" + Style.RESET_ALL)
            except Exception as e:
                print(ERR_COLOR + f"Error running command: {e}" + Style.RESET_ALL)
            continue

        # Nmap suggestions
        if prompt.lower().startswith('nmap') and 'help' in prompt.lower():
            print(HEADING_COLOR + "\nRecommended Nmap templates:\n" + Style.RESET_ALL)
            print(CMD_COLOR + "Quick discovery: --nmap-args \"--top-ports 100 -sV -T4\"" + Style.RESET_ALL)
            print(CMD_COLOR + "Full audit (use with consent): --nmap-args \"-A --script vuln -p- -T4\"" + Style.RESET_ALL)
            print(CMD_COLOR + "SSL checks: --nmap-args \"--script ssl-enum-ciphers -p 443\"" + Style.RESET_ALL)
            print(CMD_COLOR + "Safe quick scan: --nmap-args \"-sT --top-ports 50 -T3\"\n" + Style.RESET_ALL)
            continue

        # Suggestion helper: 'suggest [topic]'
        if prompt.lower().startswith('suggest'):
            topic = prompt[len('suggest'):].strip()
            if not topic:
                try:
                    topic = input(f"{PROMPT_COLOR}What topic do you want suggestions for? {Style.RESET_ALL}").strip()
                except (EOFError, KeyboardInterrupt):
                    topic = ''
            if not topic:
                print(ERR_COLOR + "No topic provided." + Style.RESET_ALL)
                continue
            suggestions = _get_suggestions(topic)
            print(HEADING_COLOR + f"\nSuggestions for: {topic}\n" + Style.RESET_ALL)
            for i, s in enumerate(suggestions, start=1):
                print(CMD_COLOR + f"{i}) {s}" + Style.RESET_ALL)
            try:
                _append_history('assistant', f"Suggestions for {topic}: {suggestions}")
            except Exception:
                pass
            try:
                choice = input(f"{PROMPT_COLOR}Select a suggestion to run (number) or 'n' to cancel: {Style.RESET_ALL}").strip()
            except (EOFError, KeyboardInterrupt):
                choice = 'n'
            if not choice or choice.lower() == 'n':
                print("Cancelled.")
                continue
            if choice.isdigit():
                idx = int(choice) - 1
                if idx < 0 or idx >= len(suggestions):
                    print(ERR_COLOR + "Invalid selection." + Style.RESET_ALL)
                    continue
                sel = suggestions[idx]
                # if suggestion contains placeholder <target>, prompt for it
                if '<target>' in sel:
                    try:
                        tgt = input(f"{PROMPT_COLOR}Enter target (domain or IP): {Style.RESET_ALL}").strip()
                    except (EOFError, KeyboardInterrupt):
                        tgt = ''
                    if not tgt:
                        print(ERR_COLOR + "No target provided. Cancelled." + Style.RESET_ALL)
                        continue
                    sel_cmd = sel.replace('<target>', tgt)
                else:
                    sel_cmd = sel
                # If the suggestion looks like a natural phrase, try to interpret
                if not sel_cmd.startswith('nmap') and not sel_cmd.startswith('python') and not sel_cmd.startswith('openssl'):
                    interpreted_cmd, reason = _interpret_nl_command(sel_cmd)
                    if interpreted_cmd:
                        sel_cmd = interpreted_cmd
                print(CMD_COLOR + f"Interpreted/selected command: {sel_cmd}" + Style.RESET_ALL)
                try:
                    confirm = input(f"{PROMPT_COLOR}Execute this suggestion? (y/N): {Style.RESET_ALL}").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    confirm = 'n'
                if confirm != 'y':
                    print("Cancelled.")
                    continue
                # run it
                print(CMD_COLOR + f"[Running] {sel_cmd}\n" + Style.RESET_ALL)
                try:
                    completed = subprocess.run(sel_cmd, shell=True, capture_output=True, text=True, timeout=600)
                    out = completed.stdout.strip()
                    err = completed.stderr.strip()
                    if out:
                        print(OUT_COLOR + "--- STDOUT ---" + Style.RESET_ALL)
                        print(out)
                    if err:
                        print(ERR_COLOR + "--- STDERR ---" + Style.RESET_ALL)
                        print(err)
                    if not out and not err:
                        print("(no output)")
                    try:
                        _append_history('assistant', f"Ran suggestion: {sel_cmd} | stdout_len={len(out)} stderr_len={len(err)}")
                    except Exception:
                        pass
                except subprocess.TimeoutExpired:
                    print(ERR_COLOR + "Command timed out (over 600s)" + Style.RESET_ALL)
                except Exception as e:
                    print(ERR_COLOR + f"Error running command: {e}" + Style.RESET_ALL)
                continue

        # Check if this is an action-oriented intent (e.g., "execute," "run," "show," "find," "discover," "scan")
        # If so, try to interpret it as a command request and auto-propose execution
        q = prompt.lower()
        action_intents = r'execute|run command|show|find|discover|scan|check|analyze|enumerate|lookup|probe|test|audit'
        is_action_request = re.search(action_intents, q)
        
        if is_action_request:
            # Try to interpret as a command
            interpreted_cmd, reason = _interpret_nl_command(prompt)
            if interpreted_cmd:
                print(CMD_COLOR + f"Detected action intent. Interpreted command: {interpreted_cmd}" + Style.RESET_ALL)
                print(PROMPT_COLOR + f"Reason: {reason}" + Style.RESET_ALL)
                try:
                    confirm = input(f"{PROMPT_COLOR}Execute this command? (y/N): {Style.RESET_ALL}").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    confirm = 'n'
                
                if confirm == 'y':
                    print(CMD_COLOR + f"[Running] {interpreted_cmd}\n" + Style.RESET_ALL)
                    try:
                        completed = subprocess.run(interpreted_cmd, shell=True, capture_output=True, text=True, timeout=600)
                        out = completed.stdout.strip()
                        err = completed.stderr.strip()
                        if out:
                            print(OUT_COLOR + "--- STDOUT ---" + Style.RESET_ALL)
                            print(out)
                        if err:
                            print(ERR_COLOR + "--- STDERR ---" + Style.RESET_ALL)
                            print(err)
                        if not out and not err:
                            print("(no output)")
                        try:
                            _append_history('assistant', f"Executed: {interpreted_cmd} | stdout_len={len(out)} stderr_len={len(err)}")
                        except Exception:
                            pass
                    except subprocess.TimeoutExpired:
                        print(ERR_COLOR + "Command timed out (over 600s)" + Style.RESET_ALL)
                    except Exception as e:
                        print(ERR_COLOR + f"Error running command: {e}" + Style.RESET_ALL)
                    continue
                else:
                    print("Cancelled. Showing KB answer instead.\n")

        # If no action intent, check if it's just a bare target (domain or IP)
        # If so, offer interactive module selection
        if not is_action_request:
            bare_target = _extract_target(prompt)
            if bare_target and prompt.strip() == bare_target:
                # User provided only a target, no action
                print(HEADING_COLOR + f"\nDetected target: {bare_target}" + Style.RESET_ALL)
                selected_cmds = _offer_target_modules(bare_target)
                
                if selected_cmds:
                    for cmd in selected_cmds:
                        print(CMD_COLOR + f"[Running] {cmd}\n" + Style.RESET_ALL)
                        try:
                            completed = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                            out = completed.stdout.strip()
                            err = completed.stderr.strip()
                            if out:
                                print(OUT_COLOR + "--- STDOUT ---" + Style.RESET_ALL)
                                print(out[:1000])  # truncate long output
                                if len(out) > 1000:
                                    print(OUT_COLOR + f"... (output truncated, total: {len(out)} chars)" + Style.RESET_ALL)
                            if err:
                                print(ERR_COLOR + "--- STDERR ---" + Style.RESET_ALL)
                                print(err[:500])
                            if not out and not err:
                                print("(no output)")
                            try:
                                _append_history('assistant', f"Executed module: {cmd}")
                            except Exception:
                                pass
                        except subprocess.TimeoutExpired:
                            print(ERR_COLOR + "Command timed out (over 600s)" + Style.RESET_ALL)
                        except Exception as e:
                            print(ERR_COLOR + f"Error running command: {e}" + Style.RESET_ALL)
                        print()
                continue

        # For other prompts, first try an LLM (if configured), else consult a small knowledge base and fall back to AIAnalyzer guidance
        try:
            # If OpenAI is available and an API key is set, call it for a conversational reply
            if OPENAI_AVAILABLE and (OPENAI_API_KEY or os.getenv('OPENAI_API_KEY')):
                try:
                    openai.api_key = OPENAI_API_KEY or os.getenv('OPENAI_API_KEY')
                    system_msg = (
                        "You are Malakai, a highly skilled cybersecurity assistant specializing in OSINT (Open Source Intelligence), "
                        "network reconnaissance, and vulnerability assessment. You provide expert, actionable, and safe advice. "
                        "Key principles: "
                        "(1) Always emphasize the need for WRITTEN AUTHORIZATION before any active scanning or testing. "
                        "(2) Recommend passive reconnaissance first (Shodan, DNS, WHOIS). "
                        "(3) Suggest graduated threat levels: passive -> quick active -> targeted deep dives. "
                        "(4) Provide specific, executable commands with target placeholders. "
                        "(5) Explain risks and mitigation strategies. "
                        "(6) Be concise but complete. Do not execute commands yourself; let the user confirm."
                    )
                    
                    # Build message history from chat_history (limit to last 10 messages to avoid token bloat)
                    messages = [{"role": "system", "content": system_msg}]
                    for role, content in chat_history[-20:]:  # last 10 exchanges (20 messages)
                        messages.append({"role": role, "content": content})
                    messages.append({"role": "user", "content": prompt})
                    
                    resp = openai.ChatCompletion.create(
                        model=OPENAI_MODEL,
                        messages=messages,
                        temperature=OPENAI_TEMPERATURE,
                        max_tokens=512,
                    )
                    answer = resp.choices[0].message.get('content', '').strip()
                    if answer:
                        print(AI_COLOR + "AI:" + Style.RESET_ALL)
                        print(answer)
                        try:
                            _append_history('assistant', answer)
                        except Exception:
                            pass
                        continue
                except Exception as e:
                    # Fall through to local KB if LLM call fails
                    print(ERR_COLOR + f"(LLM unavailable: {type(e).__name__}) Using local knowledge base." + Style.RESET_ALL)
                    try:
                        _append_history('assistant', f"(LLM unavailable) Using KB fallback.")
                    except Exception:
                        pass

            # Expanded knowledge base (pattern -> answer)
            kb = [
                # PORTS & NETWORK
                (r'open ports|find open ports|how to find open ports|scan for open ports',
                 """To find open ports use Nmap (active) or Shodan (passive).
**Passive (Safer, No Alerts)**: Shodan, historical data
  `python malakai.py <target> --network`  # Shodan lookup
**Quick Active Scan** (Top 100 ports, ~5 min):
  `nmap --top-ports 100 -sV -T4 <target>`
**Full Port Scan** (All 65535 ports, 30+ min, conspicuous):
  `nmap -p- -sV -T4 <target>`
**Stealthy Scan** (Slower, less detection):
  `nmap -sT --top-ports 50 -T1 <target>`
⚠️ Always get authorization before scanning. Unauthorized scanning is illegal."""),

                (r'how to find|how can i find|discover|locate service|what running',
                 """To identify running services on a target:
1. **Service Version Detection**: `nmap -sV -p- <target>`
2. **OS Fingerprinting**: `nmap -O <target>` (requires root/admin)
3. **Banner Grabbing**: `nc -zv -w1 <target> 1-1000`
4. **Combined aggressive scan**: `nmap -A -p- --script default <target>`
With Malakai: `python malakai.py <target> --network` (passive + Shodan data)"""),

                (r'vulnerab|exploit|cve|weakness|flaw|bug|weakness',
                 """To find vulnerabilities:
**Nmap NSE Vuln Scripts**: `nmap --script vuln -p- <target>`
**Service-Specific**:
  - Apache: `nmap --script apache2-methods -p 80,443 <target>`
  - SMB: `nmap --script smb-enum-shares -p 445 <target>`
**VirusTotal Check** (file hash): `python malakai.py <target> --module threat_intelligence`
**CVE Databases**: CVEDetails, NVD, ExploitDB
With Malakai: `python malakai.py <target>` runs full OSINT including threat intelligence."""),

                # SSL/TLS & CERTIFICATES
                (r'ssl|tls|certificate|cert|cipher|https|443|secure',
                 """To analyze SSL/TLS certificates and ciphers:
**Cipher Strength Check**: `nmap --script ssl-enum-ciphers -p 443 <target>`
**Certificate Details**: `nmap --script ssl-cert -p 443 <target>`
**OpenSSL Inspection**: `openssl s_client -connect <target>:443 -showcerts`
**Certificate Transparency**: Check CT logs for new certs
**Malakai SSL analysis**: `python malakai.py <target> --ssl` (full cert analysis)
Look for: weak ciphers, expired certs, self-signed, lack of HSTS."""),

                # WHOIS & DOMAIN
                (r'whois|owner|registr|domain info|registration|registrant',
                 """To get WHOIS and domain registration info:
**CLI Tools**:
  `whois example.com`
  `whois <IP>`
**Malakai**: `python malakai.py <target> --module whois`
**Online Services**: whois.com, ICANN WHOIS, registrar sites
**Info Retrieved**: Registrant, registrar, NS, registration dates, expiry
**Privacy**: Watch for WHOIS privacy (whoisguard, privacy services)."""),

                # DNS & RESOLUTION
                (r'dns|nameserver|mx|a record|resolve|domain resolve|cname',
                 """To enumerate DNS records:
**Full DNS Lookup**: `nslookup -type=ANY <target>` or `dig ANY <target>`
**Specific Records**:
  - A: `dig A <target>`
  - MX: `dig MX <target>`
  - NS: `dig NS <target>`
  - TXT: `dig TXT <target>` (SPF, DKIM, DMARC)
**DNS Transfer** (if allowed): `dig AXFR <target> @<nameserver>`
**Malakai**: `python malakai.py <target> --module dns`
**Tools**: nslookup, dig, host, dnsenum, fierce"""),

                # SUBDOMAINS
                (r'subdomain|enum subdomain|find subdomain|sub domain|wildcard',
                 """To enumerate subdomains:
**Passive Tools** (no alerts):
  - Certificate Transparency: crt.sh, certspotter
  - DNS aggregators: shodan.io, DNSdumpster, virustotal
  - Malakai: `python malakai.py <domain> --module subdomains`
**Active Tools** (may trigger alerts):
  - Brute force: `nmap -sL <domain>` or tools like sublist3r, ffuf
  - DNS queries: `for sub in $(cat wordlist.txt); do dig $sub.<domain>; done`
**Common Subdomains**: www, mail, ftp, cdn, api, dev, staging, admin"""),

                # EMAIL & USERS
                (r'email|mail|user|enumerate|breach|leaked|account',
                 """To enumerate emails and check for breaches:
**Email Enumeration**:
  `python malakai.py <domain> --module emails`
  Tools: mailmodo, email-enum, etc.
**Breach/Leak Check**:
  `python malakai.py <target> --module threat_intelligence` (uses VirusTotal, Shodan)
  Online: haveibeenpwned.com, breachdb.com
**OSINT Email Search**:
  - Google Dorks: site:linkedin.com "<domain>"
  - Shodan: `shodan search org:<domain>`"""),

                # THREAT INTELLIGENCE
                (r'threat|shodan|virustotal|reputation|malicious|ioc|indicator',
                 """To check threat intelligence and reputation:
**Shodan** (IP/domain history, open ports, services):
  `python malakai.py <target> --module threat_intelligence`
  Web: shodan.io
**VirusTotal** (malware/phishing checks, file analysis):
  `python malakai.py <target> --module threat_intelligence`
  Web: virustotal.com
**Other Services**: AbuseIPDB, Google Safe Browsing, URLhaus, AlienVault OTX
**Malakai Integrated**: Combines Shodan + VirusTotal automatically"""),

                # GEOLOCATION & INFRASTRUCTURE
                (r'geoloc|location|country|geoip|where|infrastructure|hosting|isp',
                 """To find geolocation and hosting info:
**IP Geolocation**: `python malakai.py <IP> --module geo`
**Hosting Provider**: `whois <IP>` or check AS (Autonomous System)
**Tools**: GeoIP2, IPinfo, DB-IP, MaxMind
**Info**: Country, city, ISP, organization, AS number
**OSINT**: Reverse IP lookup to find other domains on same host
**Infrastructure**: CDN, proxy detection, cloud provider identification"""),

                # NETWORK RECONNAISSANCE
                (r'network recon|passive recon|osint|complete|full analysis|all modules|comprehensive',
                 """To run complete OSINT reconnaissance:
**Malakai Complete Analysis** (all modules):
  `python malakai.py <target>`
  Includes: Domain, subdomains, DNS, WHOIS, geolocation, emails, threat intel, SSL
**Step-by-Step Passive Approach**:
  1. Shodan: `python malakai.py <target> --network`
  2. DNS: `python malakai.py <target> --module dns`
  3. WHOIS: `python malakai.py <target> --module whois`
  4. Threat Intel: `python malakai.py <target> --module threat_intelligence`
  5. Subdomains: `python malakai.py <target> --module subdomains`
**Then (if authorized) Active**:
  6. Port scan: `nmap --top-ports 1000 -sV <target>`
  7. Vulnerabilities: `nmap --script vuln <target>`
⚠️ Authorization required for active scans."""),

                # PERMISSIONS & ETHICS
                (r'permission|authorize|legal|ethics|responsible|can i scan|am i allowed',
                 """AUTHORIZATION & ETHICAL SCANNING:
**Golden Rule**: Never scan without explicit written authorization.
**Scope Definition**:
  - Get client to sign a Rules of Engagement (ROE) document
  - Define: targets, methods (passive/active), timing, out-of-scope systems
  - Clarify: disclosure requirements, liability, remediation timeline
**Penalties for Unauthorized Scanning**:
  - Legal: CFAA (Computer Fraud and Abuse Act) violation
  - Criminal charges: fines, imprisonment
**Best Practice**:
  1. Start PASSIVE only (no scans): Shodan, WHOIS, DNS, Google dorking
  2. Get signed authorization before ANY active scanning
  3. Document all activities with timestamps
  4. Report findings responsibly"""),

                # METHODOLOGY
                (r'methodology|approach|process|steps|how to start|best practice|workflow',
                 """OSINT & RECONNAISSANCE METHODOLOGY:
**Phase 1: Passive Intelligence** (No active scanning):
  - WHOIS: registrant, NS, infrastructure
  - DNS enumeration: A, MX, TXT, NS
  - Shodan: historical data, exposed ports, services
  - Subdomains: CT logs, DNS aggregators
  - Email: breaches, public records
**Phase 2: Active Reconnaissance** (With authorization):
  - Quick port scan: top 1000 ports
  - Service identification: version detection
  - Vulnerability scan: NSE scripts
  - OS fingerprinting: if applicable
**Phase 3: Deep Dive** (Targeted exploitation research):
  - Service-specific exploits
  - Configuration weaknesses
  - Business logic flaws
**Tools**: Malakai (integrated), Nmap, Shodan, crt.sh, DNSdumpster, Burp Suite"""),

                # HELP & COMMANDS
                (r'help|how do i|how can i|what can|commands|list|menu',
                 """MALAKAI COMMANDS & USAGE:
**Interactive AI Chat** (you are here):
  `python malakai.py --ai`
**CLI Modules**:
  `python malakai.py <target> --module <module>` (domain|subdomains|dns|whois|geo|emails|threat_intelligence|ssl)
  `python malakai.py <target> --network` (Nmap + Shodan)
  `python malakai.py <target> --ssl` (SSL analysis)
  `python malakai.py <target>` (All modules)
**AI Chat Commands**:
  `run <command>` → interpret & execute
  `!<command>` → shortcut
  `suggest <topic>` → get suggestions
  `nmap help` → Nmap templates
  `exit/quit` → leave chat
**Example Flows**:
  AI> example.com [shows module menu]
  AI> find open ports on example.com [auto-proposes nmap]
  AI> suggest vulnerabilities [lists scanning options]"""),

                # LEGAL/WARNINGS
                (r'warning|illegal|crime|law|cfaa|legal issue|get caught',
                 """⚠️ LEGAL WARNING - UNAUTHORIZED HACKING IS ILLEGAL:
**Computer Fraud and Abuse Act (CFAA)**:
  - Unauthorized access: up to 10 years imprisonment
  - Damage to systems: up to 10 years + fines
  - Attempted unauthorized access: up to 5 years
**Other Applicable Laws**:
  - GDPR, CCPA: data privacy violations
  - GDPR: up to €20M or 4% global revenue
  - State-level hacking laws
**What IS Legal**:
  ✓ Authorized penetration testing (written contract)
  ✓ Bug bounty programs (authorized by target)
  ✓ Passive OSINT (public data collection)
  ✓ Testing your own systems
  ✗ Scanning others' systems without permission
  ✗ Accessing unauthorized systems
**Always Get Authorization First!**"""),

                (r'nmap help|nmap templates|nmap template|nmap options',
                 """Nmap templates and common arguments:
**Quick discovery** (5 min): `nmap --top-ports 100 -sV -T4 <target>`
**Full port scan** (30+ min): `nmap -p- -sV -T4 <target>`
**Vulnerability scan**: `nmap --script vuln -p- <target>`
**SSL/TLS ciphers**: `nmap --script ssl-enum-ciphers -p 443 <target>`
**SMB enumeration**: `nmap --script smb-enum-shares -p 445 <target>`
**Safe scan** (stealthy): `nmap -sT --top-ports 50 -T1 <target>`
**OS Detection** (needs root): `nmap -O <target>`
**Aggressive scan**: `nmap -A -p- --script default <target>`
**Timing Templates**: -T0 (paranoid), -T1 (sneaky), -T2 (polite), -T3 (normal), -T4 (aggressive), -T5 (insane)"""),

                (r'how to scan|how to scan for|scan tips|scanning tips|best practices',
                 """Best practices for effective & safe scanning:
**Before Scanning**:
  1. ✓ Get written authorization
  2. ✓ Define scope clearly (in-scope/out-of-scope)
  3. ✓ Plan timing (off-hours preferred)
  4. ✓ Notify stakeholders
**During Scanning**:
  1. Start PASSIVE: Shodan, WHOIS, DNS (no alerts)
  2. Quick ACTIVE: top 100-1000 ports (low risk)
  3. Targeted DEEP: service-specific scans (high risk)
  4. Monitor impact on live systems
**After Scanning**:
  1. Document findings with timestamps
  2. Prioritize by severity and exploitability
  3. Provide remediation guidance
  4. Follow disclosure responsibly
**Tools**: Malakai (passive-friendly), Nmap (flexible), Shodan (historical)"""),
            ]

            matched = False
            for pattern, answer in kb:
                if re.search(pattern, q):
                    print(AI_COLOR + "AI:" + Style.RESET_ALL)
                    print(answer)
                    try:
                        _append_history('assistant', answer)
                    except Exception:
                        pass
                    matched = True
                    break
            if matched:
                continue

            # fallback guidance when no KB match is found
            fallback_msg = (
                "I can help with OSINT, network scanning, and reconnaissance. I support:\n"
                "  • Execute commands: `run <cmd>` or `!<cmd>` (with NL interpretation)\n"
                "  • Suggest actions: `suggest <topic>` (shows curated options)\n"
                "  • Get templates: `nmap help` (common Nmap scans)\n"
                "  • Target analysis: just type a domain/IP for module selection menu\n"
                "  • Ask questions: 'how to find X', 'what is Y', etc.\n"
                "Type 'help' for command list or ask a specific cybersecurity question."
            )
            print(AI_COLOR + "AI:\n" + fallback_msg + Style.RESET_ALL)
            try:
                _append_history('assistant', fallback_msg)
            except Exception:
                pass
        except Exception as e:
            print(ERR_COLOR + f"AI: Error ({type(e).__name__}). Try 'help' for commands." + Style.RESET_ALL)


    def run_specific_module(self, target, module, output_file=None):
        """Run a specific OSINT module on target"""
        print(f"[*] Running {module} module for: {target}\n")
        
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'module': module,
            'result': None
        }
        
        try:
            if module == 'domain':
                results['result'] = self.domain_analyzer.analyze_domain(target)
                print("[+] Domain & IP Analysis Complete")
            elif module == 'subdomains':
                results['result'] = self.subdomain_discoverer.discover_subdomains(target)
                print("[+] Subdomain Discovery Complete")
            elif module == 'dns':
                results['result'] = self.dns_analyzer.get_complete_dns_info(target)
                print("[+] DNS Analysis Complete")
            elif module == 'whois':
                results['result'] = self.whois_lookup.get_whois_info(target)
                print("[+] WHOIS Lookup Complete")
            elif module == 'geo':
                # For geolocation, we need an IP address
                results['result'] = self.ip_geolocation.locate_ip(target)
                print("[+] IP Geolocation Complete")
        except Exception as e:
            print(f"[-] Error running {module} module: {e}")
            return None
        
        # Display results
        print("\n" + "="*60)
        print(json.dumps(results, indent=2, default=str))
        print("="*60)
        
        # Save to file if specified
        if output_file:
            self.output_formatter.save_results(results, output_file)
            print(f"\n[+] Results saved to: {output_file}")
        
        return results

def main():
    parser = argparse.ArgumentParser(description='Malakai-Osint - Advanced OSINT Tool')
    parser.add_argument('target', nargs='?', default=None, help='Domain or IP address to investigate')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('--ai', action='store_true', help='Enable AI-powered analysis')
    parser.add_argument('--module', choices=['domain', 'subdomains', 'dns', 'whois', 'geo'], help='Run specific module only')
    parser.add_argument('--ssl', action='store_true', help='Enable detailed SSL/TLS certificate analysis')
    parser.add_argument('--ssl-ports', nargs='+', type=int, help='Custom SSL ports to check (default: 443, 8443, 9443)')
    parser.add_argument('--network', action='store_true', help='Enable network reconnaissance (Nmap + Shodan)')
    parser.add_argument('--nmap-args', default='-sV --script vuln -A', help='Custom Nmap arguments (default: -sV --script vuln -A)')

    args = parser.parse_args()
    
    malakai = MalakaiOSINT()
    # If user invoked only --ai without a target, start interactive AI chatbot
    if args.ai and not args.target:
        _start_ai_chat(malakai)
        return
    
    # If no target provided, ask for module selection first
    if not args.target:
        try:
            if sys.stdin.isatty():
                print("\n" + "="*60)
                print("MALAKAI OSINT - Module Selection")
                print("="*60 + "\n")
                print("Select which module to run:\n")
                print("1) Domain & IP Analysis")
                print("2) Discover Subdomains")
                print("3) DNS Records")
                print("4) WHOIS Lookup")
                print("5) IP Geolocation")
                print("6) Email Enumeration & Breach Check")
                print("7) Threat Intelligence (Shodan + VirusTotal)")
                print("8) Network Reconnaissance (Nmap + Shodan)")
                print("9) SSL/TLS Certificate Analysis")
                print("a) All (Complete Analysis)")
                print("\n")
                module_selection = input("Enter module choice (1-9, a): ").strip().lower()
            else:
                # Non-interactive: default to complete analysis
                module_selection = 'a'
        except Exception:
            module_selection = 'a'
        
        # Get target based on module selection
        target_prompt = "Enter target (Domain or IP address): "
        try:
            if sys.stdin.isatty():
                target = input(target_prompt).strip()
            else:
                target = None
        except Exception:
            target = None
        
        if not target:
            print("[-] No target provided. Exiting.")
            sys.exit(1)
        
        # Route to appropriate handler
        if module_selection == 'a' or module_selection == 'all':
            malakai.run_complete_analysis(target, args.output, args.ai, args.ssl)
        elif module_selection == '8':
            # Network scan module
            malakai.run_network_scan(target, args.output, args.nmap_args)
        elif module_selection in ('1', '2', '3', '4', '5', '6', '7', '9'):
            # Map selection to module name
            module_map = {
                '1': 'domain',
                '2': 'subdomains',
                '3': 'dns',
                '4': 'whois',
                '5': 'geo',
                '6': 'emails',
                '7': 'threat_intelligence',
                '9': 'ssl'
            }
            module_name = module_map.get(module_selection)
            if module_name in ('emails', 'threat_intelligence'):
                # These need IP, so extract it first
                print(f"[*] Running {module_name} module for: {target}\n")
                results = {
                    'target': target,
                    'timestamp': datetime.now().isoformat(),
                    'analysis': {}
                }
                try:
                    if module_name == 'emails':
                        results['analysis']['emails'] = malakai.email_enumerator.enumerate_domain_emails(target)
                    elif module_name == 'threat_intelligence':
                        try:
                            ip = socket.gethostbyname(target)
                        except:
                            ip = target
                        results['analysis']['threat_intelligence'] = malakai.threat_intelligence.bulk_threat_check(target, ip)
                except Exception as e:
                    results['analysis'][module_name] = {'error': str(e)}
                
                malakai.output_formatter.display_results(results)
                if args.output:
                    malakai.output_formatter.save_results(results, args.output)
            elif module_name == 'ssl':
                malakai.ssl_analyzer.analyze_domain_certificate(target)
            else:
                malakai.run_specific_module(target, module_name, args.output)
        else:
            print("[-] Invalid module selection. Exiting.")
            sys.exit(1)
    else:
        # Target was provided via command line
        if args.network:
            malakai.run_network_scan(args.target, args.output, args.nmap_args)
        elif args.module:
            malakai.run_specific_module(args.target, args.module, args.output)
        else:
            # Interactive module selection with target already provided
            try:
                if sys.stdin.isatty():
                    print("\nSelect which modules to run for: {}\n".format(args.target))
                    print("1) Domain & IP Analysis")
                    print("2) Discover Subdomains")
                    print("3) DNS Records")
                    print("4) WHOIS Lookup")
                    print("5) IP Geolocation")
                    print("6) Email Enumeration & Breach Check")
                    print("7) Threat Intelligence (Shodan + VirusTotal)")
                    print("8) Network Reconnaissance (Nmap + Shodan)")
                    print("9) SSL/TLS Certificate Analysis")
                    print("a) All")
                    selection = input("Enter choices (e.g. 1,2,4 or a for all): ").strip().lower()
                else:
                    selection = 'a'
            except Exception:
                selection = 'a'

            choices = set()
            if selection == 'a' or selection == 'all' or selection == '':
                choices = {'1', '2', '3', '4', '5', '6', '7', '8', '9'}
            else:
                for part in selection.replace(' ', '').split(','):
                    if part in ('1','2','3','4','5','6','7','8','9'):
                        choices.add(part)

            # If all chosen, run the existing complete analysis which preserves ordering
            if choices == {'1','2','3','4','5','6','7','8','9'}:
                malakai.run_complete_analysis(args.target, args.output, args.ai, args.ssl)
            else:
                # Build combined results for selected modules
                results = {
                    'target': args.target,
                    'timestamp': datetime.now().isoformat(),
                    'analysis': {}
                }

                # Domain & IP
                if '1' in choices:
                    try:
                        results['analysis']['domain_ip'] = malakai.domain_analyzer.analyze_domain(args.target)
                    except Exception as e:
                        results['analysis']['domain_ip'] = {'error': str(e)}

                # Subdomains
                if '2' in choices:
                    try:
                        results['analysis']['subdomains'] = malakai.subdomain_discoverer.discover_subdomains(args.target)
                    except Exception as e:
                        results['analysis']['subdomains'] = {'error': str(e)}

                # DNS
                if '3' in choices:
                    try:
                        results['analysis']['dns_records'] = malakai.dns_analyzer.get_complete_dns_info(args.target)
                    except Exception as e:
                        results['analysis']['dns_records'] = {'error': str(e)}

                # WHOIS
                if '4' in choices:
                    try:
                        results['analysis']['whois'] = malakai.whois_lookup.get_whois_info(args.target)
                    except Exception as e:
                        results['analysis']['whois'] = {'error': str(e)}

                # Geolocation
                if '5' in choices:
                    try:
                        ip = None
                        if 'domain_ip' in results['analysis'] and isinstance(results['analysis']['domain_ip'], dict):
                            ip = results['analysis']['domain_ip'].get('ip_address')
                        if not ip:
                            try:
                                ip = socket.gethostbyname(args.target)
                            except Exception:
                                ip = None
                        if ip:
                            results['analysis']['geolocation'] = malakai.ip_geolocation.locate_ip(ip)
                        else:
                            results['analysis']['geolocation'] = {'error': 'Could not resolve IP for geolocation'}
                    except Exception as e:
                        results['analysis']['geolocation'] = {'error': str(e)}

                # Email Enumeration & Breach Check
                if '6' in choices:
                    try:
                        results['analysis']['emails'] = malakai.email_enumerator.enumerate_domain_emails(args.target)
                    except Exception as e:
                        results['analysis']['emails'] = {'error': str(e)}

                # Threat Intelligence (Shodan + VirusTotal)
                if '7' in choices:
                    try:
                        ip = None
                        if 'domain_ip' in results['analysis'] and isinstance(results['analysis']['domain_ip'], dict):
                            ip = results['analysis']['domain_ip'].get('ip_address')
                        if not ip:
                            try:
                                ip = socket.gethostbyname(args.target)
                            except Exception:
                                ip = None
                        threat_results = malakai.threat_intelligence.bulk_threat_check(args.target, ip)
                        results['analysis']['threat_intelligence'] = threat_results
                    except Exception as e:
                        results['analysis']['threat_intelligence'] = {'error': str(e)}

                # Network Reconnaissance (Nmap + Shodan)
                if '8' in choices:
                    try:
                        network_results = malakai.network_scanner.run_full_network_scan(args.target, "-sV --script vuln -A")
                        results['analysis']['network_scan'] = network_results
                    except Exception as e:
                        results['analysis']['network_scan'] = {'error': str(e)}

                # SSL/TLS
                if '9' in choices:
                    try:
                        results['analysis']['ssl_analysis'] = malakai.ssl_analyzer.analyze_domain_certificate(args.target)
                    except Exception as e:
                        results['analysis']['ssl_analysis'] = {'error': str(e)}

                # AI Analysis if requested
                if args.ai:
                    try:
                        results['ai_analysis'] = malakai.ai_analyzer.analyze_results(results)
                    except Exception:
                        pass

                # Display and save
                malakai.output_formatter.display_results(results)
                if args.output:
                    malakai.output_formatter.save_results(results, args.output)

if __name__ == "__main__":
    main()

