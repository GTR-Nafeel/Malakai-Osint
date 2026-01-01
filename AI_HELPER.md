# Malakai AI Chat Helper - Complete Guide

## Overview

The Malakai AI Chat is an interactive cybersecurity assistant that helps with OSINT (Open Source Intelligence), network reconnaissance, and vulnerability assessment. It can execute commands, suggest actions, and provide expert guidance—all with built-in safety confirmations.

**Start the AI Chat:**
```bash
python malakai.py --ai
```

---

## Table of Contents

1. [Chat Commands & Syntax](#chat-commands--syntax)
2. [Example Interactions - Basic](#example-interactions---basic)
3. [Example Interactions - Port & Network Scanning](#example-interactions---port--network-scanning)
4. [Example Interactions - Vulnerability & Security](#example-interactions---vulnerability--security)
5. [Example Interactions - Domain & Subdomain Enumeration](#example-interactions---domain--subdomain-enumeration)
6. [Example Interactions - Email & User Enumeration](#example-interactions---email--user-enumeration)
7. [Example Interactions - Threat Intelligence](#example-interactions---threat-intelligence)
8. [Example Interactions - Getting Help & Info](#example-interactions---getting-help--info)
9. [Example Interactions - Suggestions & Templates](#example-interactions---suggestions--templates)
10. [Legal & Ethics](#legal--ethics)
11. [Troubleshooting](#troubleshooting)

---

## Chat Commands & Syntax

### Command Prefix Syntax

| Prefix | Usage | Example |
|--------|-------|---------|
| `run` | Interpret & execute command (NL-friendly) | `run scan example.com for open ports` |
| `!` | Direct shell command shortcut | `!nmap --top-ports 100 -sV example.com` |
| `suggest` | Get curated action suggestions | `suggest ports` or `suggest ssl` |
| `nmap help` | Show Nmap templates | `nmap help` |
| `help` | Show command reference | `help` |
| Plain domain/IP | Open module selection menu | `example.com` or `192.168.1.1` |
| `exit` / `quit` | Leave the chat | `exit` |

### Chat Features

- **Natural Language Interpretation**: Understands phrases like "scan for open ports" → translates to concrete commands
- **Conversation Context**: Maintains chat history (last 10 exchanges) for coherent replies
- **Safety First**: Always asks confirmation before executing commands
- **Audit Logging**: All interactions saved to `ai_chat.log` with timestamps
- **Command History**: Can reference previous scans/findings in follow-up questions

---

## Example Interactions - Basic

### 1. Just Type a Domain or IP

When you provide only a target, the AI shows an interactive module menu:

```
AI> example.com

Detected target: example.com

Available modules for example.com:
  1) Domain & IP Analysis
  2) Subdomain Enumeration
  3) DNS Records Lookup
  4) WHOIS Lookup
  5) IP Geolocation
  6) Email Enumeration
  7) Threat Intelligence (Shodan/VirusTotal)
  8) Network Reconnaissance (Nmap + Shodan)
  9) SSL/TLS Certificate Analysis
  a) Complete OSINT Analysis (All Modules)
  n) Port Scan (Top 100, Nmap)
  v) Vulnerability Scan (Nmap NSE)

Select module(s) to run (e.g., 1,3,8 or 'a' for all): 1,3,8
[Running] python malakai.py example.com --module domain
--- STDOUT ---
[Domain analysis output...]

[Running] python malakai.py example.com --module dns
--- STDOUT ---
[DNS records output...]

[Running] python malakai.py example.com --network
--- STDOUT ---
[Nmap + Shodan output...]
```

**Result**: Runs multiple modules sequentially with output shown in green.

---

### 2. Ask a Question (Local KB or LLM)

```
AI> how do I find open ports?

AI:
To find open ports use Nmap (active) or Shodan (passive).
**Passive (Safer, No Alerts)**: Shodan, historical data
  `python malakai.py <target> --network`  # Shodan lookup
**Quick Active Scan** (Top 100 ports, ~5 min):
  `nmap --top-ports 100 -sV -T4 <target>`
[... detailed answer from KB ...]
```

**Result**: AI returns from expanded knowledge base (15+ topic categories).

---

### 3. Get Help

```
AI> help

AI:
I can help with OSINT, network scanning, and reconnaissance. I support:
  • Execute commands: `run <cmd>` or `!<cmd>` (with NL interpretation)
  • Suggest actions: `suggest <topic>` (shows curated options)
  • Get templates: `nmap help` (common Nmap scans)
  • Target analysis: just type a domain/IP for module selection menu
  • Ask questions: 'how to find X', 'what is Y', etc.
Type 'help' for command list or ask a specific cybersecurity question.
```

---

## Example Interactions - Port & Network Scanning

### 4. Scan for Open Ports (Action Intent Detection)

```
AI> show open ports on telenor.com.pk

Detected action intent. Interpreted command: nmap --top-ports 100 -sV -T4 telenor.com.pk
Reason: Top ports scan on telenor.com.pk

Execute this command? (y/N): y

[Running] nmap --top-ports 100 -sV -T4 telenor.com.pk

--- STDOUT ---
Starting Nmap 7.92 ( https://nmap.org ) at 2025-12-04 15:30 UTC
Nmap scan report for telenor.com.pk (219.45.30.100)
Host is up (0.045s latency).
PORT     STATE    SERVICE
21/tcp   filtered ftp
80/tcp   open     http
443/tcp  open     https
8080/tcp open     http-proxy
[... more output ...]
```

**Result**: AI detects "show open ports" intent, proposes nmap command, you confirm, it runs.

---

### 5. Full Port Scan (All Ports)

```
AI> run scan all ports on example.com

Detected action intent. Interpreted command: nmap -p- -sV -T4 example.com
Reason: Full port scan on example.com

Execute this command? (y/N): y

[Running] nmap -p- -sV -T4 example.com

--- STDOUT ---
[Full port scan results... this may take 30+ minutes for all 65535 ports]
```

**Result**: AI recognizes "all ports" phrase and uses `-p-` (all ports) instead of `--top-ports 100`.

---

### 6. Passive Network Reconnaissance (Shodan)

```
AI> run passive recon on target.com

Detected action intent. Interpreted command: python malakai.py target.com
Reason: Complete OSINT analysis on target.com

Execute this command? (y/N): y

[Running] python malakai.py target.com

--- STDOUT ---
[OSINT Analysis Output...]
[+] Domain & IP Analysis Complete
[+] Subdomain Discovery Complete
[+] DNS Analysis Complete
... [all 9 modules run]
```

**Result**: Recognizes "passive recon" or "complete analysis" phrases and runs full OSINT.

---

### 7. Network Scan with Custom Nmap Args

```
AI> run ! nmap -A -p 80,443,8080 -sV example.com

[Requested] nmap -A -p 80,443,8080 -sV example.com

No NL interpretation found. Treating as raw shell command.

Execute raw command? (y/N): y

[Running] nmap -A -p 80,443,8080 -sV example.com

--- STDOUT ---
[Nmap output for ports 80, 443, 8080...]
```

**Result**: Direct Nmap command (raw shell syntax) executes after confirmation.

---

## Example Interactions - Vulnerability & Security

### 8. Find Vulnerabilities

```
AI> discover vulnerabilities in example.com

Detected action intent. Interpreted command: nmap --script vuln -p 1-10000 example.com
Reason: Vulnerability scan on example.com

Execute this command? (y/N): y

[Running] nmap --script vuln -p 1-10000 example.com

--- STDOUT ---
[Vulnerability scan results from Nmap NSE scripts...]
```

**Result**: "discover vulnerabilities" triggers vuln scan intent.

---

### 9. Check SSL/TLS Security

```
AI> analyze SSL on example.com

Detected action intent. Interpreted command: nmap --script ssl-enum-ciphers -p 443 example.com
Reason: SSL/TLS cipher analysis on example.com

Execute this command? (y/N): y

[Running] nmap --script ssl-enum-ciphers -p 443 example.com

--- STDOUT ---
[SSL/TLS cipher strength, supported protocols, weak ciphers...]
```

**Result**: "SSL" or "TLS" or "cipher" triggers SSL analysis.

---

### 10. Ask About SSL Vulnerabilities

```
AI> what are the risks of weak SSL ciphers?

AI:
To analyze SSL/TLS certificates and ciphers:
**Cipher Strength Check**: `nmap --script ssl-enum-ciphers -p 443 <target>`
**Certificate Details**: `nmap --script ssl-cert -p 443 <target>`
**OpenSSL Inspection**: `openssl s_client -connect <target>:443 -showcerts`
[... full KB answer ...]
```

**Result**: KB answer from SSL/TLS category.

---

## Example Interactions - Domain & Subdomain Enumeration

### 11. Enumerate Subdomains

```
AI> find subdomains for example.com

Detected action intent. Interpreted command: python malakai.py example.com --module subdomains
Reason: Subdomain enumeration for example.com

Execute this command? (y/N): y

[Running] python malakai.py example.com --module subdomains

--- STDOUT ---
[+] Subdomain Discovery Complete
[Subdomains found: www, mail, ftp, cdn, api, dev, staging...]
```

**Result**: "find subdomains" or "enumerate subdomains" triggers Malakai subdomain module.

---

### 12. DNS Enumeration

```
AI> run resolve DNS records for example.com

Detected action intent. Interpreted command: python malakai.py example.com --module dns
Reason: DNS resolution and records for example.com

Execute this command? (y/N): y

[Running] python malakai.py example.com --module dns

--- STDOUT ---
[+] DNS Analysis Complete
A Record: 93.184.216.34
MX Record: mail.example.com
NS Record: ns1.example.com, ns2.example.com
TXT Record: v=spf1 include:_spf.google.com ~all
```

**Result**: DNS module runs for "resolve," "nameserver," "MX," "A record," etc.

---

### 13. WHOIS Lookup

```
AI> run WHOIS lookup on example.com

Detected action intent. Interpreted command: python malakai.py example.com --module whois
Reason: WHOIS lookup for example.com

Execute this command? (y/N): y

[Running] python malakai.py example.com --module whois

--- STDOUT ---
[+] WHOIS Lookup Complete
Registrant: Registry Operator
Registrar: VeriSign Global Registry Services
Creation Date: 1995-08-14
Expiration Date: 2025-08-13
```

**Result**: "WHOIS" or "registrant" or "owner" triggers WHOIS module.

---

## Example Interactions - Email & User Enumeration

### 14. Enumerate Email Addresses

```
AI> enumerate emails for example.com

Detected action intent. Interpreted command: python malakai.py example.com --module emails
Reason: Email enumeration for example.com

Execute this command? (y/N): y

[Running] python malakai.py example.com --module emails

--- STDOUT ---
[+] Email Enumeration and Breach Check
Emails found:
  admin@example.com
  support@example.com
  contact@example.com
Breach Status: No breaches detected
```

**Result**: "email," "mail," "user," or "enumerate" triggers email module.

---

### 15. Ask About Email Enumeration

```
AI> how do I find email addresses for a company?

AI:
To enumerate emails and check for breaches:
**Email Enumeration**:
  `python malakai.py <domain> --module emails`
  Tools: mailmodo, email-enum, etc.
**Breach/Leak Check**:
  `python malakai.py <target> --module threat_intelligence` (uses VirusTotal, Shodan)
  Online: haveibeenpwned.com, breachdb.com
[... full KB answer ...]
```

**Result**: KB answer from email enumeration category.

---

## Example Interactions - Threat Intelligence

### 16. Threat Intelligence Check

```
AI> check threat intelligence for example.com

Detected action intent. Interpreted command: python malakai.py example.com --module threat_intelligence
Reason: Threat intelligence check (Shodan/VirusTotal) for example.com

Execute this command? (y/N): y

[Running] python malakai.py example.com --module threat_intelligence

--- STDOUT ---
[+] Threat Intelligence Complete
Shodan Results:
  - Port 80: Apache 2.4.41
  - Port 443: nginx 1.18.0
  - CVEs: 3 known CVEs in detected services
VirusTotal Results:
  - Malware Score: 0/70 (Clean)
  - Last Analysis: 2025-12-04
  - Phishing Score: 0/70 (Clean)
```

**Result**: "threat," "Shodan," "VirusTotal," or "reputation" triggers threat intel module.

---

### 17. IP Geolocation

```
AI> find location of 8.8.8.8

Detected action intent. Interpreted command: python malakai.py 8.8.8.8 --module geo
Reason: IP geolocation lookup for 8.8.8.8

Execute this command? (y/N): y

[Running] python malakai.py 8.8.8.8 --module geo

--- STDOUT ---
[+] IP Geolocation Complete
IP: 8.8.8.8
Country: United States
City: Mountain View
ISP: Google LLC
Organization: Google
ASN: AS15169
```

**Result**: "geolocation," "location," "where," or "geoip" triggers geolocation module.

---

## Example Interactions - Getting Help & Info

### 18. Nmap Templates & Help

```
AI> nmap help

Recommended Nmap templates:

Quick discovery: --nmap-args "--top-ports 100 -sV -T4"
Full audit (use with consent): --nmap-args "-A --script vuln -p- -T4"
SSL checks: --nmap-args "--script ssl-enum-ciphers -p 443"
Safe quick scan: --nmap-args "-sT --top-ports 50 -T3"
```

**Result**: Shows nmap template reference.

---

### 19. Ask About Methodology

```
AI> what's the best approach for reconnaissance?

AI:
OSINT & RECONNAISSANCE METHODOLOGY:
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
[... full methodology ...]
```

**Result**: Detailed methodology from KB.

---

### 20. Ask About Legal Requirements

```
AI> do I need permission to scan?

AI:
AUTHORIZATION & ETHICAL SCANNING:
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
  4. Report findings responsibly
```

**Result**: Legal/ethics KB answer.

---

## Example Interactions - Suggestions & Templates

### 21. Get Suggestions for a Topic

```
AI> suggest ports

Suggestions for: ports

1) Quick top-ports scan: nmap --top-ports 100 -sV -T4 <target>
2) Full port scan: nmap -p- -sV -T4 <target> (slow/conspicuous)
3) Passive Shodan lookup: python malakai.py <target> --network

Select a suggestion to run (number) or 'n' to cancel: 1
Enter target (domain or IP): example.com
Interpreted/selected command: nmap --top-ports 100 -sV -T4 example.com
Execute this suggestion? (y/N): y

[Running] nmap --top-ports 100 -sV -T4 example.com

--- STDOUT ---
[Scan results...]
```

**Result**: Shows 3 suggestions, user picks one, enters target, executes.

---

### 22. Suggest SSL Scans

```
AI> suggest ssl

Suggestions for: ssl

1) SSL cipher enumeration: nmap --script ssl-enum-ciphers -p 443 <target>
2) Check certificate details with SSL analyzer: python malakai.py <target> --ssl
3) Quick TLS test: openssl s_client -connect <target>:443

Select a suggestion to run (number) or 'n' to cancel: 2
Enter target (domain or IP): example.com
Interpreted/selected command: python malakai.py example.com --ssl
Execute this suggestion? (y/N): y

[Running] python malakai.py example.com --ssl

--- STDOUT ---
[SSL certificate analysis...]
```

**Result**: User selects SSL module option from suggestions.

---

## Legal & Ethics

### Important Reminders

⚠️ **Authorization is MANDATORY before any active scanning!**

```
AI> what's the CFAA?

AI:
⚠️ LEGAL WARNING - UNAUTHORIZED HACKING IS ILLEGAL:
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
**Always Get Authorization First!**
```

---

## Troubleshooting

### Issue: "Command not interpreted. Execute raw command?"

**Cause**: AI couldn't understand your natural language request.

**Solution**: 
- Be more explicit: `run nmap --top-ports 100 -sV example.com`
- Or ask a question: `how do I scan for open ports?`
- Or use suggest: `suggest ports`

---

### Issue: Nmap not installed

```
--- STDERR ---
'nmap' is not recognized as an internal or external command, operable program or batch file.
```

**Solution**:
- Install nmap: `https://nmap.org/download.html`
- Or use Malakai modules instead (passive): `python malakai.py <target>`

---

### Issue: API Key not configured

```
(LLM unavailable) Using local knowledge base.
```

**Cause**: OpenAI API key not set.

**Solution**:
- Set environment variable: `set OPENAI_API_KEY=your-key`
- Or edit `config.py`: `OPENAI_API_KEY = "your-key"`
- AI still works with local KB (no LLM responses, but all commands work)

---

### Issue: Command takes too long

```
[Running] nmap -p- -sV -T4 example.com
[... waiting 30+ minutes ...]
```

**Tip**: Use faster scans:
- `nmap --top-ports 100` instead of `-p-` (full scan)
- `-T4` for faster timing (more conspicuous)
- Limit ports: `-p 1-1000` instead of all 65535

---

## Quick Reference

| Goal | Command | Example |
|------|---------|---------|
| Show menu for target | Just type domain/IP | `example.com` |
| Quick port scan | `run open ports on <target>` | `run open ports on example.com` |
| Full port scan | `run all ports on <target>` | `run all ports on example.com` |
| Find vulnerabilities | `run vulnerabilities on <target>` | `run vulnerabilities on example.com` |
| Check SSL | `run SSL on <target>` | `run SSL on example.com` |
| Get subdomains | `run subdomains for <target>` | `run subdomains for example.com` |
| WHOIS info | `run WHOIS on <target>` | `run WHOIS on example.com` |
| Threat intel | `run threat on <target>` | `run threat on example.com` |
| Complete OSINT | `run complete analysis on <target>` | `run complete analysis on example.com` |
| Get suggestions | `suggest <topic>` | `suggest ports` |
| Get help | `help` or `nmap help` | `help` |
| Ask question | Just type | `how do I find open ports?` |

---

## Chat Features

✅ **Conversation Context**: AI remembers last 10 exchanges  
✅ **Command Interpretation**: Converts natural language → executable commands  
✅ **Safety Confirmations**: Always asks before running commands  
✅ **Audit Logging**: All interactions saved to `ai_chat.log`  
✅ **Auto-suggestions**: Shows module menu when you type a bare target  
✅ **Error Recovery**: Falls back gracefully if LLM unavailable  
✅ **Expert KB**: 15+ categories of cybersecurity knowledge  

---

**Last Updated**: December 4, 2025  
**Version**: Malakai v1.0 with AI Chat  
**Author**: Nafeel Masood

For more information, run `python malakai.py --help` or start the AI chat with `python malakai.py --ai`.
