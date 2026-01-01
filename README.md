# Malakai OSINT

Advanced OSINT reconnaissance tool for comprehensive domain, IP, and security intelligence gathering. Provides deep infrastructure analysis with full transparency (no result truncation) and security posture assessment.

## Key Features

### Core Reconnaissance
- **Domain & IP Analysis** – HTTP fingerprinting, server detection, technology stack identification
- **Subdomain Discovery** – DNS bruteforce + Certificate Transparency log parsing  
- **DNS Enumeration** – Full record types (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV)
- **WHOIS Lookup** – Domain registration info, registrant details, nameservers
- **IP Geolocation** – Geographic location, ISP, ASN, threat indicators
- **Reverse DNS** – PTR records with enhanced accuracy and error handling

### Security Analysis
- **SSL/TLS Certificate Analysis** – Complete certificate parsing with serial numbers (decimal/hex), issuer/subject organization, location, validity dates, signature algorithms, Subject Alternative Names (SANs), certificate transparency logs
- **Security Headers Analysis** – Comprehensive HTTP security header detection (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, X-Permitted-Cross-Domain-Policies, Referrer-Policy, Permissions-Policy, X-XSS-Protection) with security scoring (0-100)
- **DNSSEC Validation** – Full DNSSEC chain validation with DS/DNSKEY record parsing, algorithm strength assessment (strong/weak/moderate), key type identification (KSK/ZSK)
- **DMARC Policy Analysis** – Complete DMARC record parsing with policy extraction (p, sp, adkim, aspf, pct, rua, ruf tags)
- **DKIM Enumeration** – Extended selector discovery (19+ common selectors) with algorithm and key type identification
- **CDN/WAF Detection** – Identification of Cloudflare, Akamai, AWS CloudFront, Fastly, Imperva, Sucuri via CNAME/reverse DNS correlation

### Email Intelligence
- **Email Enumeration** – Automated discovery of public email addresses via pattern matching, file scraping (robots.txt, sitemap.xml, security.txt)
- **Breach Checking** – Integration with Have I Been Pwned API for breach status verification with rate limiting, breach history, and paste site cross-referencing

### Threat Intelligence Integration
- **Shodan API Integration** – Internet-wide scanner integration for identifying open ports, services, vulnerabilities, and exposed infrastructure
- **VirusTotal API Integration** – Malware and security analysis with detection ratios from 90+ antivirus engines
- **Threat Scoring** – Automated threat assessment combining data from multiple sources (0-100 score: clean/warning/suspicious/malicious)
- **Vulnerability Detection** – CVE identification from Shodan, malicious voting from VirusTotal engines
- **Infrastructure Exposure Analysis** – Open ports, running services, technology detection, organizational information

### Network Reconnaissance
- **Active Network Scanning** – Nmap integration with service version detection, OS identification, NSE vulnerability scripts
- **Passive Network Analysis** – Shodan passive scanning for historical data, first/last seen, tags, ISP/ASN information
- **Port Discrepancy Analysis** – Intelligent correlation identifying ports visible in Nmap but not Shodan (internal-only), and vice versa
- **Exposure Scoring** – Automated risk assessment based on open ports, unexpected services, outdated versions
- **Network Insights** – Detects recently exposed ports, firewall-filtered ports, and infrastructure inconsistencies

### Output & Export
- **Full Data Display** – No truncation of results (all subdomains, DNS records, SANs, nameservers displayed)
- **Formatted Console Output** – Color-coded results with indicators (✅ ⚠️ 🔴 🟢)
- **JSON Export** – Complete structured export of all findings
- **Interactive Module Selection** – TTY-aware prompt to choose which modules to run

## Installation

### Prerequisites
- Python 3.7+
- pip (Python package manager)

### Setup

```powershell
# Clone or download the project
cd Malakai-osint

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### Dependencies
- `requests` – HTTP requests for web fingerprinting
- `dnspython` – DNS queries and reverse DNS lookups
- `python-whois` – WHOIS lookups
- `cryptography` – SSL/TLS certificate parsing
- `beautifulsoup4` – Web scraping and HTML parsing

## Usage

### Basic Scans

**Display help:**
```powershell
python malakai.py -h
```

**Interactive module selection (no arguments):**
```powershell
python malakai.py
# First select module (1-9 or a for all)
# Then enter target domain/IP
```

**Run complete analysis on a domain:**
```powershell
python malakai.py example.com
# Follow the on-screen menu to select modules
```

### Flag Usage Examples

**Save results to JSON file:**
```powershell
python malakai.py example.com -o results.json
# Short form: -o
# Long form: --output
```

**Enable AI-powered analysis:**
```powershell
python malakai.py example.com --ai
# Provides AI insights on gathered data
```

**Run specific module (old CLI method):**
```powershell
python malakai.py example.com --module domain
# Choices: domain, subdomains, dns, whois, geo
```

**SSL/TLS Certificate Analysis:**
```powershell
# Enable SSL analysis (auto-detects 443, 8443, 9443)
python malakai.py example.com --ssl

# Custom SSL ports
python malakai.py example.com --ssl --ssl-ports 443 8443 9443 3000
```

**Network Reconnaissance (Nmap + Shodan):**
```powershell
# Default Nmap args: -sV --script vuln -A
python malakai.py example.com --network

# Custom Nmap arguments
python malakai.py example.com --network --nmap-args "-sS -p 1-65535"

# Example with specific port range
python malakai.py 192.168.1.1 --network --nmap-args "-sV -p 20-25,53,80,443,3306,5432"
```

**Combine multiple flags:**
```powershell
# SSL analysis + Network scan + AI analysis + Output to file
python malakai.py example.com --ssl --network --ai -o full_report.json

# Network scan with custom Nmap args and AI analysis
python malakai.py 8.8.8.8 --network --nmap-args "-A -T4" --ai -o network_report.json

# SSL on custom ports + save output
python malakai.py example.com --ssl --ssl-ports 443 8443 -o ssl_report.json
```

**Run complete analysis with all options:**
```powershell
python malakai.py example.com --ssl --network --ai -o complete_analysis.json --nmap-args "-sV --script vuln -A"
```

### Advanced Usage

**DNS reconnaissance only:**
```powershell
python malakai.py example.com --module dns
```

**Subdomain enumeration:**
```powershell
python malakai.py example.com --module subdomains
```

**WHOIS lookup:**
```powershell
python malakai.py example.com --module whois
```

**IP Geolocation:**
```powershell
python malakai.py 93.184.216.34 --module geo
```

**Passive network scanning (Shodan only - no Nmap):**
```powershell
python malakai.py 8.8.8.8 --network
# Requires Shodan API key in config.py
```

**Active network scanning with vulnerability detection:**
```powershell
python malakai.py 192.168.1.1 --network --nmap-args "-sV --script vuln"
```

**Domain analysis with SSL and threat intelligence:**
```powershell
python malakai.py example.com --ssl --ai -o analysis.json
```

**Save results to file:**
```powershell
python malakai.py example.com -o results.json
```

**Enable AI-powered analysis:**
```powershell
python malakai.py example.com --ai
```

## Output Examples

### Domain & IP Analysis Output
```
DOMAIN & IP ANALYSIS
----
Domain: example.com
IP Address: 93.184.216.34
HTTP Status: 200
Server: ECS (dcm/27FA)
Technologies: nginx, React
Reverse DNS: example.com
CDN/WAF: Cloudflare
Security Headers: 🟡 68/100
  Critical Headers: 2/4
  Found (6): Content-Security-Policy, Strict-Transport-Security, ...
  Missing (3): X-Frame-Options, X-Content-Type-Options, ...
```

### DNS Records with Security Analysis
```
DNS RECORDS
----
A Records:
  93.184.216.34
MX Records:
  10 aspmx.l.google.com.
NS Records:
  ns1.example.com.

DMARC:
  ✅ Record found: v=DMARC1; p=reject; rua=...
  Policy: reject
  DKIM Alignment: r (relaxed)
  SPF Alignment: s (strict)

DKIM:
  ✅ Found 2 selector(s): default, selector1
  Selectors Checked: 19

DNSSEC:
  ✅ Properly configured
  Algorithm Strength: strong
  DS Records: 1
  DNSKEY Records: 1
```

### SSL/TLS Certificate Analysis
```
SSL/TLS CERTIFICATE ANALYSIS
----
Domain: example.com
Subject: CN=example.com
Issuer: C=US, O=Example CA
Serial (Decimal): 123456789
Serial (Hex): 0x75BCD15
Validity: 2023-01-01 to 2024-01-01
Status: ✅ Valid
Organization: Example Inc.
Signature Algorithm: sha256WithRSAEncryption
Subject Alternative Names (3):
  DNS: example.com
  DNS: www.example.com
  DNS: api.example.com
```

### Email Enumeration & Breach Status
```
EMAIL ENUMERATION & BREACH STATUS
----
Total Emails Found: 5
✅ No breaches detected

Emails:
  ✅ admin@example.com
  ✅ contact@example.com
  ✅ info@example.com
  ✅ support@example.com
  ✅ team@example.com
```

### Threat Intelligence Analysis
```
🔍 THREAT INTELLIGENCE ANALYSIS (Shodan + VirusTotal)
----
Threat Score: 🟢 12/100 (CLEAN)

VirusTotal - Domain Analysis:
  Detection Ratio: 0/91
  Categories: Legitimate Business

Shodan - Internet Exposure Analysis:
  IP: 93.184.216.34
  Open Ports: 80, 443
  Services Detected: 2
    - Port 80: nginx
    - Port 443: nginx (SSL)
```

### Network Reconnaissance Report
```
🔍 NETWORK RECONNAISSANCE REPORT
Target IP: 192.0.2.1
Scan Status: Active scan completed ✅ | Passive scan completed ✅

SCANNING OVERVIEW
  Active Scan (Nmap):   8 ports open, 0 ports filtered, 1 OS match
  Passive Scan (Shodan): 12 ports indexed
  Port Overlap:         6 ports visible in both scans (confirmed)

PORTS & SERVICES
  Both Scans:
    80/tcp   open  http    Apache httpd 2.4.41 ✅ Confirmed
    443/tcp  open  https   Apache httpd 2.4.41 ✅ Confirmed
    22/tcp   open  ssh     OpenSSH 7.4 ✅ Confirmed
    
  Active Only (Nmap):
    3306/tcp open  mysql   MariaDB (internal-only likely)
    5432/tcp open  postgres PostgreSQL (internal-only likely)
    
  Passive Only (Shodan):
    8080/tcp filtered http-alt (recently closed or filtered)
    9200/tcp filtered elasticsearch (recently closed or filtered)

INFRASTRUCTURE INSIGHTS
  Internal-Only Services: 2 ports
    - MySQL on 3306 (suggests database server not exposed to internet)
    - PostgreSQL on 5432 (suggests internal database infrastructure)
    Interpretation: Services likely protected by firewall/internal network
    
  Recently Exposed: 2 ports
    - HTTP-Alt on 8080 (Shodan indexed, but not responding now)
    - Elasticsearch on 9200 (indexed previously, now filtered)
    Interpretation: Ports may have been recently closed or filtered

RISK ASSESSMENT
  Exposure Score: ⚠️ 42/100 (MODERATE)
  Risk Level: MODERATE
  
  Analysis:
    • 6 ports confirmed open and externally accessible
    • 2 internal-only database services detected
    • 2 recently closed/filtered services detected
    • Web services (80, 443) running common versions
    • SSH exposed on standard port (security concern)
    
  Unexpected Ports:
    ⚠️ SSH on port 22 (standard but exposed to internet - consider key-based auth)
    
  Outdated Services:
    ⚠️ Apache httpd 2.4.41 (2 years old - check for patches)
    ⚠️ OpenSSH 7.4 (outdated - upgrade recommended)

RECOMMENDATIONS
  1. 🔴 CRITICAL: Restrict SSH access (22) to VPN/bastion hosts or use fail2ban
  2. 🟠 HIGH: Update Apache (2.4.41 → 2.4.52+) and OpenSSH (7.4 → 8.6+)
  3. 🟡 MEDIUM: Investigate recently exposed ports (8080, 9200) - apply WAF rules
  4. 🟢 LOW: Maintain current database isolation - good security practice
  5. 🟢 LOW: Monitor Shodan index for new port listings (set alerts)
```

## Architecture

### Module Structure

```
modules/
├── domain_analyzer.py      – Domain resolution, HTTP analysis, tech detection, reverse DNS, CDN/WAF, headers
├── subdomain_discovery.py  – DNS bruteforce, Certificate Transparency parsing
├── dns_analyzer.py         – DNS records, DMARC/DKIM/DNSSEC analysis
├── whois_lookup.py         – Domain registration info
├── ip_geolocation.py       – IP location, ASN, threat intelligence
├── ssl_analyzer.py         – SSL/TLS certificate analysis
├── email_enum.py           – Email discovery, breach checking
└── __init__.py

utils/
├── output_formatter.py     – Result formatting, JSON export
├── ai_helper.py            – AI-powered analysis (optional)
└── __init__.py
```

### Key Classes

- **MalakaiOSINT** – Main orchestrator coordinating all analyzers
- **DomainAnalyzer** – HTTP/DNS resolution, server fingerprinting, security headers
- **SubdomainDiscoverer** – Subdomain enumeration
- **DNSAnalyzer** – DNS records, DMARC/DKIM/DNSSEC validation
- **WhoisLookup** – Domain registration data
- **IPGeolocation** – IP intelligence and ASN lookup
- **SSLAnalyzer** – Certificate analysis
- **EmailEnumerator** – Email discovery and HIBP breach checking
- **NetworkScanner** – Active/passive network reconnaissance combining Nmap and Shodan with port correlation
- **ThreatIntelligence** – Centralized API wrapper for Shodan and VirusTotal integration
- **OutputFormatter** – Result presentation and JSON export

## Technical Details

### Network Reconnaissance Engine

The network reconnaissance module combines **active scanning** (Nmap) and **passive scanning** (Shodan) to provide comprehensive infrastructure visibility with intelligent port correlation.

#### Active Scanning (Nmap)
- **Service Version Detection** (-sV): Identifies service type and version running on each port
- **OS Detection** (-A): Fingerprints operating system and additional metadata
- **Vulnerability Scripts** (--script vuln): Runs NSE scripts to detect known CVEs
- **Graceful Degradation**: If Nmap is not installed, continues with Shodan-only analysis

#### Passive Scanning (Shodan)
- **Historical Port Index**: Identifies all ports Shodan has indexed for the IP
- **Service Information**: Banner data, technology detection, first/last seen dates
- **CVE Detection**: Cross-references indexed ports with known vulnerabilities
- **Infrastructure Metadata**: ISP, ASN, organization, hostnames, hosting provider

#### Port Discrepancy Analysis

The scanner compares Nmap and Shodan results to identify three categories:

1. **Both Scans (Confirmed Exposure)**
   - Port responds to Nmap probe AND indexed by Shodan
   - Interpretation: Port is externally accessible and exposed
   - Security Impact: Any service running here is internet-facing

2. **Nmap Only (Internal-Only Services)**
   - Port responds to Nmap probe BUT not indexed by Shodan
   - Interpretation: Service is firewalled or behind NAT; not exposed to internet
   - Security Impact: Good sign - databases, internal services protected
   - Example: MySQL on 3306, PostgreSQL on 5432

3. **Shodan Only (Recently Closed)**
   - Port indexed by Shodan BUT doesn't respond to Nmap probe
   - Interpretation: Port was previously exposed, now filtered or closed
   - Security Impact: Service may have been recently shut down or blocked
   - Example: Elasticsearch on 9200 (indexed but no longer responding)

#### Exposure Scoring Algorithm

Risk Score = (open_ports × 2) + (unexpected_ports × 15) + (outdated_services × 10) + (recently_exposed × 8)

- **0-20**: LOW (minimal exposure, well-managed)
- **21-40**: LOW-MODERATE (few services exposed, standard ports)
- **41-70**: MODERATE (multiple services exposed, outdated versions detected)
- **71-100**: HIGH (extensive exposure, multiple risk factors, critical services exposed)

#### Service Flagging

**Unexpected Ports** (high risk if exposed):
- 22/tcp (SSH) – Direct administrative access
- 3306/tcp (MySQL) – Unencrypted database access
- 5432/tcp (PostgreSQL) – Database access
- 3389/tcp (RDP) – Remote desktop protocol
- 139/tcp, 445/tcp (SMB) – File sharing/admin access

**Outdated Services** (version 2+ years old):
- Apache httpd, nginx, OpenSSH, OpenSSL, MySQL, PostgreSQL flagged if outdated

### Security Features
- **DNSSEC Validation** – Supports modern algorithms (RSASHA256, RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384, ED25519, ED448); flags weak algorithms (RSAMD5, RSASHA1)
- **Certificate Chain Validation** – Verifies issuer/subject organization alignment, CN/SAN matching, certificate expiry
- **Security Header Scoring** – Weighted scoring (critical headers worth 15pts, non-critical 5pts each)
- **Breach Checking** – Rate-limited API calls (500ms delay), Have I Been Pwned API integration

### DNS Methods
- **Extended DKIM Selector Search** – Tests 19+ common selectors (default, google, selector1-3, office365, sendgrid, mailgun, etc.)
- **DMARC Policy Parsing** – Extracts all policy tags (p, sp, adkim, aspf, pct, rua, ruf)
- **Comprehensive DNSSEC** – DS/DNSKEY record validation, algorithm strength assessment, key type identification

### Reverse DNS Enhancement
- Improved error handling with detailed reason messages
- Count of reverse DNS records returned
- Distinguishes between NXDOMAIN, NoAnswer, and other errors

## Configuration

### Advanced Scanning

**Network Reconnaissance (Active + Passive):**
```powershell
# Full network scan combining Nmap (active) and Shodan (passive)
python malakai.py 8.8.8.8 --network

# Custom Nmap arguments
python malakai.py 192.168.1.1 --network --nmap-args "-sS -p 1-65535"
```

**SSL/TLS Certificate Analysis:**
```powershell
# Analyze SSL certificate
python malakai.py example.com --ssl

# Check custom ports
python malakai.py example.com --ssl --ssl-ports 443,8443,9443
```

**Combined Analysis:**
```powershell
# Full reconnaissance with network scanning and SSL analysis
python malakai.py example.com --ssl --network -o full_report.json
```

### Optional Flags

**Output & Configuration:**
- `-o`, `--output FILE` – Save results to JSON file
  - Example: `python malakai.py example.com -o results.json`

**Module Selection:**
- `--module {domain|subdomains|dns|whois|geo}` – Run specific module only
  - Example: `python malakai.py example.com --module dns`

**SSL/TLS Analysis:**
- `--ssl` – Enable SSL/TLS certificate analysis
  - Example: `python malakai.py example.com --ssl`
- `--ssl-ports PORT [PORT ...]` – Custom SSL ports (default: 443, 8443, 9443)
  - Example: `python malakai.py example.com --ssl --ssl-ports 443 8443 3000`

**Network Reconnaissance:**
- `--network` – Enable network reconnaissance (Nmap + Shodan)
  - Example: `python malakai.py example.com --network`
  - Requires: Nmap installed (optional) + Shodan API key in config.py
- `--nmap-args ARGS` – Custom Nmap arguments (default: "-sV --script vuln -A")
  - Example: `python malakai.py 192.168.1.1 --network --nmap-args "-sS -p 1-65535"`
  - Common args: `-sV` (service version), `-A` (aggressive), `--script vuln` (vulnerability scripts)

**Analysis Options:**
- `--ai` – Enable AI-powered analysis and insights
  - Example: `python malakai.py example.com --ai`

## Nmap Cheat Sheet (Integrated)

Below is an extended, AI-friendly Nmap command list. Malakai's AI recognizes several `run <alias> <target>` shortcuts — for example: `run ping-scan example.com` will execute `nmap -sn example.com` (after confirmation).

```text
============================================================
CUSTOM NMAP COMMANDS (AI-FRIENDLY) - EXTENDED EDITION
============================================================

BASIC SCANS & DISCOVERY

run basic-scan <target> # nmap <target>
run verbose-scan <target> # nmap -v <target>
run discovery-only <target> # nmap -sn -PE -PS22,80,443 <target>
run arp-discovery <target> # nmap -sn -PR <target>
run traceroute-scan <target> # nmap -sn --traceroute <target>

HOST DISCOVERY ADVANCED

run ping-scan <target> # nmap -sn <target>
run no-ping-scan <target> # nmap -Pn <target>
run no-dns-scan <target> # nmap -n <target>
run dns-only-scan <target> # nmap -sL <target>
run tcp-ping <target> # nmap -sn -PS <target>
run udp-ping <target> # nmap -sn -PU <target>
run ipv6-scan <target> # nmap -6 <target>

PORT SCANNING OPTIONS

run web-ports <target> # nmap -p 80,443,8080,8443 <target>
run full-port-range <target> # nmap -p 1-65535 <target>
run all-ports <target> # nmap -p- <target>
run top-100 <target> # nmap --top-ports 100 <target>
run top-1000 <target> # nmap --top-ports 1000 <target>
run service-ports <service> # nmap -p <service> <target>
run exclude-ports <target> # nmap --exclude-ports <ports> <target>
run port-ratio <target> # nmap --min-rate 1000 --max-rate 5000 <target>

SCAN TYPES ENHANCED

run stealth-syn <target> # nmap -sS <target>
run tcp-connect <target> # nmap -sT <target>
run udp-scan <target> # nmap -sU <target>
run ack-scan <target> # nmap -sA <target>
run window-scan <target> # nmap -sW <target>
run maimon-scan <target> # nmap -sM <target>
run fin-scan <target> # nmap -sF <target>
run null-scan <target> # nmap -sN <target>
run xmas-scan <target> # nmap -sX <target>
run idle-scan <zombie> <target> # nmap -sI <zombie> <target>
run version-scan <target> # nmap -sV <target>
run version-intensity <target> # nmap -sV --version-intensity 9 <target>
run os-detect <target> # nmap -O <target>
run os-intensity <target> # nmap -O --osscan-guess <target>
run aggressive-scan <target> # nmap -A <target>
run banner-grab <target> # nmap -sV --script=banner <target>

TIMING & PERFORMANCE

run paranoid-scan <target> # nmap -T0 <target>
run sneaky-scan <target> # nmap -T1 <target>
run polite-scan <target> # nmap -T2 <target>
run normal-scan <target> # nmap -T3 <target>
run fast-scan <target> # nmap -T4 <target>
run insane-scan <target> # nmap -T5 <target>
run min-parallelism <target> # nmap --min-parallelism 100 <target>
run max-parallelism <target> # nmap --max-parallelism 256 <target>
run min-rate <target> # nmap --min-rate 1000 <target>
run max-rate <target> # nmap --max-rate 5000 <target>
run scan-delay <target> # nmap --scan-delay 2s <target>
run max-retries <target> # nmap --max-retries 2 <target>

COMBINED SCANS & PROFILES

run default-scripts <target> # nmap -sC -sV <target>
run aggressive-all-ports <target> # nmap -A -p- <target>
run full-stealth-os-fast <target> # nmap -sS -sV -O -p- -T4 <target>
run comprehensive-scan <target> # nmap -sS -sV -O -A -p- <target>
run quick-tcp <target> # nmap -T4 -F <target>
run quick-udp <target> # nmap -sU -T4 -F <target>
run top-ports-aggressive <target> # nmap -A --top-ports 100 <target>

OUTPUT FORMATS EXTENDED

run output-normal <target> # nmap -oN results.txt <target>
run output-xml <target> # nmap -oX results.xml <target>
run output-gnmap <target> # nmap -oG results.gnmap <target>
run output-all <target> # nmap -oA results <target>
run append-output <target> # nmap -oN results.txt --append-output <target>
run stylesheet-xml <target> # nmap -oX results.xml --stylesheet stylesheet.xsl <target>
run web-xml <target> # nmap -oX - --webxml <target>
run no-stylesheet <target> # nmap -oX results.xml --no-stylesheet <target>
run verbose-output <target> # nmap -vv -oN results.txt <target>
run grepable-output <target> # nmap -oG - <target> | grep open

NSE SCRIPTING EXTENDED

run vuln-scan <target> # nmap --script vuln <target>
run exploit-scan <target> # nmap --script exploit <target>
run safe-scripts <target> # nmap --script safe <target>
run http-enum <target> # nmap --script http-enum <target>
run dns-brute <target> # nmap --script dns-brute <target>
run smb-enum <target> # nmap --script smb-enum* <target>
run smb-vuln <target> # nmap --script smb-vuln* <target>
run ftp-anon <target> # nmap --script ftp-anon -p 21 <target>
run ssh-auth <target> # nmap --script ssh-auth-methods -p 22 <target>
run ssh-hostkey <target> # nmap --script ssh-hostkey -p 22 <target>
run ssl-enum <target> # nmap --script ssl-enum-ciphers -p 443 <target>
run sql-injection <target> # nmap --script http-sql-injection <target>
run xss-scan <target> # nmap --script http-xssed <target>
run dir-scan <target> # nmap --script http-directory-scanner <target>
run whois-info <target> # nmap --script whois-ip <target>
run vulscan-database <target> # nmap -sV --script vulscan/vulscan.nse <target>
run malware-scan <target> # nmap --script malware-detection <target>
run all-http-scripts <target> # nmap --script "http-*" <target>
run script-category <category> # nmap --script "<category>" <target>
run script-trace <target> # nmap --script-trace <target>
run script-debug <target> # nmap --script --script-args unsafe=1 <target>
run custom-script <script> # nmap --script <script> <target>

TARGET SPECIFICATION

run ip-range <range> # nmap <start-ip>-<end-ip>
run cidr-scan <cidr> # nmap <network>/<mask>
run targets-from-file <file> # nmap -iL <file>
run exclude-targets <target> # nmap --exclude <hosts> <target>
run exclude-file <file> # nmap --excludefile <file> <target>
run random-targets <num> # nmap -iR <num>
run list-scan <target> # nmap -sL <target>

EVASION & STEALTH TECHNIQUES

run packet-fragment <target> # nmap -f <target>
run data-length <target> # nmap --data-length <size> <target>
run decoy-scan <target> # nmap -D <decoy1>,<decoy2>,<me> <target>
run random-decoys <target> # nmap -D RND:5 <target>
run spoofed-source-port <target> # nmap --source-port <port> <target>
run spoofed-mac <target> # nmap --spoof-mac <mac> <target>
run random-mac <target> # nmap --spoof-mac 0 <target>
run ttl-evasions <target> # nmap --ttl <value> <target>
run bad-checksum <target> # nmap --badsum <target>
run proxy-scan <proxy> <target> # nmap -sT -Pn --proxies <proxy> <target>
run ip-options <options> # nmap --ip-options <options> <target>
run mtu-discovery <target> # nmap --mtu <value> <target>
run send-eth <target> # nmap --send-eth <target>
run send-ip <target> # nmap --send-ip <target>

SERVICE DETECTION

run version-all <target> # nmap -sV --version-all <target>
run version-light <target> # nmap -sV --version-light <target>
run version-intensity <level> # nmap -sV --version-intensity <0-9> <target>
run rpc-scan <target> # nmap -sR <target>
run ssl-cert <target> # nmap -sV --script ssl-cert -p 443 <target>
run service-info <target> # nmap -sV --script service-info <target>

FIREWALL DETECTION

run firewall-detection <target> # nmap -sA -p <ports> <target>
run firewall-bypass <target> # nmap -f -D RND:10 --data-length 24 <target>
run ftp-bounce <proxy> <target> # nmap -b <proxy> <target>

ADVANCED TECHNIQUES

run idle-scan-detailed <zombie> # nmap -sI <zombie> -Pn -p 1-65535 <target>
run sctp-scan <target> # nmap -sY <target>
run ip-protocol-scan <target> # nmap -sO <target>
run tcp-scan-flags <flags> # nmap --scanflags <flags> <target>
run traceroute-detail <target> # nmap --traceroute --max-ttl 30 <target>

USEFUL MIXED EXAMPLES

run web-vuln-scan <target> # nmap --script vuln -p 80,443,8080,8443 <target>
run ssl-cipher-scan <target> # nmap --script ssl-enum-ciphers -p 443 <target>
run http-vuln-scan <target> # nmap --script http-enum,http-vuln* -p 80,443 <target>
run ssh-bruteforce <target> # nmap --script ssh-brute -p 22 <target>
run quiet-scan <target> # nmap -sT -p- --top-ports 50 -T3 <target>
run mega-vuln-scan <target> # nmap -A -sV --script vuln -T4 <target>
run network-sweep <network> # nmap -sn -T4 -oG sweep.txt <network>/24
run full-web-audit <target> # nmap -sV --script "http-* and not (brute or dos)" -p 80,443,8080,8443 <target>
run db-servers-scan <target> # nmap -sV --script "mysql-* or postgresql-* or mssql-*" -p 3306,5432,1433 <target>
run mail-servers-scan <target> # nmap -sV --script "smtp-* or pop3-* or imap-*" -p 25,110,143,465,587,993,995 <target>
run all-tcp-udp-top100 <target> # nmap -sU -sS --top-ports 100 -T4 <target>

SCRIPT ARGUMENTS & CUSTOMIZATION

run script-with-args <target> # nmap --script <script> --script-args <args> <target>
run http-user-agent <target> # nmap --script http-headers --script-args http.useragent="CustomAgent" <target>
run brute-threads <target> # nmap --script <brute-script> --script-args userdb=users.txt,passdb=pass.txt,brute.threads=10 <target>
run vulscan-db <database> # nmap -sV --script vulscan --script-args vulscandb=<database>.csv <target>

LOGGING & DEBUGGING

run debug-scan <target> # nmap -d <target>
run debug-level <level> # nmap -d<level> <target>
run packet-trace <target> # nmap --packet-trace <target>
run reason-output <target> # nmap --reason <target>
run open-ports-only <target> # nmap --open <target>
run interface-list # nmap --iflist
run no-gui <target> # nmap --nogui <target>

PERFORMANCE PROFILES

run stealthy-profile <target> # nmap -T2 -f --max-parallelism 1 --scan-delay 5s <target>
run normal-profile <target> # nmap -T3 --max-retries 2 --min-rate 1000 <target>
run aggressive-profile <target> # nmap -T4 --max-retries 0 --min-rate 5000 <target>
run insane-profile <target> # nmap -T5 --max-retries 0 --min-rate 10000 <target>

============================================================
QUICK REFERENCE - COMMON SCENARIOS
============================================================

Initial Reconnaissance:
run network-sweep 192.168.1.0/24
run discovery-only <target>

Full Port Enumeration:
run aggressive-all-ports <target>
run full-stealth-os-fast <target>

Web Application Testing:
run full-web-audit <target>
run web-vuln-scan <target>

Service Enumeration:
run default-scripts <target>
run service-info <target>

Vulnerability Assessment:
run mega-vuln-scan <target>
run vuln-scan <target>

Stealth Scanning:
run stealthy-profile <target>
run idle-scan <zombie-ip> <target>

Firewall Testing:
run firewall-detection <target>
run ack-scan <target>

Quick Checks:
run top-100 <target>
run fast-scan <target>

============================================================
TIPS & BEST PRACTICES
============================================================

Always start with host discovery (-sn) to identify live hosts

Use -sC -sV for initial service enumeration

For comprehensive scans, use -p- with -A

Adjust timing (-T) based on network conditions

Use --script-trace for debugging NSE scripts

Always save output with -oA for multiple formats

Consider network impact when using aggressive scans

Use --exclude to avoid scanning unintended targets

For production environments, start with conservative timing

Always have proper authorization before scanning

============================================================
END OF EXTENDED CUSTOM COMMAND LIST
============================================================
```

How to use these with Malakai
-----------------------------
- Pass any of the above Nmap templates with `--nmap-args`.
  Example: `python malakai.py example.com --network --nmap-args "-sS -sV -p 1-65535 -T4"`

- If you only want passive (Shodan) results, run `--network` without Nmap installed or set: `python malakai.py 8.8.8.8 --network` (Shodan-only behavior).

- Recommended safe defaults for discovery:
  - Quick discovery: `--nmap-args "--top-ports 100 -sV -T4"`
  - Full audit (use with consent): `--nmap-args "-A --script vuln -p- -T4"`

Security & Ethics Reminder
-------------------------
Always have explicit authorization before actively scanning systems you don't own. Use aggressive scans (`-A`, `-p-`, `-T5`, `--script vuln`) only with permission.

## Limitations & Notes

- **Rate Limiting** – Some APIs have rate limits; add credentials for higher limits
- **Subdomain Discovery** – DNS bruteforce limited to common patterns; CT logs provide broader coverage
- **Real-time Only** – Historical tracking requires external service integration (SecurityTrails, Shodan)
- **Large Subdomain Lists** – No truncation for display
- **WHOIS Accuracy** – Varies by TLD and registrar
- **Nmap Requirement** – Network scanning works without Nmap (Shodan-only), but full features require it
- **API Keys** – Configure Shodan and VirusTotal keys in config.py for best results

## Future Enhancements

- Phishing/typosquatting detection using edit-distance algorithms
- Entity graph construction (domains↔IPs↔ASNs↔registrants)
- Community detection for infrastructure clustering
- Historical baseline anomaly detection
- Integration with VirusTotal, AbuseIPDB, Censys

## Contributing

Improvements, bug reports, and feature requests are welcome!

## License

MIT License

VirusTotal API: 61ac0b0db884b1339ec1633225d9c59dfa8b7ee9033886bee59fdb78fcda63bd
Shodan API: WyQUaaBx3HPi6C7cbZ8FESyyUS7EjmjF