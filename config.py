"""
Configuration file for Malakai-OSINT
API keys and settings for threat intelligence integration
"""

# Shodan API Configuration
SHODAN_API_KEY = "WyQUaaBx3HPi6C7cbZ8FESyyUS7EjmjF"
SHODAN_BASE_URL = "https://api.shodan.io"

# VirusTotal API Configuration
VIRUSTOTAL_API_KEY = "61ac0b0db884b1339ec1633225d9c59dfa8b7ee9033886bee59fdb78fcda63bd"
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"

# Have I Been Pwned API Configuration
HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
HIBP_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Request Configuration
REQUEST_TIMEOUT = 10
REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

# Rate Limiting
RATE_LIMIT_DELAY = 0.55  # seconds between API calls
SHODAN_RATE_LIMIT = 1.0  # seconds between Shodan calls
VIRUSTOTAL_RATE_LIMIT = 0.2  # seconds between VirusTotal calls

# Feature Flags
ENABLE_SHODAN = True
ENABLE_VIRUSTOTAL = True
ENABLE_HIBP = True
ENABLE_SSL_ANALYSIS = True
ENABLE_EMAIL_ENUM = True
ENABLE_DNSSEC_VALIDATION = True

# Output Configuration
MAX_DISPLAY_ITEMS = None  # None = show all (no truncation)
JSON_INDENT = 2

# IP Geolocation Services
IPAPI_TIMEOUT = 10
IPAPI_RETRIES = 2

# DNS Configuration
DNS_TIMEOUT = 10
NAMESERVER_TIMEOUT = 5

# Optional OpenAI configuration for AI chat (set your API key here or via env var)
OPENAI_API_KEY = None
OPENAI_MODEL = "gpt-4o-mini"
OPENAI_TEMPERATURE = 0.2
