"""
config.py — PhishIntelix Configuration
Sensitive values are loaded from environment variables on the server.
"""
import os

# ── Email (contact form) ──
CONTACT_EMAIL      = os.environ.get('CONTACT_EMAIL', 'phishintelix@gmail.com')
GMAIL_APP_PASSWORD = os.environ.get('GMAIL_APP_PASSWORD', '')

# ── VirusTotal ──
VT_API_KEY = os.environ.get('VT_API_KEY', '')

# ── Google Safe Browsing ──
GSB_API_KEY = os.environ.get('GSB_API_KEY', '')

# ── Site identity ──
SITE_NAME      = 'PhishIntelix'
AUTHOR_NAME    = 'Jagadish Ray'
AUTHOR_EMAIL   = 'phishintelix@gmail.com'
GITHUB_URL     = 'https://github.com/jagadish-ray'
LINKEDIN_URL   = 'https://www.linkedin.com/in/jagadish-ray-6536a5290/'
COPYRIGHT_YEAR = '2026'

# ── Admin ──
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'PhishIntelix@2026')
