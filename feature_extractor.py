"""
feature_extractor.py
---------------------
Turns a raw URL into the numeric feature vector used by the ML model,
and also runs a set of extra heuristic checks ("red flags") that are
common in real-world phishing detectors but aren't part of the
training data. The heuristic flags are combined with the ML score
in app.py for a hybrid verdict.
"""

import re
from urllib.parse import urlparse

# Order matters: must match the columns in dataset.csv (minus 'label')
FEATURE_ORDER = ['length', 'dots', 'https', 'has_ip', 'has_at', 'subdomains', 'suspicious_word']

SUSPICIOUS_WORDS = [
    'login', 'verify', 'account', 'update', 'secure', 'confirm',
    'banking', 'signin', 'sign-in', 'password', 'webscr', 'ebayisapi',
    'security', 'suspend', 'recover', 'unlock', 'support', 'invoice',
    'payment', 'wallet', 'reset', 'authenticat'
]

# Free / cheap TLDs that are disproportionately abused for throwaway
# phishing domains.
SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.club', '.work', '.click', '.loan', '.tk', '.ml',
    '.ga', '.cf', '.gq', '.download', '.win', '.bid', '.men', '.kim'
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bl.ink', 'rebrand.ly', 'cutt.ly', 'shorte.st'
]

# A small set of frequently-impersonated brands for typosquatting checks.
POPULAR_BRANDS = [
    'google', 'facebook', 'paypal', 'amazon', 'microsoft', 'apple',
    'netflix', 'instagram', 'twitter', 'whatsapp', 'bankofamerica',
    'chase', 'wellsfargo', 'ebay', 'linkedin', 'outlook', 'icloud',
    'dropbox', 'github', 'yahoo'
]

IP_PATTERN = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')


def _levenshtein(a, b):
    """Plain Levenshtein edit distance, no extra dependencies."""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


def _normalize(url):
    url = url.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', url):
        return 'http://' + url
    return url


def extract_features(raw_url):
    """
    Returns (ml_features: dict, flags: list[str])

    ml_features  -> the 7 numeric columns the model was trained on,
                     computed on the ORIGINAL string the user typed
                     (so length/dots reflect exactly what they entered).
    flags        -> human-readable extra red flags from heuristic checks
                     that go beyond the training data.
    """
    original = raw_url.strip()
    parsed = urlparse(_normalize(original))
    hostname = (parsed.hostname or '').lower()
    netloc = parsed.netloc

    # The training data's 'length'/'dots' columns reflect the domain
    # (scheme + host), not the full URL with path/query. A long but
    # legit path (e.g. github.com/org/repo) would otherwise look like
    # a long suspicious domain, so we measure the authority part only.
    authority = f"{parsed.scheme}://{netloc}" if netloc else original

    # ---- Core ML features (must match dataset.csv columns) ----
    length = len(authority)
    dots = hostname.count('.')
    https = 1 if original.lower().startswith('https://') else 0
    has_ip = 1 if IP_PATTERN.match(hostname) else 0
    has_at = 1 if '@' in netloc else 0
    subdomains = max(dots - 1, 0)
    suspicious_word = 1 if any(w in original.lower() for w in SUSPICIOUS_WORDS) else 0

    ml_features = {
        'length': length,
        'dots': dots,
        'https': https,
        'has_ip': has_ip,
        'has_at': has_at,
        'subdomains': subdomains,
        'suspicious_word': suspicious_word,
    }

    # ---- Extra heuristic red flags (hybrid scoring layer) ----
    flags = []

    if has_ip:
        flags.append("Hostname is a raw IP address instead of a domain name")

    if has_at:
        flags.append("Contains '@' \u2014 browsers ignore everything before it, a common cloaking trick")

    host_parts = hostname.split('.') if hostname else []
    tld = '.' + host_parts[-1] if len(host_parts) >= 2 else ''
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"Uses an uncommon top-level domain ({tld}) frequently abused for throwaway domains")

    if any(short in hostname for short in URL_SHORTENERS):
        flags.append("This is a shortened link \u2014 the real destination is hidden")

    if not https:
        flags.append("No HTTPS encryption")

    if length > 75:
        flags.append("Unusually long URL \u2014 may be hiding the real destination")

    if hostname.count('-') >= 2:
        flags.append("Multiple hyphens in the domain, common in fake brand domains")

    if subdomains >= 3:
        flags.append("Excessive subdomains \u2014 may be disguising the true domain")

    # Typosquatting: compare the main domain label against popular brands
    if len(host_parts) >= 2:
        domain_root = host_parts[-2]
        for brand in POPULAR_BRANDS:
            if domain_root == brand:
                break
            dist = _levenshtein(domain_root, brand)
            if 0 < dist <= 2 and abs(len(domain_root) - len(brand)) <= 2:
                flags.append(f"Domain resembles '{brand}' \u2014 possible typosquatting")
                break

    if parsed.port and parsed.port not in (80, 443):
        flags.append(f"Uses a non-standard port ({parsed.port})")

    return ml_features, flags
