"""
advanced_checks.py
-------------------
Five advanced threat-detection modules for PhishIntelix:

  1. URL parameter analysis       (open redirects, encoded hidden URLs)
  2. Hidden link detection        (anchor mismatch, shorteners, masked links)
  3. Domain & SSL verification    (cert validity, domain age, homographs)
  4. Email content analysis       (urgent keywords, fake sender, attachments)
  5. Blacklist & reputation check (VirusTotal API + local blacklist)

Each check returns a list of Finding namedtuples:
    Finding(category, severity, message)
    severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

Usage:
    from advanced_checks import run_all_checks
    findings, summary = run_all_checks(url, vt_api_key="YOUR_KEY")
"""

import re, ssl, socket, base64, unicodedata, datetime, hashlib
from urllib.parse import urlparse, parse_qs, unquote, unquote_plus
from collections import namedtuple
import requests

Finding = namedtuple('Finding', ['category', 'severity', 'message'])

# ─────────────────────────────────────────────
# Shared constants
# ─────────────────────────────────────────────
REDIRECT_PARAMS = [
    'redirect', 'redirect_uri', 'redirect_url', 'url', 'next', 'goto',
    'return', 'returnurl', 'return_url', 'target', 'dest', 'destination',
    'forward', 'rurl', 'continue', 'link', 'out', 'view', 'to', 'ref'
]

URL_SHORTENERS = [
    'bit.ly','tinyurl.com','goo.gl','t.co','ow.ly','is.gd','buff.ly',
    'adf.ly','bl.ink','rebrand.ly','cutt.ly','shorte.st','tiny.cc',
    'cli.gs','su.pr','snipurl.com','short.to','budurl.com','ping.fm'
]

SUSPICIOUS_TLDS = [
    '.xyz','.top','.club','.work','.click','.loan','.tk','.ml',
    '.ga','.cf','.gq','.download','.win','.bid','.men','.kim',
    '.cc','.pw','.su','.ws','.to','.biz'
]

POPULAR_BRANDS = [
    'google','facebook','paypal','amazon','microsoft','apple','netflix',
    'instagram','twitter','whatsapp','bankofamerica','chase','wellsfargo',
    'ebay','linkedin','outlook','icloud','dropbox','github','yahoo',
    'spotify','adobe','steam','coinbase','binance','metamask'
]

URGENT_KEYWORDS = [
    'urgent','immediately','verify now','act now','suspended','locked',
    'unusual activity','confirm your','click here','limited time',
    'expire','your account','you have won','congratulations','free gift',
    'update your','security alert','warning','action required',
    'final notice','last chance','24 hours','48 hours','response required'
]

SOCIAL_ENGINEERING = [
    'dear customer','dear user','dear valued','we have noticed',
    'we detected','failed to','unable to','unauthorized access',
    'we need you to','kindly provide','kindly click','please verify',
    'sign in to continue','your information','personal details'
]

SUSPICIOUS_ATTACHMENTS = [
    '.exe','.bat','.cmd','.vbs','.js','.jar','.scr','.ps1',
    '.msi','.pif','.com','.hta','.wsf','.reg','.dll'
]

LOCAL_BLACKLIST = {
    'paypal-security-check.xyz','amazon-verify-login.cc',
    'update-banking-now.net','secure-microsoft-auth.xyz',
    'fake-gmail-login.cc','account-suspended-apple.tk',
    'wellsfargo-alert-login.xyz','verify-paypa1-now.cc',
    'support-netflix-billing.net','secure-login-bankofamerica.xyz',
    'chase-secure-update.tk','apple-id-verify.cc',
    'microsoft-support-alert.xyz','amazon-order-problem.tk'
}

IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

def _normalize(url):
    url = url.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', url):
        return 'http://' + url
    return url


# ─────────────────────────────────────────────
# 1. URL PARAMETER ANALYSIS
# ─────────────────────────────────────────────
def _try_decode_b64(s):
    """Try to base64-decode a string, return decoded or None."""
    try:
        # Pad if needed
        padded = s + '=' * (-len(s) % 4)
        decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
        if decoded.startswith(('http', 'www', '//')):
            return decoded
    except Exception:
        pass
    return None


def _is_url(s):
    return bool(re.match(r'https?://', s) or re.match(r'www\.', s))


def check_url_parameters(url):
    findings = []
    parsed = urlparse(_normalize(url))
    params = parse_qs(parsed.query, keep_blank_values=True)

    for key, values in params.items():
        for val in values:
            key_lower = key.lower()

            # Open redirect parameter names
            if key_lower in REDIRECT_PARAMS:
                findings.append(Finding('URL Parameters', 'HIGH',
                    f"Open redirect parameter '{key}' detected — value could redirect to a malicious site"))

                # Does the value look like a URL?
                decoded_val = unquote(val)
                if _is_url(decoded_val):
                    findings.append(Finding('URL Parameters', 'HIGH',
                        f"Parameter '{key}' contains an embedded URL: {decoded_val[:80]}"))

            # Percent encoding / double encoding
            if '%' in val:
                once = unquote(val)
                twice = unquote(once)
                if once != val:
                    findings.append(Finding('URL Parameters', 'MEDIUM',
                        f"Parameter '{key}' uses percent-encoding (possible obfuscation)"))
                if twice != once:
                    findings.append(Finding('URL Parameters', 'HIGH',
                        f"Parameter '{key}' uses double percent-encoding — common evasion technique"))

            # Base64 encoded value
            b64 = _try_decode_b64(val)
            if b64:
                findings.append(Finding('URL Parameters', 'HIGH',
                    f"Parameter '{key}' appears base64-encoded, decodes to: {b64[:80]}"))

            # Hex encoding (%xx patterns covering most of the value)
            hex_ratio = len(re.findall(r'%[0-9a-fA-F]{2}', val)) / max(len(val), 1)
            if hex_ratio > 0.3:
                findings.append(Finding('URL Parameters', 'MEDIUM',
                    f"Parameter '{key}' is heavily hex-encoded ({int(hex_ratio*100)}% encoded chars)"))

    # Data URI in URL
    if 'data:' in url.lower():
        findings.append(Finding('URL Parameters', 'HIGH',
            "Data URI detected in URL — can be used to embed malicious HTML/JS"))

    # JavaScript URI
    if re.search(r'javascript\s*:', url, re.IGNORECASE):
        findings.append(Finding('URL Parameters', 'HIGH',
            "JavaScript URI scheme detected — classic XSS/phishing vector"))

    return findings


# ─────────────────────────────────────────────
# 2. HIDDEN LINK DETECTION
# ─────────────────────────────────────────────
def check_hidden_links(url):
    findings = []
    parsed = urlparse(_normalize(url))
    hostname = (parsed.hostname or '').lower()

    # URL shortener
    if any(s in hostname for s in URL_SHORTENERS):
        findings.append(Finding('Hidden Links', 'HIGH',
            f"URL shortener detected ({hostname}) — real destination is concealed"))

    # Fragment-based redirection
    if parsed.fragment and _is_url(unquote(parsed.fragment)):
        findings.append(Finding('Hidden Links', 'HIGH',
            "URL fragment (#) contains another URL — possible redirect hiding technique"))

    # Userinfo (user:pass@host)
    if parsed.username or '@' in (parsed.netloc or ''):
        findings.append(Finding('Hidden Links', 'HIGH',
            "URL contains userinfo (user@host) — browsers display only the part before @, "
            "hiding the real host"))

    # Extremely long path (link padding)
    if len(parsed.path) > 120:
        findings.append(Finding('Hidden Links', 'MEDIUM',
            f"Unusually long URL path ({len(parsed.path)} chars) — may be padding to hide destination"))

    # Multiple redirects chained in query string
    redirect_count = sum(1 for k in parse_qs(parsed.query) if k.lower() in REDIRECT_PARAMS)
    if redirect_count >= 2:
        findings.append(Finding('Hidden Links', 'HIGH',
            f"Multiple redirect parameters ({redirect_count}) in URL — chained redirect attack"))

    # Null bytes / invisible characters
    if '\x00' in url or '\u200b' in url or '\u00ad' in url:
        findings.append(Finding('Hidden Links', 'HIGH',
            "Null byte or invisible Unicode character in URL — evasion technique"))

    return findings


# ─────────────────────────────────────────────
# 3. DOMAIN & SSL VERIFICATION
# ─────────────────────────────────────────────
def _levenshtein(a, b):
    if a == b: return 0
    if not a: return len(b)
    if not b: return len(a)
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0]*len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+(0 if ca==cb else 1))
        prev = cur
    return prev[-1]


def _is_homograph(domain):
    """Detect Unicode homograph: domain has non-ASCII chars that look like ASCII."""
    try:
        domain.encode('ascii')
        return False  # pure ASCII, no homograph
    except UnicodeEncodeError:
        pass
    # Try to find look-alike: normalize to NFKD and compare
    normalized = unicodedata.normalize('NFKD', domain).encode('ascii', 'ignore').decode()
    return normalized != domain and normalized != ''


def check_ssl_domain(url):
    findings = []
    parsed = urlparse(_normalize(url))
    hostname = (parsed.hostname or '').lower()
    host_parts = hostname.split('.') if hostname else []

    # ── SSL certificate check ──
    if url.lower().startswith('https://') and hostname and not IP_RE.match(hostname):
        try:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(
                socket.create_connection((hostname, 443), timeout=5),
                server_hostname=hostname
            )
            cert = conn.getpeercert()
            conn.close()

            # Expiry
            expire_str = cert.get('notAfter', '')
            if expire_str:
                exp_date = datetime.datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
                days_left = (exp_date - datetime.datetime.utcnow()).days
                if days_left < 0:
                    findings.append(Finding('SSL / Domain', 'HIGH',
                        f"SSL certificate has EXPIRED ({abs(days_left)} days ago)"))
                elif days_left < 14:
                    findings.append(Finding('SSL / Domain', 'HIGH',
                        f"SSL certificate expires in {days_left} days — very soon"))
                elif days_left < 60:
                    findings.append(Finding('SSL / Domain', 'MEDIUM',
                        f"SSL certificate expires in {days_left} days"))
                else:
                    findings.append(Finding('SSL / Domain', 'INFO',
                        f"SSL certificate valid for {days_left} more days"))

            # Issuer
            issuer = dict(x[0] for x in cert.get('issuer', []))
            org = issuer.get('organizationName', 'Unknown')
            findings.append(Finding('SSL / Domain', 'INFO',
                f"SSL certificate issued by: {org}"))

            # Self-signed (issuer == subject)
            subject = dict(x[0] for x in cert.get('subject', []))
            if issuer.get('commonName') == subject.get('commonName'):
                findings.append(Finding('SSL / Domain', 'HIGH',
                    "Self-signed SSL certificate — not trusted by browsers"))

        except ssl.SSLCertVerificationError:
            findings.append(Finding('SSL / Domain', 'HIGH',
                "SSL certificate is INVALID or untrusted"))
        except ssl.CertificateError as e:
            findings.append(Finding('SSL / Domain', 'HIGH',
                f"SSL certificate error: {str(e)[:80]}"))
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
            findings.append(Finding('SSL / Domain', 'MEDIUM',
                "Could not connect to verify SSL certificate (timeout or unreachable)"))
    elif not url.lower().startswith('https://'):
        findings.append(Finding('SSL / Domain', 'HIGH',
            "No HTTPS — connection is unencrypted"))

    # ── Domain age via WHOIS ──
    if hostname and not IP_RE.match(hostname):
        try:
            import whois as whois_lib
            w = whois_lib.whois(hostname)
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if created:
                if isinstance(created, str):
                    created = datetime.datetime.strptime(created[:10], '%Y-%m-%d')
                age_days = (datetime.datetime.utcnow() - created).days
                if age_days < 30:
                    findings.append(Finding('SSL / Domain', 'HIGH',
                        f"Domain registered only {age_days} days ago — very new, high risk"))
                elif age_days < 180:
                    findings.append(Finding('SSL / Domain', 'MEDIUM',
                        f"Domain registered {age_days} days ago ({age_days//30} months) — relatively new"))
                else:
                    findings.append(Finding('SSL / Domain', 'INFO',
                        f"Domain age: {age_days//365}y {(age_days%365)//30}m — established domain"))
        except Exception:
            findings.append(Finding('SSL / Domain', 'INFO',
                "Could not retrieve WHOIS domain age (may be private or unavailable)"))

    # ── IP address as hostname ──
    if hostname and IP_RE.match(hostname):
        findings.append(Finding('SSL / Domain', 'HIGH',
            "Raw IP address used as hostname — legitimate sites use domain names"))

    # ── Homograph attack ──
    if hostname and _is_homograph(hostname):
        findings.append(Finding('SSL / Domain', 'HIGH',
            f"Unicode homograph detected in domain '{hostname}' — look-alike character attack"))

    # ── Typosquatting / misspelled brand ──
    root = host_parts[-2] if len(host_parts) >= 2 else hostname
    for brand in POPULAR_BRANDS:
        if root == brand:
            break
        dist = _levenshtein(root, brand)
        if 0 < dist <= 2 and abs(len(root)-len(brand)) <= 2:
            findings.append(Finding('SSL / Domain', 'HIGH',
                f"Domain '{root}' closely resembles brand '{brand}' (edit distance={dist}) — possible typosquatting"))
            break

    # ── Suspicious TLD ──
    tld = '.' + host_parts[-1] if host_parts else ''
    if tld in SUSPICIOUS_TLDS:
        findings.append(Finding('SSL / Domain', 'MEDIUM',
            f"Suspicious TLD '{tld}' — frequently used for throwaway phishing domains"))

    # ── Excessive subdomains ──
    subdomain_count = len(host_parts) - 2 if len(host_parts) > 2 else 0
    if subdomain_count >= 3:
        findings.append(Finding('SSL / Domain', 'MEDIUM',
            f"{subdomain_count} subdomains detected — may be disguising the real domain"))

    return findings


# ─────────────────────────────────────────────
# 4. EMAIL CONTENT ANALYSIS
# ─────────────────────────────────────────────
def check_email_content(text, sender_email=None, vt_api_key=None, gsb_api_key=None):
    """Full email analysis - 10 detection layers."""
    findings = []
    text_lower = text.lower()

    # 1. Urgent keywords
    found_urgent = [kw for kw in URGENT_KEYWORDS if kw in text_lower]
    if len(found_urgent) >= 3:
        findings.append(Finding('Urgency Detection', 'HIGH',
            "High urgency language ({} triggers): {}".format(len(found_urgent), ', '.join(found_urgent[:5]))))
    elif found_urgent:
        findings.append(Finding('Urgency Detection', 'MEDIUM',
            "Urgency keyword(s): {}".format(', '.join(found_urgent))))

    # 2. Social engineering
    social_cats = {
        'Fear':      ['your account will be','permanently suspended','unauthorized access','security breach','account has been locked'],
        'Urgency':   ['within 24 hours','within 48 hours','act now','last chance','expires today','final notice'],
        'Authority': ['your bank','irs notice','legal action','government notice','microsoft support','official notice'],
        'Reward':    ['you have won','congratulations','claim your prize','free gift','selected winner'],
        'Curiosity': ['pending delivery','your package','new voicemail','you have a pending'],
        'Trust':     ['we have noticed','we detected','kindly verify','kindly provide','please confirm'],
    }
    for cat, patterns in social_cats.items():
        found = [p for p in patterns if p in text_lower]
        if found:
            sev = 'HIGH' if cat in ('Fear', 'Authority') else 'MEDIUM'
            findings.append(Finding('Social Engineering', sev,
                "{} pattern: '{}'".format(cat, found[0])))

    # 3a. Context-aware email phrase mistakes
    EMAIL_CONTEXT_MISTAKES = {
        'deer customer':     'dear customer',
        'deer user':         'dear user',
        'deer valued':       'dear valued',
        'deer sir':          'dear sir',
        'deer madam':        'dear madam',
        'deer client':       'dear client',
        'deer member':       'dear member',
        'deer account':      'dear account',
        'form your account': 'from your account',
        'form our team':     'from our team',
        'form the team':     'from the team',
        'bellow link':       'below link',
        'bellow button':     'below button',
        'click bellow':      'click below',
        'visit bellow':      'visit below',
        'kindely':           'kindly',
        'pleese':            'please',
        'immediatly':        'immediately',
        'urgentely':         'urgently',
        'permanantly':       'permanently',
        'tempararily':       'temporarily',
        'acount':            'account',
        'passward':          'password',
        'informaton':        'information',
        'verfy':             'verify',
        'confrm':            'confirm',
        'suspendd':          'suspended',
        'recieve':           'receive',
        'beleive':           'believe',
        'occured':           'occurred',
        'untill':            'until',
        'usally':            'usually',
        'activty':           'activity',
        'securty':           'security',
    }
    context_mistakes = []
    for wrong, correct in EMAIL_CONTEXT_MISTAKES.items():
        if wrong in text_lower:
            context_mistakes.append('"{}" (should be "{}")'.format(wrong, correct))
    if context_mistakes:
        findings.append(Finding('Spelling Check', 'MEDIUM',
            "Context mistake(s) — classic phishing email errors: {}".format(
                ', '.join(context_mistakes[:5]))))

    # 3. Spelling check — ONLY check known phishing misspelling patterns
    # We do NOT use a full dictionary checker on all words because:
    # - Brand names (flipkart, noreply, gmail) get false positives
    # - People names (kumar, suresh, meera) are not in English dictionary
    # - Technical terms (meetup, watchlist) get false positives
    # Instead we ONLY check words that closely resemble common phishing keywords
    PHISHING_KEYWORDS = {
        'account','password','security','update','verify','login','access',
        'suspended','unusual','activity','confirm','information','details',
        'immediately','urgently','required','important','notification',
        'banking','credit','payment','invoice','delivery','tracking',
        'unauthorized','temporarily','restricted','permanently','customer',
        'secure','validate','authenticate','credential','billing',
    }
    try:
        from spellchecker import SpellChecker
        spell = SpellChecker()

        # Clean text — remove URLs, HTML, email addresses
        clean_text = re.sub(r'https?://[^\s]+', ' ', text)
        clean_text = re.sub(r'<[^>]+>', ' ', clean_text)
        clean_text = re.sub(r'\S+@\S+', ' ', clean_text)
        clean_text = re.sub(r'[^a-zA-Z\s]', ' ', clean_text)

        all_words = re.findall(r'[a-zA-Z]+', clean_text)

        # Only check lowercase words (skip proper nouns, brand names, names)
        # A word is only checked if it is ALL lowercase (no capitals at all)
        # This skips: Flipkart, Jagadish, Suresh, Kumar, GitHub, Netflix etc.
        words_lower_only = [w for w in all_words
                            if w == w.lower()  # all lowercase — not a name/brand
                            and len(w) >= 5    # at least 5 chars
                            and w not in PHISHING_KEYWORDS]  # not already correct

        # Only flag if the misspelled word closely resembles a phishing keyword
        misspelled_list = []
        for word in set(words_lower_only):
            for keyword in PHISHING_KEYWORDS:
                dist = _levenshtein(word, keyword)
                if 0 < dist <= 2 and abs(len(word)-len(keyword)) <= 2:
                    correction = spell.correction(word)
                    # Only flag if spell checker also agrees it's wrong
                    if correction and correction != word:
                        misspelled_list.append('"{}" → "{}"'.format(word, keyword))
                        break

        if misspelled_list:
            findings.append(Finding('Spelling Check', 'MEDIUM',
                "Phishing keyword misspelling(s) detected: {}".format(
                    ', '.join(misspelled_list[:5]))))

    except ImportError:
        pass

        # Bigram context check — detect wrong-word-right-spelling errors
        # Build word pairs and check against known correct patterns
        WRONG_BIGRAMS = {
            'deer customer':'dear customer', 'deer user':'dear user',
            'deer sir':'dear sir', 'deer madam':'dear madam',
            'deer valued':'dear valued', 'deer account':'dear account',
            'deer client':'dear client', 'deer member':'dear member',
            'form your':'from your', 'form our':'from our',
            'form the':'from the', 'form us':'from us',
            'click bellow':'click below', 'visit bellow':'visit below',
            'see bellow':'see below', 'listed bellow':'listed below',
            'as bellow':'as below', 'the bellow':'the below',
            'loose your':'lose your', 'loose access':'lose access',
            'their is':'there is', 'their are':'there are',
            'your welcome':'you are welcome', 'your account have':'your account has',
            'we has':'we have', 'i has':'i have',
            'you is':'you are', 'he have':'he has',
            'please to':'please', 'kindely':'kindly',
            'do the needful':'take the necessary action',
            'revert back':'revert', 'return back':'return',
        }
        bigram_errors = []
        text_lower_clean = ' '.join(all_words).lower()
        for wrong, correct in WRONG_BIGRAMS.items():
            if wrong in text_lower_clean:
                bigram_errors.append('"{}" (should be "{}")'.format(wrong, correct))

        if bigram_errors:
            findings.append(Finding('Grammar & Context', 'MEDIUM',
                "Wrong word in context — classic phishing mistake(s): {}".format(
                    ', '.join(bigram_errors[:5]))))

    except ImportError:
        # Fallback if pyspellchecker not installed
        words = re.findall(r'[a-zA-Z]{4,}', text.lower())
        BASIC = {'account','password','security','verify','suspended','immediately','payment'}
        misspelled = []
        for word in set(words):
            for correct in BASIC:
                if word != correct and abs(len(word)-len(correct)) <= 1:
                    if _levenshtein(word, correct) == 1:
                        misspelled.append('"{}" → "{}"'.format(word, correct))
                        break
        if misspelled:
            findings.append(Finding('Spelling Check', 'MEDIUM',
                "Misspelled word(s): {}".format(', '.join(misspelled[:5]))))


    # 4. Shortened links
    import re as _re
    url_pat = _re.compile(r'https?://[^\s"<>)\]]+')
    urls_in_text = list(set(url_pat.findall(text)))
    if urls_in_text:
        findings.append(Finding('Embedded Links', 'INFO',
            "{} URL(s) found in email body".format(len(urls_in_text))))
        for u in urls_in_text[:5]:
            host = (urlparse(u).hostname or '').lower()
            clean_host = host.replace("www.", "")
            if clean_host in URL_SHORTENERS:
                findings.append(Finding('Shortened Link', 'HIGH',
                    "URL shortener in email: {} — real destination hidden".format(u[:70])))

    # 5. Button hidden links
    btn_pat = _re.compile(r'<(?:button|input)[^>]*onclick=[^>]*(?:location|href)[^>]*>', _re.IGNORECASE)
    btns = btn_pat.findall(text)
    if btns:
        findings.append(Finding('Button Hidden Link', 'HIGH',
            "{} button(s) use JavaScript onclick to hide redirect".format(len(btns))))

    # 6. HTML masked links
    anchor_pat = _re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', _re.IGNORECASE | _re.DOTALL)
    for href, anchor_html in anchor_pat.findall(text)[:10]:
        anchor_text = _re.sub(r'<[^>]+>', '', anchor_html).strip()
        h_domain = (urlparse(href).hostname or '').lower()
        if _re.match(r'https?://', anchor_text):
            t_domain = (urlparse(anchor_text).hostname or '').lower()
            if h_domain and t_domain and h_domain != t_domain:
                findings.append(Finding('HTML Masked Link', 'HIGH',
                    "Link shows '{}' but goes to '{}' — phishing mask".format(t_domain, h_domain)))
        deceptive = ['click here','verify now','login here','sign in','confirm here','update now']
        if any(d in anchor_text.lower() for d in deceptive) and href.startswith('http'):
            findings.append(Finding('HTML Masked Link', 'MEDIUM',
                "Deceptive text '{}' hiding: {}".format(anchor_text[:40], href[:60])))

    # 7. Suspicious attachments
    # Remove all URLs, email addresses, and domain names first
    import re as _re2
    text_no_urls = _re2.sub(r'https?://\S+', ' ', text_lower)
    text_no_urls = _re2.sub(r'www\.\S+', ' ', text_no_urls)
    text_no_urls = _re2.sub(r'\S+@\S+', ' ', text_no_urls)  # remove email addresses
    # Remove standalone domain patterns like github.com, paypal.com etc
    text_no_urls = _re2.sub(r'[a-z0-9\-]+\.(com|org|net|io|co|uk|edu|gov)', ' ', text_no_urls)

    # Only flag dangerous extensions that appear as actual filenames
    # Pattern: word characters immediately before extension (e.g. invoice.exe, file.bat)
    REAL_DANGEROUS = ['.exe','.bat','.cmd','.vbs','.js','.jar','.scr',
                      '.ps1','.msi','.pif','.hta','.wsf','.reg','.dll']
    found_ext = []
    for e in REAL_DANGEROUS:
        pattern = r"[a-z0-9_-]{2,}" + _re2.escape(e) + r"(?:\s|$|[,;])"
        if _re2.search(pattern, text_no_urls):
            found_ext.append(e)
    if found_ext:
        findings.append(Finding('Suspicious Attachment', 'HIGH',
            "Dangerous file extension(s): {} — malware risk".format(', '.join(found_ext))))

    # 8. Sender verification
    if sender_email and '@' in sender_email:
        sender_domain = sender_email.split('@')[-1].lower()
        parts = sender_domain.split('.')
        # root = second-to-last part e.g. 'microsoft' from 'teams.microsoft.com'
        root = parts[-2] if len(parts) >= 2 else sender_domain

        # Check brand impersonation — but allow legitimate subdomains
        for brand in POPULAR_BRANDS:
            if brand in sender_domain:
                # If root domain (second-to-last) IS the brand, it's legitimate
                # e.g. teams.MICROSOFT.com, accounts.GOOGLE.com, no-reply.GITHUB.com
                if root == brand:
                    break  # legitimate — skip
                # Also allow direct brand domains
                if sender_domain in (brand+'.com', brand+'.org', brand+'.net'):
                    break  # legitimate
                # Otherwise it's impersonation
                findings.append(Finding('Sender Verification', 'HIGH',
                    "Sender '{}' impersonates '{}' — fake domain".format(sender_domain, brand)))
                break

        # Free email provider check
        free = ['gmail.com','yahoo.com','hotmail.com','outlook.com','aol.com']
        if sender_domain in free:
            findings.append(Finding('Sender Verification', 'MEDIUM',
                "Official email from free provider ({})".format(sender_domain)))

        # Typosquatting on root domain
        for brand in POPULAR_BRANDS:
            if root != brand and 0 < _levenshtein(root, brand) <= 2:
                findings.append(Finding('Sender Verification', 'HIGH',
                    "Sender domain '{}' resembles '{}' — typosquatting".format(root, brand)))
                break

    # 9. VirusTotal
    if vt_api_key and urls_in_text:
        for u in urls_in_text[:3]:
            try:
                headers = {'x-apikey': vt_api_key}
                resp = requests.post('https://www.virustotal.com/api/v3/urls',
                                     headers=headers, data={'url': u}, timeout=8)
                if resp.status_code == 200:
                    aid = resp.json()['data']['id']
                    r2 = requests.get('https://www.virustotal.com/api/v3/analyses/'+aid,
                                      headers=headers, timeout=8)
                    if r2.status_code == 200:
                        stats = r2.json()['data']['attributes']['stats']
                        mal = stats.get('malicious', 0)
                        sus = stats.get('suspicious', 0)
                        total = sum(stats.values())
                        if mal >= 3:
                            findings.append(Finding('VirusTotal', 'HIGH',
                                "URL flagged by {}/{} VT engines: {}".format(mal, total, u[:60])))
                        elif mal > 0 or sus > 0:
                            findings.append(Finding('VirusTotal', 'MEDIUM',
                                "{} malicious, {} suspicious ({} engines): {}".format(mal, sus, total, u[:60])))
                        else:
                            findings.append(Finding('VirusTotal', 'INFO',
                                "URL clean ({} engines): {}".format(total, u[:60])))
            except Exception:
                pass

    # 10. Google Safe Browsing
    if gsb_api_key and urls_in_text:
        try:
            gsb_url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + gsb_api_key
            payload = {
                'client': {'clientId': 'phishintelix', 'clientVersion': '1.0'},
                'threatInfo': {
                    'threatTypes': ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE'],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': u} for u in urls_in_text[:5]],
                }
            }
            r = requests.post(gsb_url, json=payload, timeout=8)
            if r.status_code == 200:
                matches = r.json().get('matches', [])
                if matches:
                    for m in matches[:3]:
                        flagged = m.get('threat', {}).get('url', 'unknown')
                        threat = m.get('threatType', 'UNKNOWN')
                        findings.append(Finding('Google Safe Browsing', 'HIGH',
                            "Flagged [{}]: {}".format(threat, flagged[:60])))
                else:
                    findings.append(Finding('Google Safe Browsing', 'INFO',
                        "All {} URL(s) clean on Google Safe Browsing".format(len(urls_in_text))))
        except Exception as e:
            findings.append(Finding('Google Safe Browsing', 'INFO',
                "GSB check failed: {}".format(str(e)[:50])))

    return findings


def check_reputation(url, vt_api_key=None):
    findings = []
    parsed = urlparse(_normalize(url))
    hostname = (parsed.hostname or '').lower()

    # Local blacklist
    if hostname in LOCAL_BLACKLIST:
        findings.append(Finding('Reputation', 'HIGH',
            "Domain '{}' is on the local phishing blacklist".format(hostname)))

    # VirusTotal
    if vt_api_key:
        try:
            headers = {'x-apikey': vt_api_key}
            resp = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers=headers, data={'url': url}, timeout=10)
            if resp.status_code == 200:
                analysis_id = resp.json()['data']['id']
                result_resp = requests.get(
                    'https://www.virustotal.com/api/v3/analyses/' + analysis_id,
                    headers=headers, timeout=10)
                if result_resp.status_code == 200:
                    stats = result_resp.json()['data']['attributes']['stats']
                    malicious  = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    harmless   = stats.get('harmless', 0)
                    total = malicious + suspicious + harmless + stats.get('undetected', 0)
                    if malicious >= 5:
                        findings.append(Finding('Reputation', 'HIGH',
                            "VirusTotal: {}/{} engines flagged as MALICIOUS".format(malicious, total)))
                    elif malicious > 0 or suspicious > 0:
                        findings.append(Finding('Reputation', 'MEDIUM',
                            "VirusTotal: {} malicious, {} suspicious out of {} engines".format(
                                malicious, suspicious, total)))
                    else:
                        findings.append(Finding('Reputation', 'INFO',
                            "VirusTotal: Clean ({}/{} engines report safe)".format(harmless, total)))
                else:
                    findings.append(Finding('Reputation', 'INFO',
                        "VirusTotal analysis pending — result not yet available"))
            elif resp.status_code == 429:
                findings.append(Finding('Reputation', 'INFO',
                    "VirusTotal API rate limit reached — try again in a minute"))
            else:
                findings.append(Finding('Reputation', 'INFO',
                    "VirusTotal returned status {}".format(resp.status_code)))
        except requests.exceptions.Timeout:
            findings.append(Finding('Reputation', 'INFO', "VirusTotal check timed out"))
        except Exception as e:
            findings.append(Finding('Reputation', 'INFO',
                "VirusTotal check failed: {}".format(str(e)[:60])))
    else:
        findings.append(Finding('Reputation', 'INFO',
            "VirusTotal check skipped — no API key configured"))

    return findings


# Trusted tracking/redirect domains — legitimate services that use complex URLs
TRUSTED_TRACKING_ROOTS = {
    'awstrack.me',      # AWS email tracking
    'salesforce.com',   # Salesforce
    'exacttarget.com',  # Salesforce Marketing
    'marketo.net',      # Marketo
    'hubspot.com',      # HubSpot
    'mailchimp.com',    # Mailchimp
    'sendgrid.net',     # SendGrid
    'customer.io',      # Customer.io
    'cio56239.tryhackme.com', # TryHackMe
    'mandrillapp.com',  # Mandrill
    'intercom.io',      # Intercom
    'mixpanel.com',     # Mixpanel
    'branch.io',        # Branch
    'app.link',         # Branch
    'click.pstmrk.it',  # Postmark
    'trk.klclick.com',  # Klaviyo
    'mail.beehiiv.com', # Beehiiv
}


def run_all_checks(url, vt_api_key=None, email_text=None, sender_email=None):
    """
    Run all 5 advanced checks on a URL.
    Returns (findings: list[Finding], summary: dict)
    """
    # Check if URL is from a trusted email tracking service
    from urllib.parse import urlparse as _urlp
    _host = (_urlp(url).hostname or '').lower()
    _root = '.'.join(_host.split('.')[-2:]) if _host else ''
    _trusted = any(_host == t or _host.endswith('.'+t) or _root == t
                   for t in TRUSTED_TRACKING_ROOTS)

    all_findings = []
    if not _trusted:
        all_findings += check_url_parameters(url)
        all_findings += check_hidden_links(url)
    else:
        all_findings.append(Finding('Reputation', 'INFO',
            'URL from trusted email service (' + _host + ') — skipping aggressive checks'))
    all_findings += check_ssl_domain(url)
    if email_text:
        all_findings += check_email_content(email_text, sender_email)
    all_findings += check_reputation(url, vt_api_key)

    counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary = {
        'total': len(all_findings),
        'high': counts['HIGH'],
        'medium': counts['MEDIUM'],
        'low': counts['LOW'],
        'info': counts['INFO'],
    }
    return all_findings, summary


# ─────────────────────────────────────────────
# EMAIL HEADER ANALYSIS — SPF, DKIM, DMARC
# ─────────────────────────────────────────────

def check_email_headers(raw_headers):
    """Parse raw email headers — SPF, DKIM, DMARC, mismatch detection."""
    import re
    findings = []

    if not raw_headers or len(raw_headers.strip()) < 5:
        findings.append(Finding('Header Analysis', 'INFO', 'No headers provided'))
        return findings

    h = raw_headers

    # SPF
    m = re.search(r'spf\s*=\s*(\w+)', h, re.IGNORECASE)
    if m:
        v = m.group(1).lower()
        if v == 'pass':
            findings.append(Finding('SPF', 'INFO', 'SPF: PASS — sender server is authorised to send for this domain'))
        elif v in ('fail', 'hardfail'):
            findings.append(Finding('SPF', 'HIGH', 'SPF: FAIL — sender NOT authorised. Email is likely spoofed'))
        elif v in ('softfail', 'neutral'):
            findings.append(Finding('SPF', 'MEDIUM', 'SPF: ' + v.upper() + ' — sender not fully authorised. Suspicious'))
        else:
            findings.append(Finding('SPF', 'MEDIUM', 'SPF: ' + v.upper() + ' — cannot verify sender'))
    else:
        findings.append(Finding('SPF', 'MEDIUM', 'SPF: Not found in headers — sender authorisation unknown'))

    # DKIM
    m = re.search(r'dkim\s*=\s*(\w+)', h, re.IGNORECASE)
    if m:
        v = m.group(1).lower()
        if v == 'pass':
            findings.append(Finding('DKIM', 'INFO', 'DKIM: PASS — signature valid, message not tampered'))
        elif v == 'fail':
            findings.append(Finding('DKIM', 'HIGH', 'DKIM: FAIL — signature INVALID, message may be forged or tampered'))
        else:
            findings.append(Finding('DKIM', 'MEDIUM', 'DKIM: ' + v.upper() + ' — signature could not be verified'))
    else:
        m2 = re.search(r'signed\s*by[:\s]+(\S+)', h, re.IGNORECASE)
        if m2:
            findings.append(Finding('DKIM', 'INFO', 'DKIM: Signed by ' + m2.group(1).strip()))
        else:
            findings.append(Finding('DKIM', 'MEDIUM', 'DKIM: Not found — message integrity cannot be verified'))

    # DMARC
    m = re.search(r'dmarc\s*=\s*(\w+)', h, re.IGNORECASE)
    if m:
        v = m.group(1).lower()
        if v == 'pass':
            findings.append(Finding('DMARC', 'INFO', 'DMARC: PASS — email passed domain alignment policy'))
        elif v == 'fail':
            findings.append(Finding('DMARC', 'HIGH', 'DMARC: FAIL — failed domain alignment. Strong phishing indicator'))
        else:
            findings.append(Finding('DMARC', 'MEDIUM', 'DMARC: ' + v.upper()))
    else:
        findings.append(Finding('DMARC', 'MEDIUM', 'DMARC: Not found in headers'))

    # Encryption
    m = re.search(r'security[:\s]+([^\r\n]+)', h, re.IGNORECASE)
    if m:
        sec = m.group(1).strip()
        if 'tls' in sec.lower() or 'encryption' in sec.lower():
            findings.append(Finding('Encryption', 'INFO', 'Connection encrypted: ' + sec))
        else:
            findings.append(Finding('Encryption', 'MEDIUM', 'Encryption status: ' + sec))

    # Mailed-by
    m = re.search(r'mailed.by[:\s]+([^\r\n]+)', h, re.IGNORECASE)
    if m:
        findings.append(Finding('Mailed-By', 'INFO', 'Mailed by: ' + m.group(1).strip()))

    # Signed-by (Gmail display)
    m = re.search(r'signed\s*by[:\s]+([^\r\n]+)', h, re.IGNORECASE)
    if m:
        findings.append(Finding('Signed-By', 'INFO', 'Signed by: ' + m.group(1).strip()))

    # From vs Return-Path mismatch
    fm = re.search(r'^from[:\s]+(.+)$', h, re.MULTILINE | re.IGNORECASE)
    rm = re.search(r'^return.path[:\s]+(.+)$', h, re.MULTILINE | re.IGNORECASE)
    if fm and rm:
        fd = re.search(r'@([\w.\-]+)', fm.group(1))
        rd = re.search(r'@([\w.\-]+)', rm.group(1))
    if fm and rm:
        fd = re.search(r'@([\w.\-]+)', fm.group(1))
        rd = re.search(r'@([\w.\-]+)', rm.group(1))
        if fd and rd:
            from_d = fd.group(1).lower()
            ret_d  = rd.group(1).lower()
            from_root = '.'.join(from_d.split('.')[-2:])
            ret_root  = '.'.join(ret_d.split('.')[-2:])
            if from_root != ret_root:
                findings.append(Finding('Header Mismatch', 'HIGH',
                    'From (' + from_d + ') differs from Return-Path (' + ret_d + ') — possible spoofing'))
            elif from_d != ret_d:
                findings.append(Finding('Header Mismatch', 'INFO',
                    'Return-Path uses subdomain (' + ret_d + ') — normal for bulk email services'))
            else:
                findings.append(Finding('Header Mismatch', 'INFO',
                    'From and Return-Path match (' + from_d + ')'))

    # Reply-To mismatch
    repm = re.search(r'^reply.to[:\s]+(.+)$', h, re.MULTILINE | re.IGNORECASE)
    if repm and fm:
        rd2 = re.search(r'@([\w.\-]+)', repm.group(1))
        fd2 = re.search(r'@([\w.\-]+)', fm.group(1))
        if rd2 and fd2:
            reply_domain = rd2.group(1).lower()
            from_domain2 = fd2.group(1).lower()
            reply_root = '.'.join(reply_domain.split('.')[-2:])
            from_root2 = '.'.join(from_domain2.split('.')[-2:])
            if reply_root != from_root2:
                # Truly different root domain — suspicious
                findings.append(Finding('Header Mismatch', 'HIGH',
                    'Reply-To (' + reply_domain + ') differs from From (' + from_domain2 + ') — replies may go to attacker'))
            elif reply_domain != from_domain2:
                findings.append(Finding('Header Mismatch', 'INFO',
                    'Reply-To uses subdomain (' + reply_domain + ') — normal for email services'))

    # X-Mailer
    mm = re.search(r'^x.mailer[:\s]+(.+)$', h, re.MULTILINE | re.IGNORECASE)
    if mm:
        ml = mm.group(1).strip()
        if any(b in ml.lower() for b in ['phpmailer', 'massmailer', 'bulkmail', 'sendblast']):
            findings.append(Finding('X-Mailer', 'MEDIUM', 'Bulk mailer detected: ' + ml + ' — common in phishing'))
        else:
            findings.append(Finding('X-Mailer', 'INFO', 'Sent via: ' + ml))

    # Received chain
    received = re.findall(r'^received[:\s]+.+$', h, re.MULTILINE | re.IGNORECASE)
    if received:
        findings.append(Finding('Received Chain', 'INFO',
            'Email passed through ' + str(len(received)) + ' mail server(s)'))

    # Summary at top — based on real HIGH findings only (not subdomain mismatches)
    real_high = sum(1 for f in findings
        if f.severity == 'HIGH' and 'subdomain' not in f.message.lower() and 'normal' not in f.message.lower())
    if real_high >= 2:
        findings.insert(0, Finding('Header Summary', 'HIGH',
            str(real_high) + ' authentication failures — strong indication of email spoofing or phishing'))
    elif real_high == 1:
        findings.insert(0, Finding('Header Summary', 'MEDIUM',
            '1 authentication failure detected — treat this email with caution'))
    else:
        findings.insert(0, Finding('Header Summary', 'INFO',
            'No critical header failures — email authentication appears legitimate'))

    return findings
