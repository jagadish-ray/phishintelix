"""
app.py  —  PhishIntelix full web app
"""
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, request, make_response, jsonify
import joblib, io, datetime
import config
import pandas as pd
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

from feature_extractor import extract_features, FEATURE_ORDER
from advanced_checks import run_all_checks

app = Flask(__name__)
model = joblib.load('model.pkl')

# ── VirusTotal API key ──
VT_API_KEY = 'a849945235ec9cf73fe3b498b8127a8f3d957fcd0c731179992bf184776748a1'

# ── Stats + History ──
import json, threading
STATS_FILE = 'stats.json'
_stats_lock = threading.Lock()

def _load_stats():
    try:
        return json.load(open(STATS_FILE))
    except Exception:
        return {'total_scans': 0, 'phishing_detected': 0}

def _save_stats(stats):
    try:
        json.dump(stats, open(STATS_FILE, 'w'))
    except Exception:
        pass

def increment_stats(is_phishing):
    with _stats_lock:
        stats = _load_stats()
        stats['total_scans'] += 1
        if is_phishing:
            stats['phishing_detected'] += 1
        _save_stats(stats)

def increment_email_stats(is_phishing):
    with _stats_lock:
        stats = _load_stats()
        stats['email_scans'] = stats.get('email_scans', 0) + 1
        if is_phishing:
            stats['email_phishing'] = stats.get('email_phishing', 0) + 1
        _save_stats(stats)

# ── Scan history (URL scans) ──
HISTORY_FILE = 'scan_history.json'
_history_lock = threading.Lock()
MAX_HISTORY = 200

def _load_history():
    try:
        return json.load(open(HISTORY_FILE))
    except Exception:
        return []

def _save_history(history):
    try:
        json.dump(history[-MAX_HISTORY:], open(HISTORY_FILE, 'w'))
    except Exception:
        pass

def append_history(result):
    with _history_lock:
        history = _load_history()
        history.append({
            'url':         result['url'],
            'verdict':     result['verdict'],
            'label':       result['label'],
            'final_score': result['final_score'],
            'ml_score':    result['ml_score'],
            'flags':       len(result['flags']),
            'timestamp':   datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        })
        _save_history(history)

# ── Email scan history ──
EMAIL_HISTORY_FILE = 'email_scan_history.json'
_email_lock = threading.Lock()

def _load_email_history():
    try:
        return json.load(open(EMAIL_HISTORY_FILE))
    except Exception:
        return []

def _save_email_history(h):
    try:
        json.dump(h[-MAX_HISTORY:], open(EMAIL_HISTORY_FILE, 'w'))
    except Exception:
        pass

def append_email_history(result, email_text=''):
    with _email_lock:
        history = _load_email_history()
        history.append({
            'sender':    result.get('sender', ''),
            'verdict':   result['verdict'],
            'label':     result['label'],
            'score':     result['score'],
            'high':      result['summary']['high'],
            'medium':    result['summary']['medium'],
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        })
        _save_email_history(history)

# ── Fix 1: Whitelist — always marked Safe ──
WHITELISTED_DOMAINS = {
    'cyberwarfare.live', 'virustotal.com', 'shodan.io', 'exploit-db.com',
    'haveibeenpwned.com', 'securitytrails.com', 'censys.io',
    'google.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'facebook.com', 'twitter.com', 'linkedin.com', 'wikipedia.org',
    'stackoverflow.com', 'youtube.com', 'reddit.com', 'netflix.com',
    'anthropic.com', 'openai.com', 'cloudflare.com',
    'phishintelix.com',  # Our own domain
    # Trusted email tracking & business services
    'awstrack.me', 'webex.com', 'zoom.us', 'tryhackme.com',
    'salesforce.com', 'hubspot.com', 'mailchimp.com', 'sendgrid.net',
    'customer.io', 'intercom.io', 'mandrillapp.com', 'marketo.net',
    'beehiiv.com', 'substack.com', 'convertkit.com', 'klaviyo.com',
    'internshala.com', 'educative.io', 'bseindia.com', 'quantinsti.com',
    'smartinternz.com', 'forms.gle', 'docs.google.com', 'drive.google.com',
    'communication.smartinternz.com', 'tryhackme.com', 'hackerrank.com',
}


def _get_root_domain(url):
    from urllib.parse import urlparse
    hostname = (urlparse(url if '://' in url else 'http://'+url).hostname or '').lower()
    parts = hostname.split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else hostname


def get_verdict(url):
    # Whitelist check FIRST — before any ML or feature extraction
    root_domain = _get_root_domain(url)
    hostname = root_domain  # for logging
    if root_domain in WHITELISTED_DOMAINS:
        # Extract features just for display but force safe verdict
        try:
            ml_features, flags = extract_features(url)
        except Exception:
            ml_features, flags = {}, []
        return {
            'url': url, 'verdict': 'safe', 'label': 'Likely Safe',
            'ml_score': 0.0, 'final_score': 0.0,
            'flags': [], 'features': ml_features,
            'note': f'Domain "{root_domain}" is whitelisted as a known safe domain.'
        }

    ml_features, flags = extract_features(url)

    X = pd.DataFrame([ml_features], columns=FEATURE_ORDER)
    proba = model.predict_proba(X)[0]
    classes = list(model.classes_)
    phishing_idx = classes.index('phishing')
    ml_score = float(proba[phishing_idx])
    heuristic_score = min(len(flags) * 0.12, 0.6)

    # Fix 2: Confidence threshold
    # If URL has no suspicious structure at all, cap ML score so
    # it cannot alone push a clean URL into Phishing territory.
    all_clean = all(ml_features.get(k, 0) == 0
                    for k in ('has_ip', 'has_at', 'suspicious_word'))
    if all_clean and len(flags) == 0:
        ml_score = min(ml_score, 0.55)

    final_score = min(ml_score * 0.7 + heuristic_score, 1.0)

    if final_score >= 0.6:
        verdict, label = 'phishing', 'Likely Phishing'
    elif final_score >= 0.3:
        verdict, label = 'suspicious', 'Suspicious'
    else:
        verdict, label = 'safe', 'Likely Safe'

    return {
        'url': url, 'verdict': verdict, 'label': label,
        'ml_score': round(ml_score * 100, 1),
        'final_score': round(final_score * 100, 1),
        'flags': flags, 'features': ml_features,
        'note': None,
    }


def build_pdf(result, adv_findings, adv_summary):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)

    TEAL       = colors.HexColor('#0066cc')
    BLACK      = colors.HexColor('#000000')
    DARK_COL   = colors.HexColor('#1a1a2e')
    WHITE      = colors.white
    RED        = colors.HexColor('#cc0000')
    AMBER      = colors.HexColor('#cc6600')
    GREY       = colors.HexColor('#666666')
    LIGHT_GREY = colors.HexColor('#f5f5f5')
    RISK_COLOR = RED if result['verdict']=='phishing' else (AMBER if result['verdict']=='suspicious' else colors.HexColor('#006600'))

    title_style   = ParagraphStyle('T',  fontSize=24, textColor=BLACK, alignment=TA_CENTER,
                                   spaceAfter=10, spaceBefore=10, fontName='Helvetica-Bold')
    sub_style     = ParagraphStyle('S',  fontSize=13, textColor=TEAL,  alignment=TA_CENTER,
                                   spaceAfter=10, spaceBefore=6, fontName='Helvetica-Bold')
    footer_style  = ParagraphStyle('FT', fontSize=9,  textColor=GREY,  alignment=TA_CENTER, spaceAfter=4)
    heading_style = ParagraphStyle('H',  fontSize=12, textColor=BLACK, spaceAfter=4,
                                   spaceBefore=14, fontName='Helvetica-Bold')
    cat_style     = ParagraphStyle('C',  fontSize=10, textColor=BLACK, spaceAfter=3,
                                   spaceBefore=8, fontName='Helvetica-Bold', leftIndent=8)
    high_style    = ParagraphStyle('FH', fontSize=9,  textColor=RED,   spaceAfter=3, leftIndent=20, leading=13)
    med_style     = ParagraphStyle('FM', fontSize=9,  textColor=AMBER, spaceAfter=3, leftIndent=20, leading=13)
    info_style    = ParagraphStyle('FI', fontSize=9,  textColor=GREY,  spaceAfter=3, leftIndent=20, leading=13)
    body_style    = ParagraphStyle('B',  fontSize=10, textColor=BLACK, spaceAfter=4, leading=15)
    rec_style     = ParagraphStyle('R',  fontSize=10, textColor=BLACK, spaceAfter=4, leading=15)

    story = []
    story.append(Spacer(1, 10))
    story.append(Paragraph("PhishIntelix", title_style))
    story.append(Spacer(1, 8))
    story.append(Paragraph("URL Phishing Analysis Report", sub_style))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1.5, color=TEAL, spaceAfter=14))

    now = datetime.datetime.now().strftime("%d %B %Y, %I:%M %p")
    meta = [
        ['Scanned URL',   result['url']],
        ['Scan Date',     now],
        ['Verdict',       result['label']],
        ['Risk Score',    str(result['final_score'])+'%'],
        ['ML Score',      str(result['ml_score'])+'%'],
        ['Basic Flags',   str(len(result['flags']))],
        ['Adv HIGH',      str(adv_summary.get('high', 0))],
        ['Adv MEDIUM',    str(adv_summary.get('medium', 0))],
        ['Total Findings',str(adv_summary.get('high',0)+adv_summary.get('medium',0)+adv_summary.get('info',0))],
    ]
    t = Table(meta, colWidths=[4*cm, 13*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(0,-1), DARK_COL),
        ('BACKGROUND',    (1,0),(1,-1), WHITE),
        ('TEXTCOLOR',     (0,0),(0,-1), WHITE),
        ('TEXTCOLOR',     (1,0),(1,-1), BLACK),
        ('TEXTCOLOR',     (1,2),(1,2),  RISK_COLOR),
        ('FONTNAME',      (0,0),(0,-1), 'Helvetica-Bold'),
        ('FONTNAME',      (1,0),(1,-1), 'Helvetica'),
        ('FONTSIZE',      (0,0),(-1,-1), 9),
        ('ROWBACKGROUNDS',(1,0),(1,-1), [WHITE, LIGHT_GREY]),
        ('GRID',          (0,0),(-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('PADDING',       (0,0),(-1,-1), 7),
        ('WORDWRAP',      (1,0),(1,-1), 'CJK'),
    ]))
    story.append(t)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Basic Heuristic Flags", heading_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc'), spaceAfter=6))
    if result['flags']:
        for f in result['flags']:
            story.append(Paragraph('▪  ' + f, med_style))
    else:
        story.append(Paragraph('✔  No basic heuristic flags detected.', body_style))

    story.append(Paragraph("Extracted ML Features", heading_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc'), spaceAfter=6))
    feat_rows = [['Feature', 'Value']] + [[k, str(v)] for k,v in result['features'].items()]
    ft = Table(feat_rows, colWidths=[8.5*cm, 8.5*cm])
    ft.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,0),  DARK_COL),
        ('TEXTCOLOR',     (0,0),(-1,0),  WHITE),
        ('FONTNAME',      (0,0),(-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0,0),(-1,-1), 9),
        ('ROWBACKGROUNDS',(0,1),(-1,-1), [WHITE, LIGHT_GREY]),
        ('TEXTCOLOR',     (0,1),(-1,-1), BLACK),
        ('GRID',          (0,0),(-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('PADDING',       (0,0),(-1,-1), 6),
    ]))
    story.append(ft)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Advanced Threat Analysis", heading_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc'), spaceAfter=6))
    if adv_findings:
        current_cat = None
        for f in adv_findings:
            if f.category != current_cat:
                current_cat = f.category
                story.append(Paragraph('➢  ' + f.category, cat_style))
            sty = high_style if f.severity=='HIGH' else (med_style if f.severity=='MEDIUM' else info_style)
            story.append(Paragraph('▪  [' + f.severity + '] ' + f.message, sty))
    else:
        story.append(Paragraph('✔  No advanced threats detected.', body_style))

    story.append(Spacer(1, 10))
    story.append(Paragraph("Recommendation", heading_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc'), spaceAfter=6))
    if result['verdict'] == 'phishing':
        rec = "This URL shows strong indicators of a phishing attack. Do NOT visit, click, or share this link. Report it to your IT or security team immediately."
    elif result['verdict'] == 'suspicious':
        rec = "This URL has suspicious characteristics. Exercise caution before visiting. Verify the domain independently before entering any credentials."
    else:
        rec = "This URL appears safe. However, always remain cautious online and never enter credentials on a page you did not navigate to yourself."
    story.append(Paragraph(rec, rec_style))

    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc'), spaceAfter=6))
    story.append(Paragraph("Generated by PhishIntelix · AI-Powered Phishing Detection · © 2026", footer_style))

    doc.build(story)
    buf.seek(0)
    return buf


def build_email_pdf(sender, email_text, verdict, label, score, findings, summary):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)

    # Colors — white background style like your edited PDF
    TEAL       = colors.HexColor('#0066cc')
    BLACK      = colors.HexColor('#000000')
    DARK_COL   = colors.HexColor('#1a1a2e')
    WHITE      = colors.white
    RED        = colors.HexColor('#cc0000')
    AMBER      = colors.HexColor('#cc6600')
    GREY       = colors.HexColor('#666666')
    LIGHT_GREY = colors.HexColor('#f5f5f5')
    RISK_COLOR = RED if verdict=='phishing' else (AMBER if verdict=='suspicious' else colors.HexColor('#006600'))

    title_style   = ParagraphStyle('T',  fontSize=24, textColor=BLACK,  alignment=TA_CENTER,
                                   spaceAfter=10, spaceBefore=10, fontName='Helvetica-Bold')
    sub_style     = ParagraphStyle('S',  fontSize=13, textColor=TEAL,   alignment=TA_CENTER,
                                   spaceAfter=10, spaceBefore=6, fontName='Helvetica-Bold')
    footer_style  = ParagraphStyle('FT', fontSize=9,  textColor=GREY,   alignment=TA_CENTER,
                                   spaceAfter=4)
    heading_style = ParagraphStyle('H',  fontSize=12, textColor=BLACK,  spaceAfter=4,
                                   spaceBefore=14, fontName='Helvetica-Bold')
    cat_style     = ParagraphStyle('C',  fontSize=10, textColor=BLACK,  spaceAfter=3,
                                   spaceBefore=8,  fontName='Helvetica-Bold', leftIndent=8)
    high_style    = ParagraphStyle('FH', fontSize=9,  textColor=RED,    spaceAfter=3,
                                   leftIndent=20, leading=13)
    med_style     = ParagraphStyle('FM', fontSize=9,  textColor=AMBER,  spaceAfter=3,
                                   leftIndent=20, leading=13)
    info_style    = ParagraphStyle('FI', fontSize=9,  textColor=GREY,   spaceAfter=3,
                                   leftIndent=20, leading=13)
    body_style    = ParagraphStyle('B',  fontSize=9,  textColor=BLACK,  spaceAfter=4,
                                   leading=14, leftIndent=8)
    rec_style     = ParagraphStyle('R',  fontSize=10, textColor=BLACK,  spaceAfter=4,
                                   leading=15)

    story = []

    # Title
    story.append(Spacer(1, 10))
    story.append(Paragraph("PhishIntelix", title_style))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Email Phishing Analysis Report", sub_style))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1.5, color=TEAL, spaceAfter=14))

    # Metadata table — dark left column, white right column
    now = datetime.datetime.now().strftime("%d %B %Y, %I:%M %p")
    meta = [
        ['Sender Email',    sender or 'Not provided'],
        ['Scan Date',       now],
        ['Verdict',         label],
        ['Risk Score',      f"{score}%"],
        ['HIGH Findings',   str(summary['high'])],
        ['MEDIUM Findings', str(summary['medium'])],
        ['INFO Findings',   str(summary['info'])],
        ['Total Findings',  str(summary['high'] + summary['medium'] + summary['info'])],
    ]
    t = Table(meta, colWidths=[4.5*cm, 12.5*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(0,-1), DARK_COL),
        ('BACKGROUND',    (1,0),(1,-1), WHITE),
        ('TEXTCOLOR',     (0,0),(0,-1), WHITE),
        ('TEXTCOLOR',     (1,0),(1,-1), BLACK),
        ('TEXTCOLOR',     (1,2),(1,2),  RISK_COLOR),
        ('FONTNAME',      (0,0),(0,-1), 'Helvetica-Bold'),
        ('FONTNAME',      (1,0),(1,-1), 'Helvetica'),
        ('FONTSIZE',      (0,0),(-1,-1), 9),
        ('ROWBACKGROUNDS',(1,0),(1,-1), [WHITE, LIGHT_GREY]),
        ('GRID',          (0,0),(-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('PADDING',       (0,0),(-1,-1), 7),
        ('WORDWRAP',      (1,0),(1,-1), 'CJK'),
    ]))
    story.append(t)
    story.append(Spacer(1, 16))

    # Threat Analysis Findings
    story.append(Paragraph("Threat Analysis Findings", heading_style))
    if findings:
        current_cat = None
        for f in findings:
            if f.category != current_cat:
                current_cat = f.category
                story.append(Paragraph(f"➢  {f.category}", cat_style))
            if f.severity == 'HIGH':
                sty = high_style
                bullet = "▪"
            elif f.severity == 'MEDIUM':
                sty = med_style
                bullet = "▪"
            else:
                sty = info_style
                bullet = "▪"
            story.append(Paragraph(f"{bullet}  [{f.severity}] {f.message}", sty))
    else:
        story.append(Paragraph("✔  No phishing indicators detected in this email.", rec_style))

    story.append(Spacer(1, 10))

    # Email body excerpt
    story.append(Paragraph("Email Body (first 500 chars)", heading_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc'), spaceAfter=6))
    excerpt = (email_text[:500] + '...') if len(email_text) > 500 else email_text
    story.append(Paragraph(excerpt, body_style))
    story.append(Spacer(1, 10))

    # Recommendation
    story.append(Paragraph("Recommendation", heading_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc'), spaceAfter=6))
    if verdict == 'phishing':
        rec = "This email shows strong phishing indicators. Do NOT click any links, open attachments, or reply. Report it to your IT/security team and delete it immediately."
    elif verdict == 'suspicious':
        rec = "This email has suspicious characteristics. Do not click links or open attachments without independently verifying the sender through an official channel."
    else:
        rec = "This email appears safe based on our analysis. However, always remain cautious and verify unexpected requests through official channels."
    story.append(Paragraph(rec, rec_style))

    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cccccc'), spaceAfter=6))
    story.append(Paragraph("Generated by PhishIntelix · AI-Powered Email Analysis · © 2026", footer_style))

    doc.build(story)
    buf.seek(0)
    return buf


@app.route('/', methods=['GET', 'POST'])
def index():
    result, error, adv_findings, adv_summary = None, None, [], {}
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            error = "Please enter a URL to scan."
        else:
            result = get_verdict(url)
            vt_key = VT_API_KEY
            adv_findings, adv_summary = run_all_checks(url, vt_api_key=vt_key)

            # Only apply advanced boost if NOT whitelisted
            if result['final_score'] > 0 or result['verdict'] != 'safe':
                adv_boost = min(
                    adv_summary.get('high', 0) * 0.15 +
                    adv_summary.get('medium', 0) * 0.08, 0.6)
                raw_final = (result['final_score'] / 100) + adv_boost
                new_final = round(min(raw_final, 1.0) * 100, 1)

                if new_final >= 60:
                    new_verdict, new_label = 'phishing', 'Likely Phishing'
                elif new_final >= 30:
                    new_verdict, new_label = 'suspicious', 'Suspicious'
                else:
                    new_verdict, new_label = 'safe', 'Likely Safe'

                result['final_score'] = new_final
                result['verdict']     = new_verdict
                result['label']       = new_label

            increment_stats(result['verdict'] == 'phishing')
            append_history(result)
    stats = _load_stats()
    return render_template('index.html',
                           result=result, error=error,
                           adv_findings=adv_findings,
                           adv_summary=adv_summary,
                           stats=stats,
                           cfg=config)


@app.route('/download-report', methods=['POST'])
def download_report():
    url = request.form.get('url', '').strip()
    if not url:
        return "No URL provided", 400
    result = get_verdict(url)
    vt_key = VT_API_KEY
    adv_findings, adv_summary = run_all_checks(url, vt_api_key=vt_key)
    # Recalculate with advanced boost
    adv_boost = min(adv_summary.get('high',0)*0.15 + adv_summary.get('medium',0)*0.08, 0.6)
    new_final = round(min((result['final_score']/100) + adv_boost, 1.0)*100, 1)
    if new_final >= 60: result['verdict'],result['label'] = 'phishing','Likely Phishing'
    elif new_final >= 30: result['verdict'],result['label'] = 'suspicious','Suspicious'
    else: result['verdict'],result['label'] = 'safe','Likely Safe'
    result['final_score'] = new_final
    pdf_buf = build_pdf(result, adv_findings, adv_summary)
    safe_name = url.replace('https://','').replace('http://','').replace('/','_')[:40]
    filename = f"PhishIntelix_Report_{safe_name}.pdf"
    response = make_response(pdf_buf.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


@app.route('/download-email-report', methods=['POST'])
def download_email_report():
    email_text   = request.form.get('email_text', '').strip()
    sender_email = request.form.get('sender_email', '').strip()
    if not email_text:
        return "No email content provided", 400

    from advanced_checks import check_email_content
    gsb_key = config.GSB_API_KEY if config.GSB_API_KEY != 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY' else None
    findings = check_email_content(email_text, sender_email or None,
                                   vt_api_key=VT_API_KEY, gsb_api_key=gsb_key)
    high   = sum(1 for f in findings if f.severity == 'HIGH')
    medium = sum(1 for f in findings if f.severity == 'MEDIUM')
    info   = sum(1 for f in findings if f.severity == 'INFO')
    score  = min(high * 22 + medium * 10, 100)  # INFO findings don't add to risk score
    if score >= 60:
        verdict, label = 'phishing', 'Likely Phishing Email'
    elif score >= 30:
        verdict, label = 'suspicious', 'Suspicious Email'
    else:
        verdict, label = 'safe', 'Likely Safe Email'

    result = {
        'url': sender_email or 'Email Content',
        'verdict': verdict, 'label': label,
        'final_score': score, 'ml_score': 0,
        'flags': [], 'features': {},
        'note': None,
    }
    adv_summary = {'high': high, 'medium': medium, 'low': 0, 'info': info}
    pdf_buf = build_email_pdf(sender_email, email_text, verdict, label, score, findings, adv_summary)
    filename = "PhishIntelix_Email_Report.pdf"
    response = make_response(pdf_buf.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


# ── Contact form email config (from config.py) ──
CONTACT_EMAIL      = config.CONTACT_EMAIL
GMAIL_APP_PASSWORD = config.GMAIL_APP_PASSWORD


@app.route('/contact', methods=['POST'])
def contact():
    name    = request.form.get('name', '').strip()
    email   = request.form.get('email', '').strip()
    message = request.form.get('message', '').strip()

    if not name or not email or not message:
        return jsonify({'status': 'error', 'msg': 'All fields are required.'}), 400

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'[PhishIntelix Contact] Message from {name}'
        msg['From']    = CONTACT_EMAIL
        msg['To']      = CONTACT_EMAIL
        msg['Reply-To'] = email

        body = f"""
New contact form submission from PhishIntelix:

Name:    {name}
Email:   {email}

Message:
{message}

---
Sent via PhishIntelix contact form
"""
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(CONTACT_EMAIL, GMAIL_APP_PASSWORD)
            server.sendmail(CONTACT_EMAIL, CONTACT_EMAIL, msg.as_string())

        return jsonify({'status': 'ok', 'msg': 'Message sent! We will get back to you soon.'})
    except Exception as e:
        return jsonify({'status': 'error', 'msg': f'Could not send message: {str(e)[:80]}'}), 500


# ── Blog routes ──
@app.route('/blog/what-is-phishing')
def blog1():
    return render_template('blogs/what-is-phishing.html')

@app.route('/blog/homograph-typosquatting')
def blog2():
    return render_template('blogs/homograph-typosquatting.html')

@app.route('/blog/10-signs-phishing')
def blog3():
    return render_template('blogs/10-signs-phishing.html')

@app.route('/blog/ml-detects-phishing')
def blog4():
    return render_template('blogs/ml-detects-phishing.html')

@app.route('/blog/open-redirect')
def blog5():
    return render_template('blogs/open-redirect.html')

@app.route('/blog/spotting-phishing-emails')
def blog6():
    return render_template('blogs/spotting-phishing-emails.html')


# ── API endpoint ──
@app.route('/api/scan')
def api_scan():
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided. Use /api/scan?url=https://example.com'}), 400
    result = get_verdict(url)
    adv_findings, adv_summary = run_all_checks(url, vt_api_key=VT_API_KEY)
    adv_boost = min(adv_summary.get('high',0)*0.15 + adv_summary.get('medium',0)*0.08, 0.6)
    new_final = round(min((result['final_score']/100) + adv_boost, 1.0)*100, 1)
    if new_final >= 60: result['verdict'],result['label'] = 'phishing','Likely Phishing'
    elif new_final >= 30: result['verdict'],result['label'] = 'suspicious','Suspicious'
    else: result['verdict'],result['label'] = 'safe','Likely Safe'
    result['final_score'] = new_final
    return jsonify({
        'url':           result['url'],
        'verdict':       result['verdict'],
        'label':         result['label'],
        'final_score':   result['final_score'],
        'ml_score':      result['ml_score'],
        'flags':         result['flags'],
        'features':      result['features'],
        'advanced': {
            'summary':   adv_summary,
            'findings':  [{'category': f.category, 'severity': f.severity, 'message': f.message}
                          for f in adv_findings],
        }
    })


# ── Scan history route ──
@app.route('/email-view/<email_id>')
def email_view(email_id):
    history = _load_email_history()
    record = next((r for r in history if r.get('id') == email_id), None)
    if not record:
        return "Email not found.", 404
    return render_template('email_view.html', record=record, cfg=config)


@app.route('/stats')
def get_stats():
    stats = _load_stats()
    stats.setdefault('email_scans', 0)
    stats.setdefault('email_phishing', 0)
    return jsonify(stats)


@app.route('/api/history')
def api_history():
    url_scans   = list(reversed(_load_history()))
    email_scans = list(reversed(_load_email_history()))
    return jsonify({'url_scans': url_scans, 'email_scans': email_scans})


@app.route('/history')
def history():
    url_records   = list(reversed(_load_history()))
    email_records = list(reversed(_load_email_history()))
    return render_template('history.html',
                           url_records=url_records,
                           email_records=email_records,
                           cfg=config)


# ── Email scanner route ──

def parse_email_file(file_storage):
    import email as email_lib
    from email import policy
    import re as _re
    filename = file_storage.filename.lower()
    raw_bytes = file_storage.read()
    extracted_body = ""
    extracted_headers = ""
    extracted_sender = ""
    try:
        if filename.endswith(".eml") or filename.endswith(".txt"):
            msg = email_lib.message_from_bytes(raw_bytes, policy=policy.default)
            header_keys = ["Delivered-To","Authentication-Results","From","Return-Path",
                           "Reply-To","Received","X-Mailer","DKIM-Signature"]
            header_lines = []
            for key in header_keys:
                val = msg.get(key, "")
                if val:
                    header_lines.append(key + ": " + str(val))
            extracted_headers = "\n".join(header_lines)
            extracted_sender  = str(msg.get("From", ""))
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    if ctype == "text/plain":
                        try: extracted_body += part.get_content() + "\n"
                        except: pass
                    elif ctype == "text/html" and not extracted_body:
                        try: extracted_body += part.get_content() + "\n"
                        except: pass
            else:
                try: extracted_body = msg.get_content()
                except: extracted_body = raw_bytes.decode("utf-8", errors="ignore")
        elif filename.endswith(".html") or filename.endswith(".htm"):
            raw_text = raw_bytes.decode("utf-8", errors="ignore")
            raw_text = _re.sub(r"<(script|style)[^>]*>.*?</(script|style)>", " ", raw_text, flags=_re.DOTALL|_re.IGNORECASE)
            extracted_body = _re.sub(r"<[^>]+>", " ", raw_text)
            extracted_body = _re.sub(r"\s+", " ", extracted_body).strip()
        elif filename.endswith(".msg"):
            try:
                import extract_msg
                msg = extract_msg.Message(io.BytesIO(raw_bytes))
                extracted_body   = msg.body or ""
                extracted_sender = msg.sender or ""
                extracted_headers = msg.header or ""
            except ImportError:
                extracted_body = raw_bytes.decode("utf-8", errors="ignore")
        else:
            extracted_body = raw_bytes.decode("utf-8", errors="ignore")
    except Exception:
        extracted_body = raw_bytes.decode("utf-8", errors="ignore")
    return extracted_body.strip(), extracted_headers.strip(), extracted_sender.strip()


@app.route('/email-scanner', methods=['GET', 'POST'])
def email_scanner():
    result = None
    if request.method == 'POST':
        email_text=request.form.get('email_text','').strip()
        sender_email=request.form.get('sender_email','').strip()
        raw_headers=request.form.get('raw_headers','').strip()
        uploaded_file=request.files.get('email_file')
        if uploaded_file and uploaded_file.filename:
            body,headers,sender=parse_email_file(uploaded_file)
            if not email_text: email_text=body
            if not raw_headers: raw_headers=headers
            if not sender_email: sender_email=sender
        if email_text:
            from advanced_checks import check_email_content
            gsb_key = config.GSB_API_KEY if config.GSB_API_KEY != 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY' else None
            findings = check_email_content(email_text, sender_email or None, vt_api_key=VT_API_KEY, gsb_api_key=gsb_key)
            if raw_headers:
                from advanced_checks import check_email_headers
                findings.extend(check_email_headers(raw_headers))
            # Weighted scoring — urgency/social engineering get lower weight
            urgency_social = sum(1 for f in findings
                if f.category in ('Urgency Detection', 'Social Engineering'))
            high   = sum(1 for f in findings if f.severity == 'HIGH')
            medium = sum(1 for f in findings if f.severity == 'MEDIUM')
            info   = sum(1 for f in findings if f.severity == 'INFO')
            real_medium = max(medium - urgency_social, 0)
            score = min(high * 20 + real_medium * 8 + urgency_social * 3, 100)
            if score >= 75:
                verdict, label = 'phishing', 'Phishing Email'
            elif score >= 50:
                verdict, label = 'phishing', 'Likely Phishing Email'
            elif score >= 30:
                verdict, label = 'suspicious', 'Suspicious Email'
            elif score >= 12:
                verdict, label = 'safe', 'Mostly Safe Email'
            else:
                verdict, label = 'safe', 'Likely Safe Email'
            result = {
                'verdict': verdict, 'label': label, 'score': score,
                'findings': findings,
                'summary': {'high': high, 'medium': medium, 'info': info},
                'sender': sender_email,
                'email_text': email_text,
            }
            append_email_history(result, email_text=email_text)
            increment_email_stats(result['verdict'] == 'phishing')
    return render_template('email_scanner.html', result=result, cfg=config)


@app.route('/blog/email-header-analysis')
def blog7():
    return render_template('blogs/email-header-analysis.html')

@app.route('/blog/anatomy-phishing-email')
def blog8():
    return render_template('blogs/anatomy-phishing-email.html')




@app.route('/about')
def about():
    return render_template('about.html', cfg=config)


if __name__ == '__main__':
    app.run(debug=True)
# Note: the above line was a duplicate, removing it below
