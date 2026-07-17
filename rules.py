import re
from urllib.parse import urlparse
import ipaddress

# Suspicious extensions commonly used for malware delivery or phishing attachments
SUSPICIOUS_EXTENSIONS = {
    '.exe', '.scr', '.js', '.vbs', '.bat', '.cmd', '.pif', '.msi', '.wsf', 
    '.htm', '.html', '.jar', '.vbe', '.jse', '.lnk', '.ps1', '.hta'
}

# List of high-pressure / urgency keywords grouped by similarity
URGENCY_GROUPS = [
    {
        'name': 'Immediate Action Required',
        'keywords': ['urgent', 'immediate action required', 'immediate action', 'action required', 'act now', 'critical alert']
    },
    {
        'name': 'Account Suspension',
        'keywords': ['suspended', 'suspension', 'restricted', 'restrict', 'disabled', 'lockout', 'locked', 'deactivated']
    },
    {
        'name': 'Security/Verification Prompt',
        'keywords': ['verify your account', 'verify account', 'verify credentials', 'security alert', 'unauthorized login', 'confirm your identity']
    },
    {
        'name': 'Declined/Expired Payment',
        'keywords': ['payment declined', 'card declined', 'billing failure', 'expired', 'expires in']
    }
]

def get_tld_plus_one(domain):
    """
    Extract the base domain (TLD+1) for comparison.
    Handles subdomains and common multi-part SLDs (e.g., co.uk, org.br).
    """
    if not domain:
        return ""
    domain = domain.lower().strip()
    
    # Check if domain is a raw IP address
    if is_ip_address(domain):
        return domain

    parts = domain.split('.')
    if len(parts) >= 2:
        # Check if the second-to-last part is a common short second-level domain (SLD)
        # e.g., domain.co.uk -> co.uk is the suffix, base is domain.co.uk
        if len(parts) >= 3 and parts[-2] in ('co', 'org', 'gov', 'com', 'edu', 'net', 'ac', 'nom'):
            return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])
    return domain

def domains_match(d1, d2):
    """Check if two domains belong to the same primary organization (TLD+1)."""
    if not d1 or not d2:
        return True # Cannot determine mismatch
    
    tld1 = get_tld_plus_one(d1)
    tld2 = get_tld_plus_one(d2)
    return tld1 == tld2

def is_ip_address(hostname):
    """Check if a string represents an IPv4 or IPv6 address."""
    if not hostname:
        return False
    # Quick check for IPv4
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
        try:
            ipaddress.IPv4Address(hostname)
            return True
        except ValueError:
            return False
    # Quick check for IPv6 (contains colons and brackets or hex digits)
    hostname_clean = hostname.strip('[]')
    if ':' in hostname_clean:
        try:
            ipaddress.IPv6Address(hostname_clean)
            return True
        except ValueError:
            return False
    return False

def extract_urls(text):
    """Extract all URLs from a text string using regex."""
    if not text:
        return set()
    # Matches http://... or https://... but stops at delimiters like quote, angle bracket, whitespace
    pattern = r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
    return set(re.findall(pattern, text))

def analyze_email_data(email_data):
    """
    Run security rules on the parsed email data.
    Returns a dict with score, risk_level, and list of triggered indicators.
    """
    score = 0
    indicators = []
    
    from_domain = email_data['from']['domain']
    return_path_domain = email_data['return_path']['domain']

    # Rule 1: Sender Alignment (From Domain vs. Return-Path Domain)
    if from_domain and return_path_domain:
        if not domains_match(from_domain, return_path_domain):
            points = 5
            score += points
            indicators.append({
                'name': 'Sender Domain Mismatch',
                'description': f"Claimed sender domain '{from_domain}' does not align with Return-Path domain '{return_path_domain}'. This is a strong indicator of spoofing.",
                'score': points,
                'severity': 'High'
            })
    elif from_domain and not return_path_domain:
        points = 2
        score += points
        indicators.append({
            'name': 'Missing Return-Path',
            'description': "Return-Path header is empty, which can hide the bounce routing domain.",
            'score': points,
            'severity': 'Low'
        })

    # Rule 2: Authentication Failures
    spf_status = email_data['auth'].get('spf', 'unknown')
    dkim_status = email_data['auth'].get('dkim', 'unknown')

    if spf_status == 'fail':
        points = 5
        score += points
        indicators.append({
            'name': 'SPF Authentication Failure',
            'description': "SPF check failed, indicating the sending server is not authorized to send mail for this domain.",
            'score': points,
            'severity': 'High'
        })
    elif spf_status == 'softfail':
        points = 3
        score += points
        indicators.append({
            'name': 'SPF Authentication Warning',
            'description': "SPF check soft-failed, indicating a potential authorization issue.",
            'score': points,
            'severity': 'Medium'
        })

    if dkim_status == 'fail':
        points = 5
        score += points
        indicators.append({
            'name': 'DKIM Verification Failure',
            'description': "DKIM signature check failed, suggesting the email content may have been modified or forged.",
            'score': points,
            'severity': 'High'
        })

    # Rule 3: Urgency / High-Pressure Language Detection
    subject = email_data['subject'].lower()
    body_text = email_data['body_text'].lower()
    body_html = email_data['body_html'].lower()
    full_content = f"{subject}\n{body_text}\n{body_html}"

    triggered_groups = []
    for group in URGENCY_GROUPS:
        matched_keywords = []
        for keyword in group['keywords']:
            # Use word boundaries or literal matching for phrases
            if re.search(r'\b' + re.escape(keyword) + r'\b', full_content):
                matched_keywords.append(keyword)
        if matched_keywords:
            triggered_groups.append({
                'group_name': group['name'],
                'matches': matched_keywords
            })

    if triggered_groups:
        # Add points: +2 points per group triggered, max +6
        points = min(len(triggered_groups) * 2, 6)
        score += points
        matched_desc = ", ".join([f"{g['group_name']} (matches: {', '.join(g['matches'])})" for g in triggered_groups])
        indicators.append({
            'name': 'Urgent Language Detected',
            'description': f"High-pressure words found: {matched_desc}.",
            'score': points,
            'severity': 'Medium' if points < 6 else 'High'
        })

    # Rule 4: Link Verification (URLs)
    all_urls = extract_urls(email_data['body_text']) | extract_urls(email_data['body_html'])
    flagged_links = []
    unique_mismatched_domains = set()
    raw_ip_count = 0

    for url in all_urls:
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            if not hostname:
                continue
            
            link_flagged = False
            flag_reasons = []

            # A. Check for Raw IP Address
            if is_ip_address(hostname):
                raw_ip_count += 1
                link_flagged = True
                flag_reasons.append("Uses raw IP address instead of domain name")

            # B. Check for Mismatched Domain
            elif from_domain and not domains_match(hostname, from_domain):
                # Ignore common tracking or standard content domains to avoid false positives (e.g. google.com)
                # But let's report them anyway as mismatched with an explanatory warning.
                # In real-world tools, we check if the mismatched domain is a known lookalike.
                # Here, we will flag it if it's not a common generic CDN or the sender's domain.
                common_whitelisted_domains = {'google.com', 'gstatic.com', 'microsoft.com', 'apple.com', 'w3.org', 'schema.org'}
                if not domains_match(hostname, from_domain) and get_tld_plus_one(hostname) not in common_whitelisted_domains:
                    unique_mismatched_domains.add(get_tld_plus_one(hostname))
                    link_flagged = True
                    flag_reasons.append(f"Domain '{hostname}' does not match sender '{from_domain}'")

            if link_flagged:
                flagged_links.append({
                    'url': url,
                    'hostname': hostname,
                    'reasons': flag_reasons
                })
        except Exception:
            pass

    # Scoring for Links
    if raw_ip_count > 0:
        points = 5
        score += points
        indicators.append({
            'name': 'Raw IP Address Link',
            'description': f"Detected {raw_ip_count} link(s) using raw IP addresses (e.g., http://192.168.x.x). Legitimate senders rarely use IP links.",
            'score': points,
            'severity': 'High'
        })

    if unique_mismatched_domains:
        # +4 points per unique mismatched domain, max +8
        points = min(len(unique_mismatched_domains) * 4, 8)
        score += points
        mismatched_str = ", ".join(unique_mismatched_domains)
        indicators.append({
            'name': 'Mismatched Link Domain',
            'description': f"Detected link domains not matching sender's domain '{from_domain}': {mismatched_str}.",
            'score': points,
            'severity': 'High'
        })

    # Rule 5: Suspicious Attachments
    suspicious_attachments_detected = []
    for attachment in email_data['attachments']:
        filename = attachment['filename']
        ext = filename.lower()[filename.rfind('.'):] if '.' in filename else ''
        # Also check for double extensions like file.pdf.exe
        is_double_ext = False
        parts = filename.lower().split('.')
        if len(parts) >= 3:
            # Check if any parts except the first matches a suspicious extension
            for part in parts[1:]:
                if f".{part}" in SUSPICIOUS_EXTENSIONS:
                    is_double_ext = True
                    break

        if ext in SUSPICIOUS_EXTENSIONS or is_double_ext:
            suspicious_attachments_detected.append(attachment)

    if suspicious_attachments_detected:
        points = 5
        score += points
        attach_names = ", ".join([a['filename'] for a in suspicious_attachments_detected])
        indicators.append({
            'name': 'Suspicious Attachment Detected',
            'description': f"Email contains attachment(s) with potentially executable or high-risk extensions: {attach_names}.",
            'score': points,
            'severity': 'High'
        })

    # Map score to Risk Level
    if score >= 7:
        risk_level = 'High Risk'
    elif score >= 3:
        risk_level = 'Medium Risk'
    else:
        risk_level = 'Low Risk'

    return {
        'score': score,
        'risk_level': risk_level,
        'indicators': indicators,
        'flagged_links': flagged_links,
        'all_links_found': list(all_urls),
        'suspicious_attachments': suspicious_attachments_detected
    }
