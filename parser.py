import email
from email import policy
import email.utils
from urllib.parse import urlparse
import re

def extract_domain(email_address):
    """Extract domain from email address (e.g. 'john@example.com' -> 'example.com')."""
    if not email_address or '@' not in email_address:
        return None
    # Strip brackets and whitespace
    email_address = email_address.strip('<> ')
    parts = email_address.split('@')
    if len(parts) >= 2:
        return parts[-1].strip().lower()
    return None

def clean_header(header_val):
    """Normalize header values, resolving encoded words if any."""
    if not header_val:
        return ""
    # email.message will handle decoding if opened with policy.default
    return str(header_val).strip()

def parse_auth_headers(msg):
    """
    Parse authentication results (SPF and DKIM) from email headers.
    Returns a dict with spf and dkim status, e.g. {'spf': 'pass', 'dkim': 'fail'}.
    """
    results = {'spf': 'unknown', 'dkim': 'unknown'}
    
    # 1. Check Received-SPF header
    spf_headers = msg.get_all('Received-SPF')
    if spf_headers:
        for spf in spf_headers:
            spf_lower = str(spf).lower()
            if 'pass' in spf_lower:
                results['spf'] = 'pass'
                break
            elif 'fail' in spf_lower:
                results['spf'] = 'fail'
                # Don't break in case there's a pass in another hop (though unlikely, fail takes precedence usually)
            elif 'softfail' in spf_lower:
                if results['spf'] != 'fail':
                    results['spf'] = 'softfail'
            elif 'neutral' in spf_lower or 'none' in spf_lower:
                if results['spf'] not in ('pass', 'fail', 'softfail'):
                    results['spf'] = 'neutral'
                    
    # 2. Check Authentication-Results header (can contain both SPF and DKIM)
    auth_headers = msg.get_all('Authentication-Results')
    if auth_headers:
        for auth in auth_headers:
            auth_str = str(auth).lower()
            # SPF check
            spf_match = re.search(r'spf=(\w+)', auth_str)
            if spf_match:
                spf_val = spf_match.group(1)
                if spf_val in ('pass', 'fail', 'softfail', 'neutral', 'none'):
                    # Prioritize fail/pass over unknown/none
                    if results['spf'] == 'unknown' or spf_val in ('fail', 'pass'):
                        results['spf'] = spf_val
            
            # DKIM check
            dkim_match = re.search(r'dkim=(\w+)', auth_str)
            if dkim_match:
                dkim_val = dkim_match.group(1)
                if dkim_val in ('pass', 'fail', 'softfail', 'neutral', 'none'):
                    if results['dkim'] == 'unknown' or dkim_val in ('fail', 'pass'):
                        results['dkim'] = dkim_val

    # 3. Check for DKIM-Signature header as indicator of presence
    dkim_signatures = msg.get_all('DKIM-Signature')
    if dkim_signatures and results['dkim'] == 'unknown':
        results['dkim'] = 'signed' # DKIM signature exists but no auth header checked it yet

    return results

def parse_eml_file(file_path):
    """
    Load and parse a raw .eml file.
    Returns a dict containing all structured metadata, body text, HTML, and attachment list.
    """
    with open(file_path, 'rb') as f:
        # Use policy.default to automatically decode headers, line endings, etc.
        msg = email.message_from_binary_file(f, policy=policy.default)

    # 1. Basic Metadata
    from_header = clean_header(msg.get('From', ''))
    from_name, from_email = email.utils.parseaddr(from_header)
    from_domain = extract_domain(from_email)

    to_header = clean_header(msg.get('To', ''))
    to_list = []
    if to_header:
        # getaddresses parses a list of comma-separated addresses
        raw_to_addresses = email.utils.getaddresses([to_header])
        for name, addr in raw_to_addresses:
            to_list.append({'name': name, 'email': addr})

    subject = clean_header(msg.get('Subject', ''))
    date = clean_header(msg.get('Date', ''))
    message_id = clean_header(msg.get('Message-ID', ''))
    
    # Return-Path is often formatted as <email@domain.com>
    return_path = clean_header(msg.get('Return-Path', ''))
    return_path_email = return_path.strip('<>') if return_path else ""
    return_path_domain = extract_domain(return_path_email)

    # 2. Body extraction (Plain Text & HTML) and Attachment detection
    body_text = ""
    body_html = ""
    attachments = []

    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = part.get_content_disposition()
        filename = part.get_filename()

        # If it's an attachment
        if content_disposition == 'attachment' or filename is not None:
            if not filename:
                filename = "unnamed_attachment"
            try:
                payload = part.get_payload(decode=True)
                size = len(payload) if payload else 0
            except Exception:
                size = 0
            attachments.append({
                'filename': filename,
                'content_type': content_type,
                'size_bytes': size
            })
        else:
            # Check for text or html body parts
            if content_type == 'text/plain':
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        body_text += payload.decode(charset, errors='replace')
                    except Exception:
                        body_text += payload.decode('utf-8', errors='replace')
            elif content_type == 'text/html':
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        body_html += payload.decode(charset, errors='replace')
                    except Exception:
                        body_html += payload.decode('utf-8', errors='replace')

    # Parse Authentication Headers
    auth = parse_auth_headers(msg)

    # Combine text and HTML body parts to ensure we scan all textual content
    return {
        'from': {
            'raw': from_header,
            'name': from_name,
            'email': from_email,
            'domain': from_domain
        },
        'to': to_list,
        'subject': subject,
        'date': date,
        'message_id': message_id,
        'return_path': {
            'raw': return_path,
            'email': return_path_email,
            'domain': return_path_domain
        },
        'auth': auth,
        'body_text': body_text,
        'body_html': body_html,
        'attachments': attachments
    }
