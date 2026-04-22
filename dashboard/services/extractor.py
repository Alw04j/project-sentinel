"""
extractor.py
────────────
Extracts the 30 features used by the UCI Phishing Websites dataset.
Each feature returns:  1 = Legitimate,  0 = Suspicious,  -1 = Phishing

Feature index map (matches views.py heuristic rules exactly):
  [0]  having_IP_Address
  [1]  URL_Length
  [2]  Shortining_Service
  [3]  having_At_Symbol
  [4]  double_slash_redirecting
  [5]  Prefix_Suffix  (hyphen in domain)
  [6]  having_Sub_Domain
  [7]  SSLfinal_State  (HTTPS)
  [8]  Domain_registeration_length  (static default)
  [9]  Favicon  (static default)
  [10] port
  [11] HTTPS_token
  [12] Request_URL  (static default)
  [13] URL_of_Anchor  (static default)
  [14] Links_in_tags  (static default)
  [15] SFH  (static default)
  [16] Submitting_to_email
  [17] Abnormal_URL
  [18] Redirect
  [19] on_mouseover  (static default)
  [20] RightClick  (static default)
  [21] popUpWidnow  (static default)
  [22] Iframe  (static default)
  [23] age_of_domain  (static default)
  [24] DNSRecord  (static default)
  [25] web_traffic  (static default)
  [26] Page_Rank  (static default)
  [27] Google_Index  (static default)
  [28] Links_pointing_to_page  (static default)
  [29] Statistical_report  (static default)
"""

import re
from urllib.parse import urlparse

# Known URL shortener domains
SHORTENERS = {
    'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'is.gd',
    'buff.ly', 'adf.ly', 'bl.ink', 'rb.gy', 'cutt.ly', 'shorte.st',
    'tiny.cc', 'lnkd.in', 'mcaf.ee', 'su.pr', 'dlvr.it', 'url4.eu',
}

# Ports that indicate phishing
SUSPICIOUS_PORTS = {21, 22, 23, 445, 1433, 3306, 8080, 8443}


def _get_parsed(url: str):
    """Ensure URL has a scheme so urlparse works correctly."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return urlparse(url)


def _having_ip_address(url: str) -> int:
    """Return -1 if URL uses an IP address instead of a domain name."""
    ipv4 = re.compile(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])')
    # Hex IP like 0x7f000001
    hex_ip = re.compile(r'(0x[0-9a-fA-F]{1,2}\.){3}0x[0-9a-fA-F]{1,2}')
    hostname = _get_parsed(url).hostname or ''
    if ipv4.match(hostname) or hex_ip.search(url):
        return -1
    return 1


def _url_length(url: str) -> int:
    length = len(url)
    if length < 54:
        return 1
    if length <= 75:
        return 0
    return -1


def _shortening_service(url: str) -> int:
    hostname = (_get_parsed(url).hostname or '').lower()
    if hostname in SHORTENERS:
        return -1
    return 1


def _having_at_symbol(url: str) -> int:
    return -1 if '@' in url else 1


def _double_slash_redirecting(url: str) -> int:
    """Return -1 if '//' appears after position 7 (after the scheme)."""
    pos = url.find('//', 7)
    return -1 if pos > 0 else 1


def _prefix_suffix(url: str) -> int:
    """Return -1 if domain contains a hyphen."""
    hostname = (_get_parsed(url).hostname or '')
    return -1 if '-' in hostname else 1


def _having_sub_domain(url: str) -> int:
    """
    Count dots in the registered domain (excluding TLD and www).
    0 dots → 1 (legit), 1 dot → 0 (suspicious), 2+ dots → -1 (phishing)
    """
    hostname = (_get_parsed(url).hostname or '').lower()
    if hostname.startswith('www.'):
        hostname = hostname[4:]
    parts = hostname.split('.')
    # parts[-1] = TLD, parts[-2] = domain name, anything before = subdomains
    subdomain_count = len(parts) - 2
    if subdomain_count <= 0:
        return 1
    if subdomain_count == 1:
        return 0
    return -1


def _ssl_final_state(url: str) -> int:
    """Return 1 if HTTPS, -1 if HTTP."""
    return 1 if url.startswith('https://') else -1


def _port(url: str) -> int:
    parsed = _get_parsed(url)
    port = parsed.port
    if port is None:
        return 1
    return -1 if port in SUSPICIOUS_PORTS else 0


def _https_token_in_domain(url: str) -> int:
    """Return -1 if 'https' literally appears in the domain name (spoofing)."""
    hostname = (_get_parsed(url).hostname or '').lower()
    return -1 if 'https' in hostname else 1


def _submitting_to_email(url: str) -> int:
    return -1 if 'mailto:' in url.lower() else 1


def _abnormal_url(url: str) -> int:
    """Return -1 if the hostname is not present in the full URL (abnormal structure)."""
    hostname = (_get_parsed(url).hostname or '')
    return 1 if hostname and hostname in url else -1


def _redirect(url: str) -> int:
    """Return -1 if URL contains multiple '//' (possible redirect chaining)."""
    count = url.count('//')
    return -1 if count > 1 else 1


# ─── Main Feature Extractor ───────────────────────────────────────────────────
def extract_features(url: str) -> list:
    """
    Return a list of 30 integers matching the UCI phishing feature order.
    Features that require live HTTP/DNS lookups default to a neutral value (0).
    """
    features = [
        _having_ip_address(url),       # [0]
        _url_length(url),              # [1]
        _shortening_service(url),      # [2]
        _having_at_symbol(url),        # [3]
        _double_slash_redirecting(url),# [4]
        _prefix_suffix(url),           # [5]  ← views.py heuristic uses this
        _having_sub_domain(url),       # [6]  ← views.py heuristic uses this
        _ssl_final_state(url),         # [7]  ← views.py heuristic uses this
        0,                             # [8]  domain_registration_length (DNS needed)
        1,                             # [9]  favicon (HTTP needed)
        _port(url),                    # [10]
        _https_token_in_domain(url),   # [11]
        0,                             # [12] request_url (HTTP needed)
        0,                             # [13] url_of_anchor (HTTP needed)
        0,                             # [14] links_in_tags (HTTP needed)
        0,                             # [15] SFH (HTTP needed)
        _submitting_to_email(url),     # [16]
        _abnormal_url(url),            # [17]
        _redirect(url),                # [18]
        1,                             # [19] on_mouseover (HTTP needed)
        1,                             # [20] right_click (HTTP needed)
        1,                             # [21] pop_up_window (HTTP needed)
        1,                             # [22] iframe (HTTP needed)
        0,                             # [23] age_of_domain (DNS needed)
        0,                             # [24] dns_record (DNS needed)
        0,                             # [25] web_traffic (API needed)
        0,                             # [26] page_rank (API needed)
        0,                             # [27] google_index (API needed)
        0,                             # [28] links_pointing_to_page (API needed)
        0,                             # [29] statistical_report (API needed)
    ]
    return features
