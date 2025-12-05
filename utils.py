import re
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup


DEFAULT_HEADERS = {
    "User-Agent": "WebScanPro/1.0"
}


SQL_ERROR_PATTERNS = [
    r"SQL syntax",
    r"mysql_fetch",
    r"you have an error in your sql syntax",
    r"unterminated quoted string",
    r"Oracle error",
    r"SQLSTATE",
    r"PDOException",
    r"mysqli_sql",
    r"syntax error.*near",
]

XSS_REFLECT_PATTERNS = [
    r"<script>alert\(",
    r"<img src=x onerror=alert",
]


def get_session():
    s = requests.Session()
    s.headers.update(DEFAULT_HEADERS)
    return s


def is_same_domain(base, url):
    return urlparse(base).netloc == urlparse(url).netloc


def normalize_url(base, link):
    if not link:
        return None
    return urljoin(base, link)


def extract_links(html, base_url):
    soup = BeautifulSoup(html, "lxml")
    links = set()

    for tag in soup.find_all(['a', 'link', 'area']):
        href = tag.get('href')
        if href:
            full = normalize_url(base_url, href)
            links.add(full)

    for form in soup.find_all('form'):
        action = form.get('action') or base_url
        links.add(normalize_url(base_url, action))

    return links


def extract_forms(html, base_url):
    soup = BeautifulSoup(html, "lxml")
    forms = []

    for form in soup.find_all('form'):
        method = (form.get('method') or 'get').lower()
        action = normalize_url(base_url, form.get('action') or base_url)

        inputs = []
        for inp in form.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            if not name:
                continue

            input_type = inp.get('type', 'text')
            value = inp.get('value') or ''
            inputs.append({'name': name, 'type': input_type, 'value': value})

        forms.append({'method': method, 'action': action, 'inputs': inputs})

    return forms


def find_sql_errors(text):
    t = text.lower()
    for pat in SQL_ERROR_PATTERNS:
        if re.search(pat.lower(), t):
            return True, pat
    return False, None


def find_xss_reflection(text):
    t = text.lower()
    for pat in XSS_REFLECT_PATTERNS:
        if re.search(pat.lower(), t):
            return True, pat
    return False, None
