from bs4 import BeautifulSoup
import re

def scan_html_for_anomalies(html_code):
    soup = BeautifulSoup(html_code, "html.parser")
    issues = []

    # Suspicious JavaScript
    for script in soup.find_all("script"):
        if script.string:
            if "eval" in script.string or "fromCharCode" in script.string:
                issues.append("⚠️ Suspicious JS: eval/fromCharCode")
            if "base64," in script.string:
                issues.append("⚠️ Obfuscated base64 in JS")

    # Inline JS (XSS vector)
    for tag in soup.find_all(True):
        for attr in tag.attrs:
            if attr.lower().startswith("on"):
                issues.append(f"⚠️ Inline event handler: {attr} in <{tag.name}>")

    # Suspicious iframe sources
    for iframe in soup.find_all("iframe"):
        src = iframe.get("src", "")
        if "http" in src and not src.startswith("https://trusted.com"):
            issues.append(f"⚠️ Suspicious iframe: {src}")

    # Hidden elements
    for tag in soup.select('[style*="display:none"], [style*="visibility:hidden"]'):
        issues.append("⚠️ Hidden element found")

    return issues
