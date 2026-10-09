"""Offline phishing-message heuristic demo. Never opens or fetches URLs."""
import re
from urllib.parse import urlparse
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
SIGNALS = {
    "urgent language": re.compile(r"\b(urgent|immediately|within 24 hours|account suspended)\b", re.I),
    "credential request": re.compile(r"\b(password|verify your account|login credentials|one-time code)\b", re.I),
    "payment pressure": re.compile(r"\b(gift card|wire transfer|payment required)\b", re.I),
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd"}

def analyze_message(text: str) -> dict:
    reasons, score = [], 0
    for label, pattern in SIGNALS.items():
        if pattern.search(text):
            score += 25; reasons.append(label)
    for url in URL_RE.findall(text):
        host = (urlparse(url).hostname or "").lower()
        if host in SHORTENERS:
            score += 20; reasons.append("URL shortener present")
        if urlparse(url).scheme.lower() == "http":
            score += 10; reasons.append("URL uses HTTP")
    score = min(score, 100)
    return {"score": score, "verdict": "suspicious" if score >= 40 else "review" if score >= 20 else "lower-risk", "signals": sorted(set(reasons))}

if __name__ == "__main__":
    print(analyze_message("URGENT: verify your account password immediately at http://example.invalid/login"))
