"""Offline phishing-message heuristic. URLs are parsed as text and never fetched."""
from __future__ import annotations
import re
from urllib.parse import urlparse

URL_RE=re.compile(r"https?://[^\s<>\"']+",re.I)
SIGNALS={
 "urgency":re.compile(r"\b(urgent|immediately|account suspended|within 24 hours)\b",re.I),
 "credential_request":re.compile(r"\b(password|verify your account|login credentials|one-time code)\b",re.I),
 "payment_pressure":re.compile(r"\b(gift card|wire transfer|payment required)\b",re.I),
}
SHORTENERS={"bit.ly","tinyurl.com","t.co","is.gd"}
def analyze_message(message: str) -> dict:
    if not isinstance(message,str): raise ValueError("Message must be text")
    score=0; reasons=[]
    for label,pattern in SIGNALS.items():
        if pattern.search(message): score+=25; reasons.append(label)
    for raw in URL_RE.findall(message):
        parsed=urlparse(raw); host=(parsed.hostname or "").lower()
        if parsed.scheme.lower()=="http": score+=10; reasons.append("unencrypted_http")
        if host in SHORTENERS: score+=20; reasons.append("url_shortener")
        if parsed.username or parsed.password: score+=20; reasons.append("url_embeds_credentials")
    score=min(score,100)
    return {"score":score,"verdict":"suspicious" if score>=40 else "review" if score>=20 else "lower-risk","signals":sorted(set(reasons)),"urls_inspected":len(URL_RE.findall(message)),"urls_fetched":False}
if __name__=="__main__":
    print(analyze_message("URGENT: verify your account password at http://example.invalid/login"))
