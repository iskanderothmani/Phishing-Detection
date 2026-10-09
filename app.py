"""Offline suspicious-message triage. Does not open links or contact remote services."""
import re
from urllib.parse import urlparse
URL_RE=re.compile(r"https?://[^\s<>\"']+",re.I)
def analyze_message(message):
 if not isinstance(message,str): raise ValueError("Message must be text")
 score=0; signals=[]
 for label,pattern in [("urgency",r"\b(urgent|immediately|account suspended|within 24 hours)\b"),("credential_request",r"\b(password|verify your account|login credentials|one-time code)\b"),("payment_pressure",r"\b(gift card|wire transfer|payment required)\b")]:
  if re.search(pattern,message,re.I): score+=25; signals.append(label)
 urls=URL_RE.findall(message)
 for raw in urls:
  parsed=urlparse(raw)
  if parsed.scheme.lower()=="http": score+=10; signals.append("unencrypted_http")
  if (parsed.hostname or "").lower() in {"bit.ly","tinyurl.com","t.co","is.gd"}: score+=20; signals.append("url_shortener")
 score=min(score,100)
 return {"score":score,"verdict":"suspicious" if score>=40 else "review" if score>=20 else "lower-risk","signals":sorted(set(signals)),"urls_inspected":len(urls),"urls_fetched":False}
if __name__=="__main__": print(analyze_message("URGENT: verify your account password at http://example.invalid"))
