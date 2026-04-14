# =========================================
# 🔐 Advanced Phishing URL Detector
# ML + Google API + URL Features + Gradio
# =========================================

import pickle
import requests
import gradio as gr
import re
import pandas as pd
from bs4 import BeautifulSoup
import whois
from urllib.parse import urlparse

# -------------------------------
# ✅ Load Model & Vectorizer
# -------------------------------
model = pickle.load(open('phishing.pkl', 'rb'))
vectorizer = pickle.load(open('vectorizer.pkl', 'rb'))

# -------------------------------
# ✅ ML Prediction
# -------------------------------
def ml_predict(url):
    data = vectorizer.transform([url])
    return model.predict(data)[0]

# -------------------------------
# ✅ Google Safe Browsing API
# -------------------------------
API_KEY = "AIzaSyBmh9Plyyqq6O9JITYRbuN5-svMr1r8jIY"   # 🔑 Replace

def google_check(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    payload = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        res = requests.post(api_url, json=payload, timeout=5)
        result = res.json()
        return "bad" if "matches" in result else "good"
    except:
        return "error"




# -------------------------------
# ✅ Fetch Website Content
# -------------------------------
def fetch_website_text(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        return soup.get_text()[:2000]
    except:
        return ""

# -------------------------------
# ✅ WHOIS Domain Age
# -------------------------------
def get_domain_age(url):
    try:
        domain_name = urlparse(url).netloc
        domain = whois.whois(domain_name)

        creation_date = domain.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (pd.Timestamp.now() - pd.to_datetime(creation_date)).days
            return age_days
        else:
            return "Unknown"

    except:
        return "Unknown"

# -------------------------------
# ✅ VirusTotal API
# -------------------------------
VT_API_KEY = "47e0bafb2b0ae7cd5822f066f1353ac666fbb9fe1fb40c1fe1508aacb66c3440"

def virustotal_check(url):
    try:
        api_url = "https://www.virustotal.com/api/v3/urls"

        headers = {
            "x-apikey": VT_API_KEY
        }

        res = requests.post(api_url, headers=headers, data={"url": url})
        url_id = res.json()["data"]["id"]

        report_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
        report = requests.get(report_url, headers=headers).json()

        stats = report["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)

        return "bad" if malicious > 0 else "good"

    except:
        return "error"
# -------------------------------
# ✅ URL Feature Extraction
# -------------------------------
def extract_url_features(url):
    features = {}

    features["URL Length"] = len(url)
    features["Dots Count"] = url.count('.')
    features["HTTPS"] = "Yes" if url.startswith("https") else "No"

    ip_pattern = r'\d+\.\d+\.\d+\.\d+'
    features["IP Address Used"] = "Yes" if re.search(ip_pattern, url) else "No"

    features["@ Symbol"] = "Yes" if '@' in url else "No"
    features["Hyphen (-)"] = "Yes" if '-' in url else "No"
    features["Redirect (//)"] = "Yes" if url.count('//') > 1 else "No"

    suspicious_ext = ['.xyz', '.tk', '.ml', '.ga']
    features["Suspicious Domain"] = "Yes" if any(ext in url for ext in suspicious_ext) else "No"

    return features

# -------------------------------
# ✅ Feature Explanation
# -------------------------------
def explain_features(features):
    reasons = []

    if features["URL Length"] > 50:
        reasons.append("URL is too long")

    if features["Dots Count"] > 3:
        reasons.append("Too many subdomains")

    if features["HTTPS"] == "No":
        reasons.append("Not using HTTPS")

    if features["IP Address Used"] == "Yes":
        reasons.append("Uses IP address instead of domain")

    if features["@ Symbol"] == "Yes":
        reasons.append("Contains @ symbol (redirect trick)")

    if features["Hyphen (-)"] == "Yes":
        reasons.append("Contains hyphen (-)")

    if features["Redirect (//)"] == "Yes":
        reasons.append("Multiple redirections detected")

    if features["Suspicious Domain"] == "Yes":
        reasons.append("Suspicious domain extension")

    return reasons

# -------------------------------
# ✅ Final Prediction Function
# -------------------------------
def final_predict(url):
    if url.strip() == "":
        return "⚠️ Please enter a URL"
    # -------------------------
    # ML + Google
    # -------------------------
    ml_result = ml_predict(url)
    google_result = google_check(url)

    # -------------------------
    # NEW: Fetch Website Content
    # -------------------------
    page_text = fetch_website_text(url)

    combined_input = url + " " + page_text[:500]
    ml_result_content = model.predict(vectorizer.transform([combined_input]))[0]

    # -------------------------
    # NEW: WHOIS Domain Age
    # -------------------------
    domain_age = get_domain_age(url)

    # -------------------------
    # NEW: VirusTotal
    # -------------------------
    vt_result = virustotal_check(url)

 # -------------------------
    # Feature Analysis
    # -------------------------
    features = extract_url_features(url)
    reasons = explain_features(features)

    # -------------------------
    # FINAL OUTPUT
    # -------------------------
    output = "🔍 RESULT\n\n"

    # Decision Logic
    if google_result == "bad" or vt_result == "bad":
        output += "🚨 Dangerous (API Confirmed)\n\n"

    elif ml_result == "bad" or ml_result_content == "bad":
        output += "⚠️ Suspicious (ML Detected)\n\n"

    else:
        output += "✅ Safe Website\n\n"

    # Extra Info
    output += f"🌐 Google Check: {google_result}\n"
    output += f"🛡️ VirusTotal: {vt_result}\n"
    output += f"🤖 ML (URL): {ml_result}\n"
    output += f"🤖 ML (Content): {ml_result_content}\n"
    output += f"📅 Domain Age: {domain_age} days\n\n"

 # Features
    output += "📊 URL Feature Analysis:\n"
    for k, v in features.items():
        output += f"- {k}: {v}\n"

    # Reasons
    if reasons:
        output += "\n💡 Why Suspicious:\n"
        for r in reasons:
            output += f"- {r}\n"

    return output

# -------------------------------
# ✅ Gradio UI
# -------------------------------
interface = gr.Interface(
    fn=final_predict,
    inputs=gr.Textbox(label="Enter URL"),
    outputs=gr.Textbox(label="Result"),
    title="🔐 Phishing Detector API"
).queue()

# IMPORTANT for deployment
interface.launch(server_name="0.0.0.0", server_port=7860, share=True)
