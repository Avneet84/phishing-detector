from fastapi import FastAPI
from pydantic import BaseModel
import pickle
import requests
import re
import pandas as pd
from bs4 import BeautifulSoup
import whois
from urllib.parse import urlparse

app = FastAPI()

# Load model
model = pickle.load(open('phishing.pkl', 'rb'))
vectorizer = pickle.load(open('vectorizer.pkl', 'rb'))

class URLRequest(BaseModel):
    url: str

# ---------------- ML ----------------
def ml_predict(url):
    data = vectorizer.transform([url])
    return model.predict(data)[0]

# ---------------- Google API ----------------
API_KEY = "AIzaSyDFIGlVbxsZt87xaBViwYGEb8PQzDQicSQ"

def google_check(url):
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        res = requests.post(api_url, json=payload)
        return "bad" if "matches" in res.json() else "good"
    except:
        return "error"

# ---------------- API ROUTE ----------------
@app.post("/predict")
def predict(data: URLRequest):
    url = data.url

    ml_result = ml_predict(url)
    google_result = google_check(url)

    if google_result == "bad":
        result = "🚨 Dangerous (Google)"
    elif ml_result == "bad":
        result = "⚠️ Suspicious (ML)"
    else:
        result = "✅ Safe"

    return {"result": result}
