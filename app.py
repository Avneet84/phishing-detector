from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pickle

app = FastAPI()

# ✅ CORS (IMPORTANT)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load model
model = pickle.load(open('phishing.pkl', 'rb'))
vectorizer = pickle.load(open('vectorizer.pkl', 'rb'))

class URLRequest(BaseModel):
    url: str

@app.get("/")
def home():
    return {"message": "Backend running"}

@app.post("/predict")
def predict(data: URLRequest):
    url = data.url
    prediction = model.predict(vectorizer.transform([url]))[0]

    if prediction == "bad":
        return {"result": "⚠️ Suspicious Website"}
    else:
        return {"result": "✅ Safe Website"}
