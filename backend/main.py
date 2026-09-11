from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import tempfile
import os
from backend.report_engine import generate_forensic_report
from backend.email_parser import parse_email
from backend.threat_detector import analyze_email
from backend.geo_intelligence import geolocate_ip


app = FastAPI()


# =========================
# CORS Configuration
# =========================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
# Root Endpoint
# =========================

@app.get("/")
def read_root():

    return {
        "message": "SIH26106 Email Threat Intelligence API"
    }


# =========================
# Email Analysis Endpoint
# =========================

@app.post("/analyze-email")
async def analyze_email_endpoint(
    file: UploadFile = File(...)
):

    suffix = os.path.splitext(
        file.filename
    )[1]

    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=suffix
    ) as temp_file:

        temp_file.write(
            await file.read()
        )

        temp_path = temp_file.name

    try:

        # Parse email
        result = parse_email(
            temp_path
        )

        # Threat analysis
        threat_analysis = analyze_email(
            result
        )

        # IP Geolocation
        geo_analysis = geolocate_ip(
            result.get("sender_ip")
        )

        report = generate_forensic_report(
            result,
            threat_analysis,
            geo_analysis
        )

        return {
            "email": result,
            "threat_analysis": threat_analysis,
            "geo_analysis": geo_analysis,
            "forensic_report": report
        }

    finally:

        os.remove(
            temp_path
        )