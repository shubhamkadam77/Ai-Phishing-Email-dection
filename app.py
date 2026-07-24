from pathlib import Path

from flask import Flask, render_template, request
import joblib
import re
import sqlite3
import requests
import os
from html import unescape
import time

from database import init_db
from gmail_api import get_gmail_messages


# =====================================================
# FLASK APPLICATION
# =====================================================

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model" / "phishing_model.pkl"
VECTORIZER_PATH = BASE_DIR / "model" / "vectorizer.pkl"
DB_PATH = BASE_DIR / "phishing.db"


# =====================================================
# LOAD MACHINE LEARNING MODEL
# =====================================================

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)
init_db(str(DB_PATH))


# =====================================================
# VIRUSTOTAL API KEY

VT_API_KEY = os.getenv("VT_API_KEY", "")


# =====================================================
# EMAIL CLASSIFICATION THRESHOLD
# =====================================================

PHISHING_THRESHOLD = 0.70
SAFE_THRESHOLD = 0.70


# =====================================================
# CLEAN EMAIL BODY
# =====================================================

def clean_email_text(text):

    if not text:
        return ""

    # Decode HTML entities
    text = unescape(text)

    # Remove style blocks
    text = re.sub(
        r"<style.*?>.*?</style>",
        " ",
        text,
        flags=re.IGNORECASE | re.DOTALL
    )

    # Remove script blocks
    text = re.sub(
        r"<script.*?>.*?</script>",
        " ",
        text,
        flags=re.IGNORECASE | re.DOTALL
    )

    # Remove HTML tags
    text = re.sub(
        r"<[^>]+>",
        " ",
        text
    )

    # Remove excessive spaces
    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


# =====================================================
# EXTRACT URLS
# =====================================================

def extract_urls(text):

    if not text:
        return []

    urls = re.findall(
        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
        text
    )

    # Remove common punctuation from URL ending
    cleaned_urls = []

    for url in urls:

        url = url.rstrip(
            ".,);]}>"
        )

        cleaned_urls.append(url)

    return cleaned_urls


# =====================================================
# VIRUSTOTAL URL CHECK
# =====================================================

def check_url_virustotal(url):

    if not VT_API_KEY:
        print("VirusTotal API key is not configured.")
        return None

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=15
        )

        if response.status_code not in (200, 201):
            print(
                "VirusTotal Submit Error:",
                response.status_code,
                response.text
            )
            return None

        analysis_id = response.json().get("data", {}).get("id")

        if not analysis_id:
            print("VirusTotal did not return an analysis ID.")
            return None

        for _ in range(5):
            analysis = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=15
            )

            if analysis.status_code != 200:
                print(
                    "VirusTotal Analysis Error:",
                    analysis.status_code
                )
                return None

            data = analysis.json().get("data", {}).get("attributes", {})
            status = data.get("status")

            if status == "completed":
                stats = data.get("stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                }

            time.sleep(2)

        print("VirusTotal analysis still processing.")
        return None

    except requests.RequestException as e:
        print("VirusTotal Network Error:", e)
        return None

    except Exception as e:
        print("VirusTotal Error:", e)
        return None


# =====================================================
# CLASSIFY EMAIL USING AI MODEL
# =====================================================

def classify_email(subject, body):

    # Clean raw HTML email

    cleaned_body = clean_email_text(body)


    # Combine subject + clean body

    email_content = f"""

    Subject: {subject}

    {cleaned_body}

    """


    # Convert email to TF-IDF vector

    vector = vectorizer.transform(
        [email_content]
    )


    # Get probability

    probability = model.predict_proba(
        vector
    )[0]


    # IMPORTANT:
    # This assumes model classes are 0 = Safe, 1 = Phishing.

    class_probabilities = dict(
        zip(
            model.classes_,
            probability
        )
    )


    safe_probability = float(
        class_probabilities.get(0, 0)
    )


    phishing_probability = float(
        class_probabilities.get(1, 0)
    )


    # ---------------------------------
    # PHISHING
    # ---------------------------------

    if phishing_probability >= PHISHING_THRESHOLD:

        return {

            "prediction":
                "⚠️ Phishing",

            "confidence":
                round(
                    phishing_probability * 100,
                    2
                ),

            "cleaned_body":
                cleaned_body

        }


    # ---------------------------------
    # SAFE
    # ---------------------------------

    elif safe_probability >= SAFE_THRESHOLD:

        return {

            "prediction":
                "✅ Safe",

            "confidence":
                round(
                    safe_probability * 100,
                    2
                ),

            "cleaned_body":
                cleaned_body

        }


    # ---------------------------------
    # SUSPICIOUS / UNCERTAIN
    # ---------------------------------

    else:

        confidence = round(

            max(
                safe_probability,
                phishing_probability
            ) * 100,

            2

        )


        return {

            "prediction":
                "⚠️ Suspicious",

            "confidence":
                confidence,

            "cleaned_body":
                cleaned_body

        }


# =====================================================
# PART 2 STARTS BELOW
# HOME ROUTE + MANUAL EMAIL SCANNER
# =====================================================

# =====================================================
# HOME PAGE
# =====================================================

@app.route("/", methods=["GET", "POST"])
def home():

    prediction = None
    confidence = None
    risk_level = None
    suspicious_urls = []
    vt_result = None
    gmail_results = []
    gmail_error = None
    result = 0
    is_phishing = False
    is_suspicious = False
    safe_count = 0
    suspicious_count = 0
    phishing_count = 0

    if request.method == "POST":

        # =================================================
        # GET MANUAL EMAIL
        # =================================================

        email = request.form.get(
            "email",
            ""
        ).strip()


        # If email is empty

        if not email:

            return render_template(
                "index.html",
                prediction=None,
                confidence=None,
                urls=[],
                is_phishing=False,
                is_suspicious=False,
                vt_result=None,
                gmail_results=[],
                gmail_error=None,
                safe_count=0,
                suspicious_count=0,
                phishing_count=0
            )


        # =================================================
        # EXTRACT URLS
        # =================================================

        suspicious_urls = extract_urls(
            email
        )


        print(
            "URLs:",
            suspicious_urls
        )


        # =================================================
        # VIRUSTOTAL SCAN
        # =================================================

        if suspicious_urls:

            vt_result = check_url_virustotal(

                suspicious_urls[0]

            )


        # =================================================
        # MANUAL EMAIL AI PREDICTION
        # =================================================

        cleaned_email = clean_email_text(
            email
        )


        email_vector = vectorizer.transform(

            [cleaned_email]

        )


        probabilities = model.predict_proba(

            email_vector

        )[0]


        class_probabilities = dict(

            zip(

                model.classes_,

                probabilities

            )

        )


        safe_probability = float(

            class_probabilities.get(
                0,
                0
            )

        )


        phishing_probability = float(

            class_probabilities.get(
                1,
                0
            )

        )


        # =================================================
        # MANUAL EMAIL CLASSIFICATION
        # =================================================


        # PHISHING

        if phishing_probability >= PHISHING_THRESHOLD:

            result = 1

            prediction = "⚠️ Phishing Email"
            risk_level = "HIGH RISK"

            confidence = round(

                phishing_probability * 100,

                2

            )


        # SAFE

        elif safe_probability >= SAFE_THRESHOLD:

            result = 0

            prediction = "✅ Safe Email"
            risk_level = "LOW RISK"

            confidence = round(

                safe_probability * 100,

                2

            )


        # SUSPICIOUS

        else:

            result = 2

            prediction = "⚠️ Suspicious Email"
            risk_level = "MEDIUM RISK"

            confidence = round(

                max(

                    safe_probability,

                    phishing_probability

                ) * 100,

                2

            )


        is_phishing = result == 1
        is_suspicious = result == 2

        # =================================================
        # SAVE MANUAL SCAN TO DATABASE
        # =================================================

        try:

            conn = sqlite3.connect(

                str(DB_PATH)

            )


            cursor = conn.cursor()


            cursor.execute(

                """
                INSERT INTO scan_history
                (
                    email,
                    prediction,
                    confidence
                )
                VALUES (?, ?, ?)
                """,

                (

                    email,

                    prediction,

                    confidence

                )

            )


            conn.commit()

            conn.close()


        except Exception as e:

            print(

                "Database Error:",

                e

            )

    return render_template(
        "index.html",
        prediction=prediction,
        confidence=confidence,
        risk_level=risk_level,
        urls=suspicious_urls,
        is_phishing=is_phishing,
        is_suspicious=is_suspicious,
        vt_result=vt_result,
        gmail_results=gmail_results,
        gmail_error=gmail_error,
        safe_count=safe_count,
        suspicious_count=suspicious_count,
        phishing_count=phishing_count
    )


# -------------------------------------
# Gmail Inbox AI Scan
# -------------------------------------
@app.route("/scan-gmail")
def scan_gmail():

    gmail_results = []
    gmail_error = None
    safe_count = 0
    suspicious_count = 0
    phishing_count = 0

    try:
        gmail_emails = get_gmail_messages()

        for mail in gmail_emails:
            body = mail.get("body", "").strip()

            if not body:
                continue

            vector = vectorizer.transform([body])
            probabilities = model.predict_proba(vector)[0]
            class_probabilities = dict(zip(model.classes_, probabilities))

            safe_probability = float(class_probabilities.get(0, 0))
            phishing_probability = float(class_probabilities.get(1, 0))

            if phishing_probability >= PHISHING_THRESHOLD:
                gmail_prediction = "⚠️ Phishing"
            elif safe_probability >= SAFE_THRESHOLD:
                gmail_prediction = "✅ Safe"
            else:
                gmail_prediction = "⚠️ Suspicious"

            gmail_confidence = round(max(safe_probability, phishing_probability) * 100, 2)

            gmail_results.append({
                "subject": mail.get("subject", "No Subject"),
                "sender": mail.get("sender", "Unknown"),
                "body": body,
                "prediction": gmail_prediction,
                "confidence": gmail_confidence
            })

    except Exception as e:
        gmail_error = str(e)
        print("Gmail Error:", e)

    safe_count = sum(
        1 for mail in gmail_results
        if mail["prediction"] == "✅ Safe"
    )

    suspicious_count = sum(
        1 for mail in gmail_results
        if mail["prediction"] == "⚠️ Suspicious"
    )

    phishing_count = sum(
        1 for mail in gmail_results
        if mail["prediction"] == "⚠️ Phishing"
    )

    return render_template(
        "index.html",
        prediction=None,
        confidence=None,
        risk_level=None,
        urls=[],
        is_phishing=False,
        is_suspicious=False,
        vt_result=None,
        gmail_results=gmail_results,
        gmail_error=gmail_error,
        safe_count=safe_count,
        suspicious_count=suspicious_count,
        phishing_count=phishing_count
    )

# =====================================================
# PART 3 STARTS BELOW
# SCAN HISTORY + RUN FLASK
# =====================================================

# =====================================================
# SCAN HISTORY PAGE
# =====================================================

@app.route("/history")
def history():
    conn = None

    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, email, prediction, confidence, date
            FROM scan_history
            ORDER BY id DESC
            """
        )

        rows = cursor.fetchall()

        total_scans = len(rows)
        safe_count = sum(1 for row in rows if row[2] and "Safe" in row[2])
        suspicious_count = sum(1 for row in rows if row[2] and "Suspicious" in row[2])
        phishing_count = sum(1 for row in rows if row[2] and "Phishing" in row[2])

        return render_template(
            "history.html",
            history=rows,
            total_scans=total_scans,
            safe_count=safe_count,
            suspicious_count=suspicious_count,
            phishing_count=phishing_count
        )

    except Exception as e:
        print("History Database Error:", e)
        return render_template(
            "history.html",
            history=[],
            total_scans=0,
            safe_count=0,
            suspicious_count=0,
            phishing_count=0
        )

    finally:
        if conn:
            conn.close()


# =====================================================
# RUN FLASK APPLICATION
# =====================================================

if __name__ == "__main__":

    app.run(

        debug=True,

        host="127.0.0.1",

        port=5000

    )
    
    