from pathlib import Path

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

import os
import base64

BASE_DIR = Path(__file__).resolve().parent
TOKEN_PATH = BASE_DIR / "token.json"
CREDENTIALS_PATH = BASE_DIR / "credentials.json"
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def load_gmail_credentials():
    creds = None

    if TOKEN_PATH.exists():
        try:
            creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)
        except Exception as exc:
            print("Stored Gmail token is invalid. Re-authenticating.", exc)
            if TOKEN_PATH.exists():
                TOKEN_PATH.unlink(missing_ok=True)
            creds = None

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as exc:
                print("Gmail token refresh failed. Re-authenticating.", exc)
                if TOKEN_PATH.exists():
                    TOKEN_PATH.unlink(missing_ok=True)
                creds = None

        if not creds or not creds.valid:
            if not CREDENTIALS_PATH.exists():
                raise FileNotFoundError(
                    "Google credentials file not found. Please add credentials.json."
                )

            flow = InstalledAppFlow.from_client_secrets_file(
                str(CREDENTIALS_PATH),
                SCOPES
            )
            creds = flow.run_local_server(port=0)

            if not creds:
                raise RuntimeError("Unable to authenticate with Gmail.")

    with open(TOKEN_PATH, "w", encoding="utf-8") as token:
        token.write(creds.to_json())

    return creds


def get_gmail_messages():
    try:
        creds = load_gmail_credentials()
    except Exception as exc:
        raise RuntimeError(
            "Gmail authentication expired or is no longer valid. Please reconnect your Google account."
        ) from exc

    service = build("gmail", "v1", credentials=creds)

    results = service.users().messages().list(
        userId="me",
        maxResults=10
    ).execute()

    messages = results.get("messages", [])

    email_list = []

    for msg in messages:

        txt = service.users().messages().get(
            userId="me",
            id=msg["id"],
            format="full"
        ).execute()

        headers = txt["payload"].get("headers", [])

        subject = ""
        sender = ""

        for h in headers:
            if h["name"] == "Subject":
                subject = h["value"]

            if h["name"] == "From":
                sender = h["value"]

        body = ""

        payload = txt.get("payload", {})

        if "parts" in payload:

            for part in payload["parts"]:

                if part.get("mimeType") == "text/plain":

                    data = part["body"].get("data")

                    if data:
                        body = base64.urlsafe_b64decode(
                            data.encode("UTF-8")
                        ).decode("utf-8", errors="ignore")

        else:

            data = payload.get("body", {}).get("data")

            if data:
                body = base64.urlsafe_b64decode(
                    data.encode("UTF-8")
                ).decode("utf-8", errors="ignore")

        email_list.append({
            "subject": subject,
            "sender": sender,
            "body": body
        })

    return email_list