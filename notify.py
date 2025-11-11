import os
import smtplib
from email.message import EmailMessage

def send_email(subject: str, body: str, to_addr: str = None):
    to_addr = to_addr or os.getenv("NOTIFY_EMAIL")
    if not to_addr:
        return
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", 587))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASS")
    if not (host and user and password):
        return
    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to_addr
    try:
        with smtplib.SMTP(host, port) as s:
            s.starttls()
            s.login(user, password)
            s.send_message(msg)
    except Exception as e:
        print("Failed to send email:", e)
