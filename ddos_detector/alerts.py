import logging
import smtplib
from email.message import EmailMessage


class AlertManager:
    """Email and log alert manager."""

    def __init__(self, email_alert: str = "no", sms_alert: str = "no",
                 smtp_server: str = "", smtp_port: str = "25",
                 email_from: str = "", email_to: str = "",
                 email_user: str = "", email_pass: str = ""):
        self.email_alert = (email_alert or "").lower() == "yes"
        self.sms_alert = (sms_alert or "").lower() == "yes"
        self.smtp_server = smtp_server
        self.smtp_port = int(smtp_port) if smtp_port else 25
        self.email_from = email_from
        self.email_to = email_to
        self.email_user = email_user
        self.email_pass = email_pass

    def send_alert(self, message: str):
        logging.warning("ALERT: %s", message)
        if self.email_alert and self.smtp_server and self.email_to:
            self.send_email_alert(message)

    def send_email_alert(self, message: str):
        try:
            msg = EmailMessage()
            msg.set_content(message)
            msg["Subject"] = "DDoS Detection Alert"
            msg["From"] = self.email_from
            msg["To"] = self.email_to
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                if self.email_user and self.email_pass:
                    server.login(self.email_user, self.email_pass)
                server.send_message(msg)
            logging.info("Email alert sent.")
        except Exception as exc:
            logging.error("Error sending email alert: %s", exc)
