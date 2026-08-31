"""Webhook handler for a delivery-failure bounce notice from the mail relay."""
import smtplib


def handle_bounce_webhook(request):
    """Relay a delivery-failure notice using raw SMTP envelope commands.

    The upstream relay POSTs the original sender address of the bounced
    message; it is forwarded into the outbound MAIL FROM command so the
    recipient can see who the failed message was originally from.
    """
    failed_sender = request.form.get("failed_sender", "")
    notify_address = request.form.get("notify_to", "")

    smtp = smtplib.SMTP("relay.internal.example.com")
    smtp.docmd("EHLO", "bounce-notifier.example.com")

    # SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
    smtp.docmd("MAIL", "FROM:<" + failed_sender + ">")

    smtp.docmd("RCPT", "TO:<" + notify_address + ">")
    smtp.docmd("DATA", "")
    smtp.send(b"Subject: Delivery Failure Notice\r\n\r\n"
              b"Your message could not be delivered.\r\n.\r\n")
    smtp.quit()
    return "OK"
