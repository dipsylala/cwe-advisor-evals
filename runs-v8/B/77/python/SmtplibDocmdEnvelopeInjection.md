## Verdict

Confirmed. Untrusted HTTP form data (`failed_sender` and `notify_to`) flows directly into SMTP envelope commands via string concatenation without validation, enabling SMTP command injection.

## Source

```python
# Line 12-13: Untrusted form input
failed_sender = request.form.get("failed_sender", "")
notify_address = request.form.get("notify_to", "")
```

## Fix

```python
"""Webhook handler for a delivery-failure bounce notice from the mail relay."""
import re
import smtplib


def handle_bounce_webhook(request):
    """Relay a delivery-failure notice using raw SMTP envelope commands.

    The upstream relay POSTs the original sender address of the bounced
    message; it is forwarded into the outbound MAIL FROM command so the
    recipient can see who the failed message was originally from.
    """
    failed_sender = request.form.get("failed_sender", "")
    notify_address = request.form.get("notify_to", "")

    # Validate email addresses against a strict format to prevent SMTP injection
    email_pattern = r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    
    if not re.fullmatch(email_pattern, failed_sender):
        raise ValueError(f"Invalid sender address: {failed_sender}")
    if not re.fullmatch(email_pattern, notify_address):
        raise ValueError(f"Invalid recipient address: {notify_address}")

    smtp = smtplib.SMTP("relay.internal.example.com")
    smtp.docmd("EHLO", "bounce-notifier.example.com")

    # Safe: addresses validated against email format allowlist
    smtp.docmd("MAIL", "FROM:<" + failed_sender + ">")

    smtp.docmd("RCPT", "TO:<" + notify_address + ">")
    smtp.docmd("DATA", "")
    smtp.send(b"Subject: Delivery Failure Notice\r\n\r\n"
              b"Your message could not be delivered.\r\n.\r\n")
    smtp.quit()
    return "OK"
```

## Explanation

The code builds SMTP envelope commands by concatenating untrusted form input directly into command strings passed to `smtp.docmd()`. An attacker can inject CRLF sequences followed by arbitrary SMTP commands (e.g., `attacker@evil.com\r\nRCPT TO:<other@target.com>`) to expand the recipient list or modify message routing.

The fix adds defense-in-depth email address validation using `re.fullmatch()` with a strict RFC 5322-derived allowlist pattern. This ensures only valid email addresses reach the SMTP sink, rejecting any value containing CRLF, spaces, or other SMTP protocol delimiters. The pattern uses `fullmatch()` rather than `search()` to anchor validation to the entire string, preventing trailing injection (e.g. `valid@example.com\r\nFLUSHALL`).

## Behaviour changes

- **Input validation added:** HTTP request form fields are now validated as email addresses; requests with invalid addresses raise `ValueError` instead of proceeding.
- **Attack surface eliminated:** SMTP command injection via envelope address fields is no longer possible; CRLF and SMTP metacharacters are rejected before reaching the protocol sink.
- **Legitimate email addresses still accepted:** Standard email formats remain valid; the allowlist is permissive within RFC 5322 bounds.
