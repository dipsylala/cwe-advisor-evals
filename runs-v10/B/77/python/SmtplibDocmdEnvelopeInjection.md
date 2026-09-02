## Verdict

Confirmed: CWE-77 (Command Injection via SMTP envelope). Untrusted form input reaches `smtplib.docmd()` without validation, allowing CRLF injection of additional SMTP commands.

## Source

Lines 12-13: Form input extracted directly
```python
failed_sender = request.form.get("failed_sender", "")
notify_address = request.form.get("notify_to", "")
```

Lines 19, 21: Input concatenated into SMTP commands
```python
smtp.docmd("MAIL", "FROM:<" + failed_sender + ">")
smtp.docmd("RCPT", "TO:<" + notify_address + ">")
```

An attacker can inject CRLF (`\r\n`) to inject additional SMTP commands. Example payload: `"attacker@evil.com\r\nRCPT TO:<attacker@evil.com>"`.

## Fix

Add email address validation using `re.fullmatch()` before constructing SMTP commands:

```python
"""Webhook handler for a delivery-failure bounce notice from the mail relay."""
import smtplib
import re


def handle_bounce_webhook(request):
    """Relay a delivery-failure notice using raw SMTP envelope commands.

    The upstream relay POSTs the original sender address of the bounced
    message; it is forwarded into the outbound MAIL FROM command so the
    recipient can see who the failed message was originally from.
    """
    failed_sender = request.form.get("failed_sender", "")
    notify_address = request.form.get("notify_to", "")

    # Validate email addresses against allowlist pattern to reject CRLF and malformed input
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    if not failed_sender or not re.fullmatch(email_pattern, failed_sender):
        raise ValueError("Invalid failed_sender email address")
    if not notify_address or not re.fullmatch(email_pattern, notify_address):
        raise ValueError("Invalid notify_to email address")

    smtp = smtplib.SMTP("relay.internal.example.com")
    smtp.docmd("EHLO", "bounce-notifier.example.com")

    # Safe: email addresses validated against allowlist; CRLF and command delimiters rejected
    smtp.docmd("MAIL", "FROM:<" + failed_sender + ">")

    smtp.docmd("RCPT", "TO:<" + notify_address + ">")
    smtp.docmd("DATA", "")
    smtp.send(b"Subject: Delivery Failure Notice\r\n\r\n"
              b"Your message could not be delivered.\r\n.\r\n")
    smtp.quit()
    return "OK"
```

## Explanation

The fix adds email address validation using `re.fullmatch()` before the values reach `docmd()`. The regex anchors to the whole string (fullmatch mode), rejecting any input containing CRLF, SMTP delimiters, or malformed email structure. This blocks envelope injection while preserving the existing `docmd()` API and error-handling contract. The validated values are used downstream, not the original tainted input. Defence-in-depth is applied: both sources are validated independently.

## Behaviour changes

- Invalid `failed_sender` or `notify_to` parameters now raise `ValueError` with a descriptive message instead of being forwarded to SMTP.
- SMTP commands containing embedded CRLF, spaces, command names, or any characters outside the email format are rejected.
- Legitimate email addresses (alphanumeric local-part with dots/underscores/hyphens/percent-signs, @ separator, domain with alphanumeric/dots/hyphens, and TLD of at least 2 letters) are accepted.
- Return values from `docmd()` remain unused (unchanged from original).
- Error path: `smtp.quit()` is not reached if validation fails; the caller must handle the `ValueError`.
