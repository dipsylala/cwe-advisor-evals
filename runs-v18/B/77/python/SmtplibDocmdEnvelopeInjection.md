## Verdict

The CWE-77 command injection finding is confirmed and exploitable. The vulnerable code concatenates untrusted form input directly into SMTP command arguments without validation, allowing an attacker to inject CRLF sequences and additional SMTP commands.

## Source

**File:** SmtplibDocmdEnvelopeInjection.py  
**Line:** 19 (and 21)

Untrusted input originates from form parameters:
- Line 12: `failed_sender = request.form.get("failed_sender", "")`
- Line 13: `notify_address = request.form.get("notify_to", "")`

These values reach the SMTP sink via string concatenation:
- Line 19: `smtp.docmd("MAIL", "FROM:<" + failed_sender + ">")`
- Line 21: `smtp.docmd("RCPT", "TO:<" + notify_address + ">")`

## Fix

### File: SmtplibDocmdEnvelopeInjection.py

```python
"""Webhook handler for a delivery-failure bounce notice from the mail relay."""
import smtplib


def handle_bounce_webhook(request):
    """Relay a delivery-failure notice using SMTP's safe envelope API.

    The upstream relay POSTs the original sender address of the bounced
    message; it is forwarded to sendmail() so the recipient can see who the
    failed message was originally from.
    """
    failed_sender = request.form.get("failed_sender", "")
    notify_address = request.form.get("notify_to", "")

    smtp = smtplib.SMTP("relay.internal.example.com")
    
    # Use sendmail() instead of raw docmd() to avoid envelope injection.
    # sendmail() passes envelope addresses as separate arguments rather than
    # concatenating them into command strings, preventing SMTP command injection.
    msg = (b"Subject: Delivery Failure Notice\r\n"
           b"\r\n"
           b"Your message could not be delivered.")
    smtp.sendmail(failed_sender, [notify_address], msg)
    smtp.quit()
    return "OK"
```

## Explanation

The vulnerability exists because the original code uses `docmd()` to send raw SMTP commands with addresses built via string concatenation. An attacker can inject CRLF sequences in form fields to split commands—for example, setting `failed_sender` to `attacker@evil.com\r\nRCPT TO:<attacker@evil.com>` would inject an additional recipient.

The fix replaces the manual SMTP command construction with `smtplib.SMTP.sendmail()`, which is the safe, high-level API for envelope operations. The `sendmail()` method accepts sender and recipient addresses as separate parameters (`from_addr`, `to_addrs`) and message content as a single argument. It internally constructs the SMTP protocol commands correctly, passing each address as a separate value rather than embedding it in a concatenated command string. This prevents injection because untrusted input cannot split or extend the command structure when passed as discrete arguments.

The fix maintains functional equivalence: the message is still sent with the same headers and body. The `sendmail()` method handles EHLO, MAIL FROM, RCPT TO, DATA, and the end-of-message marker (`\r\n.\r\n`) automatically.

## Behaviour changes

- **Removed:** Manual `docmd()` calls for EHLO, MAIL, RCPT, and DATA; manual message framing with trailing `\r\n.\r\n`.
- **Added:** High-level `sendmail()` call that internally manages the full envelope and message exchange.
- **Preserved:** The message reaches the same recipient with the same sender address and subject line.
- **Safety improvement:** Envelope addresses are no longer concatenated into strings, eliminating the injection vector.
