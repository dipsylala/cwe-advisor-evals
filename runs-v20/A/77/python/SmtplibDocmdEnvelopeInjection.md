## Verdict

Confirmed. `failed_sender` and `notify_address` come from the request body (`request.form.get(...)`) and are concatenated directly into raw SMTP protocol commands sent via `smtp.docmd()`. `docmd()` performs no CRLF filtering on the command it is given, so a value containing `\r\n` lets an attacker terminate the `MAIL FROM:<...>` (or `RCPT TO:<...>`) command early and inject arbitrary additional SMTP commands into the same session (e.g. extra `RCPT TO`, a forged `MAIL FROM` for a second message, or their own `DATA` block), turning the relay into an open mechanism for sending attacker-chosen mail. This is SMTP command injection into a protocol interpreter, CWE-77.

## Source

`request.form.get("failed_sender", "")` and `request.form.get("notify_to", "")` in `handle_bounce_webhook` (lines 12-13) — both attacker-controlled fields from the inbound webhook POST.

## Fix

### File: SmtplibDocmdEnvelopeInjection.py
```python
"""Webhook handler for a delivery-failure bounce notice from the mail relay."""
import re
import smtplib

# An SMTP envelope address must not contain CR, LF, or any other character
# that could terminate the MAIL/RCPT command early and let injected text be
# read as additional SMTP commands. Reject anything that isn't a plausible
# email address rather than trying to strip dangerous characters out.
_ADDR_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


def _is_safe_envelope_address(address):
    """Return True if address is safe to embed in a raw SMTP command."""
    return bool(_ADDR_RE.match(address))


def handle_bounce_webhook(request):
    """Relay a delivery-failure notice using raw SMTP envelope commands.

    The upstream relay POSTs the original sender address of the bounced
    message; it is forwarded into the outbound MAIL FROM command so the
    recipient can see who the failed message was originally from.
    """
    failed_sender = request.form.get("failed_sender", "")
    notify_address = request.form.get("notify_to", "")

    if not _is_safe_envelope_address(failed_sender):
        return "Bad Request: invalid failed_sender address", 400
    if not _is_safe_envelope_address(notify_address):
        return "Bad Request: invalid notify_to address", 400

    smtp = smtplib.SMTP("relay.internal.example.com")
    smtp.docmd("EHLO", "bounce-notifier.example.com")

    smtp.docmd("MAIL", "FROM:<" + failed_sender + ">")

    smtp.docmd("RCPT", "TO:<" + notify_address + ">")
    smtp.docmd("DATA", "")
    smtp.send(b"Subject: Delivery Failure Notice\r\n\r\n"
              b"Your message could not be delivered.\r\n.\r\n")
    smtp.quit()
    return "OK"
```

## Explanation

`smtplib.SMTP.docmd()` sends exactly the command string it is given, terminated with the connection's line ending — it does not know or care that the string was built from untrusted input, so any `\r\n` embedded in `failed_sender` or `notify_address` is interpreted by the relay as the end of that command and the start of a new one. Using `smtplib`'s higher-level `sendmail()` would not close this gap either: its internal `mail()`/`rcpt()` helpers wrap the address with `quoteaddr()`, which only adds angle brackets and does not strip or reject control characters, so the same injection would still reach the wire.

The fix validates both fields against a strict allowlist for what an email address can legitimately contain before they are ever placed into a command string, and rejects the request outright if either fails. This is not a generic security allowlist bolted onto an otherwise-unvalidated field — the application already defines the expected shape of these values (they are, by the handler's own contract, envelope addresses), so constraining them to that shape is not a behavior regression. Because CR and LF are outside the allowed character classes, an address carrying either can never reach `docmd()`, and rejecting the malformed value is preferred over trying to strip the dangerous characters, since stripping a control character can silently produce a different, still-plausible-looking address rather than surfacing the bad input.

To verify: send a `failed_sender` value containing a literal `\r\nRCPT TO:<attacker@evil.example>` — before the fix, the relay session would receive two SMTP commands from the single `docmd()` call; after the fix, `_is_safe_envelope_address()` rejects the value (the regex requires the entire string to match a `local@domain` shape with no whitespace or control characters) and the handler returns 400 before any SMTP command is issued. A legitimate address such as `bounces@example.com` continues to pass through unchanged.
