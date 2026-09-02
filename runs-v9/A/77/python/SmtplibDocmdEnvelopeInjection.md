## Verdict

Confirmed. `failed_sender` (and `notify_address`) is attacker-controlled data from the inbound webhook POST body, and it is concatenated directly into a raw SMTP protocol line that is sent verbatim over the wire via `smtplib.SMTP.docmd()`. `docmd()` performs no CRLF stripping or command-boundary enforcement, so a value containing `\r\n` lets the attacker terminate the `MAIL FROM` command and inject additional SMTP commands (e.g. extra `RCPT TO` lines, a forged `DATA` block, or arbitrary EHLO/AUTH/relay commands) into the session with `relay.internal.example.com`. This is SMTP command/protocol injection, a form of CWE-77.

## Source

`request.form.get("failed_sender", "")` at line 12 (and `request.form.get("notify_to", "")` at line 13) — untrusted data from the "upstream relay" webhook POST, forwarded unvalidated into the outbound SMTP session.

## Fix

```python
"""Webhook handler for a delivery-failure bounce notice from the mail relay."""
import re
import smtplib

# Conservative RFC 5321-ish local-part/domain check; rejects CR, LF, and any
# character that has no business inside an envelope address.
_ADDR_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


def _validate_envelope_address(value, field_name):
    """Return value if it is a safe, single-line SMTP envelope address; else raise."""
    if "\r" in value or "\n" in value or "\x00" in value:
        raise ValueError(f"{field_name} contains illegal control characters")
    if not _ADDR_RE.match(value):
        raise ValueError(f"{field_name} is not a valid email address")
    return value


def handle_bounce_webhook(request):
    """Relay a delivery-failure notice using raw SMTP envelope commands.

    The upstream relay POSTs the original sender address of the bounced
    message; it is forwarded into the outbound MAIL FROM command so the
    recipient can see who the failed message was originally from.
    """
    failed_sender = request.form.get("failed_sender", "")
    notify_address = request.form.get("notify_to", "")

    try:
        failed_sender = _validate_envelope_address(failed_sender, "failed_sender")
        notify_address = _validate_envelope_address(notify_address, "notify_to")
    except ValueError:
        return "Bad Request", 400

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

The essential change is validating both `failed_sender` and `notify_address` before they reach `docmd()`: reject any value containing `\r`, `\n`, or NUL, and require the remainder to match a strict single-line email-address shape. This closes the injection at the point where untrusted data crosses into the SMTP protocol stream, rather than trying to sanitize after the fact.

## Explanation

`smtplib.SMTP.docmd(cmd, args)` builds the wire command as `f"{cmd} {args}\r\n"` and writes it straight to the socket — it does not know that `args` is supposed to be a single address and will not stop embedded `\r\n` sequences from starting new SMTP command lines. Because `failed_sender` flows unmodified from the webhook body into the `MAIL FROM:<...>` argument, an attacker who controls that POST field can supply something like:

```
attacker@evil.example>\r\nRCPT TO:<victim@internal.example>\r\nDATA\r\nSubject: fake\r\n\r\nmessage\r\n.\r\n
```

which the relay sees as a sequence of independent, attacker-authored SMTP commands rather than a single envelope address — enabling unauthorized recipients, forged message bodies, or abuse of whatever other commands the relay accepts in that session (this is the SMTP analogue of HTTP header/CRLF injection).

The fix enforces two properties on every value that reaches an envelope command: no control characters (`\r`, `\n`, NUL) can be present at all, and the value must match the shape of a legitimate email address end-to-end (anchored regex, not a substring search). A denylist that strips or escapes only `\r\n` is weaker, because it does not stop other malformed input from confusing the relay's line parser and does not confirm the field is actually an address; validating structurally with an anchored allowlist pattern and rejecting on failure — rather than silently stripping — ensures the caller finds out the input was invalid instead of having it silently rewritten into a different, unintended value. `notify_address` is validated the same way for the same reason: it is concatenated into `RCPT TO:<...>` with identical exposure.
