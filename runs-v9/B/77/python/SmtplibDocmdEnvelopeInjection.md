## Verdict

Exploitable. CWE-77 (Improper Neutralization of Special Elements used in a Command). Confidence: high.

## Source

- **Source**: `request.form.get("failed_sender", "")` (line 12) - an HTTP form field taken from an unauthenticated webhook POST, forwarded verbatim.
- **Sink**: `smtp.docmd("MAIL", "FROM:<" + failed_sender + ">")` (line 19) - `failed_sender` is concatenated directly into the argument of a raw SMTP envelope command.
- **Flow**: `failed_sender` is read from the request body and reaches the sink with no validation, escaping, or length/charset restriction in between. `docmd()` is a low-level command sender: it frames whatever string it is given as the command's argument and writes it to the wire. `smtplib`'s own `putcmd()` rejects a `\r` or `\n` embedded in the command/args, but only on Python builds carrying the fix from 3.6.15/3.7.12/3.8.12/3.9.7/3.10 onward, and it blocks only CR/LF - it does not block other envelope-breaking characters such as `>`, `<`, or whitespace that can alter the `MAIL FROM` parameter list or truncate/extend the address unexpectedly. Relying on that interpreter-level guard alone is therefore not a complete defence; the call site has to constrain the value itself.
- **Sink contract** (Step 4): `docmd()` returns a `(code, response)` tuple that the current code discards entirely (no return-value use to preserve); it raises `smtplib.SMTPServerDisconnected` if the connection drops, which the current code does not catch (unchanged by the fix); it takes no implicit/defaulted arguments relevant to this weakness.

## Fix

Vulnerable code:

```python
failed_sender = request.form.get("failed_sender", "")
notify_address = request.form.get("notify_to", "")

smtp = smtplib.SMTP("relay.internal.example.com")
smtp.docmd("EHLO", "bounce-notifier.example.com")

# SAST FINDING: CWE-77 reported here. Sink is the next statement.
smtp.docmd("MAIL", "FROM:<" + failed_sender + ">")
```

Fixed code:

```python
import re
import smtplib

# Strict addr-spec allowlist: only characters that cannot alter or
# terminate the MAIL FROM envelope command are accepted. Anchored with
# fullmatch (not $-terminated re.match) so a trailing CR/LF cannot slip
# through.
_ADDR_SPEC_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def handle_bounce_webhook(request):
    """Relay a delivery-failure notice using raw SMTP envelope commands.

    The upstream relay POSTs the original sender address of the bounced
    message; it is forwarded into the outbound MAIL FROM command so the
    recipient can see who the failed message was originally from.
    """
    failed_sender = request.form.get("failed_sender", "")
    notify_address = request.form.get("notify_to", "")

    if not _ADDR_SPEC_RE.fullmatch(failed_sender):
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

## Explanation

`failed_sender` is validated against an anchored allowlist regex (`re.fullmatch`) before it is used to build the `MAIL FROM` command. The allowed character set (`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`) structurally excludes CR, LF, `<`, `>`, whitespace, and any other character that could inject a new SMTP command, alter the envelope's parameter list, or prematurely close the address, so the value can no longer break out of its position in the command string regardless of the Python version's `putcmd()` CRLF guard. Requests whose `failed_sender` does not match the expected address shape are rejected with a 400 before any SMTP connection is opened, closing the weakness at the point identified as the sink.

`notify_address` (line 21, `RCPT TO`) is built with the identical unvalidated-concatenation pattern from the same untrusted request and was not in scope of the reported finding, so it was left unchanged; it carries the same class of risk and should receive the same allowlist treatment.

## Behaviour changes

- A `failed_sender` that fails the addr-spec allowlist now short-circuits the request with `("Bad Request", 400)` before any SMTP connection is made, where previously any input - including one carrying CRLF or other injection payloads - was sent to the relay unconditionally. Legitimate addresses (the intended input shape) are unaffected and proceed exactly as before.
- No other return value, argument, or discarded output changed: `docmd()`'s return values are still unused, `smtp.send()`'s raw byte payload is untouched, and error/failure behaviour (`SMTPServerDisconnected` on disconnect) is unchanged.
- Assumption: `request` is a Flask-style request object (`request.form.get(...)` usage) and `("Bad Request", 400)` is a valid response tuple for the framework in use; the calling framework was not otherwise specified in the provided file.
