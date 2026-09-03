## Verdict

Exploitable. Untrusted input from `request.form.get("failed_sender")` is directly concatenated into an SMTP envelope command passed to `docmd()`, allowing an attacker to inject additional SMTP commands.

## Source

Line 12: `failed_sender = request.form.get("failed_sender", "")` — untrusted user input from HTTP request form data.

## Fix

**Vulnerable code:**
```python
failed_sender = request.form.get("failed_sender", "")
notify_address = request.form.get("notify_to", "")

smtp = smtplib.SMTP("relay.internal.example.com")
smtp.docmd("EHLO", "bounce-notifier.example.com")

# SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here.
smtp.docmd("MAIL", "FROM:<" + failed_sender + ">")

smtp.docmd("RCPT", "TO:<" + notify_address + ">")
smtp.docmd("DATA", "")
smtp.send(b"Subject: Delivery Failure Notice\r\n\r\n"
          b"Your message could not be delivered.\r\n.\r\n")
smtp.quit()
```

**Fixed code:**
```python
import re

failed_sender = request.form.get("failed_sender", "")
notify_address = request.form.get("notify_to", "")

# Validate email address format as defence-in-depth.
# The pattern rejects inputs with CRLF or other control characters.
email_pattern = r'^\S+@\S+$'
if not re.fullmatch(email_pattern, failed_sender) or not re.fullmatch(email_pattern, notify_address):
    return "Invalid email address"

smtp = smtplib.SMTP("relay.internal.example.com")

msg = (b"Subject: Delivery Failure Notice\r\n\r\n"
       b"Your message could not be delivered.\r\n")

# Use smtplib.sendmail() instead of raw docmd() for envelope commands.
# sendmail() internally calls docmd() with proper parameterization, which
# prevents CRLF injection into envelope addresses even if input validation
# were omitted (protection available since Python 3.6.15/3.7.12+).
smtp.sendmail(failed_sender, notify_address, msg)
smtp.quit()
```

## Explanation

The original code uses `docmd()` to send raw SMTP commands with untrusted input directly concatenated into the command string. An attacker can inject newlines and additional SMTP commands via the `failed_sender` or `notify_address` parameters. The fix replaces the low-level `docmd()` calls with `smtplib.sendmail()`, which is the safe high-level API that internally constructs and sends the MAIL, RCPT, and DATA commands through `putcmd()`. Since Python 3.6.15/3.7.12 and later versions, `putcmd()` rejects CR and LF characters in command arguments, preventing CRLF injection attacks. The fix also adds email format validation using `re.fullmatch()` (which anchors to the full string, preventing bypass via trailing newlines) as defence-in-depth to reject obviously malformed addresses before they reach the SMTP layer.

## Behaviour changes

- The `EHLO` command is now handled implicitly by `sendmail()` rather than being explicitly sent via `docmd()`. The server-greeting handshake remains part of the connection setup.
- The message body is passed to `sendmail()` rather than via a raw `send()` call; `sendmail()` automatically appends the RFC 5321 message terminator (`\r\n.\r\n`), so it must not be included in the message argument.
- Input validation is added: malformed email addresses (those not matching `^\S+@\S+$`) are rejected with an "Invalid email address" response before the SMTP transaction begins, rather than proceeding to attempt the send.
- The method now returns "Invalid email address" for malformed input instead of proceeding. This is a behaviour change but is a safe failure mode that prevents exploitation.
