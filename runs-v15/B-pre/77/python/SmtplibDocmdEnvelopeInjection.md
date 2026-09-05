## Verdict

**Fixed.** The vulnerability is real and exploitable.

## Source

Line 12: `failed_sender = request.form.get("failed_sender", "")` — untrusted input from HTTP form POST data, no validation or bounds checking.

## Fix

Replace the manual SMTP command construction with the standard `smtplib.SMTP.sendmail()` method, which handles envelope address framing safely:

```python
"""Webhook handler for a delivery-failure bounce notice from the mail relay."""
import smtplib


def handle_bounce_webhook(request):
    """Relay a delivery-failure notice using SMTP.

    The upstream relay POSTs the original sender address of the bounced
    message; it is forwarded into the outbound MAIL FROM so the
    recipient can see who the failed message was originally from.
    """
    failed_sender = request.form.get("failed_sender", "")
    notify_address = request.form.get("notify_to", "")

    smtp = smtplib.SMTP("relay.internal.example.com")
    
    msg = (b"Subject: Delivery Failure Notice\r\n\r\n"
           b"Your message could not be delivered.\r\n")
    
    smtp.sendmail(failed_sender, [notify_address], msg)
    smtp.quit()
    return "OK"
```

## Explanation

The vulnerability allows CRLF injection into the SMTP envelope. The original code constructs the MAIL command by concatenating untrusted input directly into the command argument: `"FROM:<" + failed_sender + ">"`. If `failed_sender` contains `\r\n`, it terminates the current command and injects additional SMTP commands. For example, a value like `user@example.com\r\nRSET` would inject a RESET command that cancels the mail transaction.

The guidance for CWE-77 in Python names `smtplib.SMTP.docmd()` as a taint sink when building SMTP commands by string concatenation. The safe pattern is to use the standard library's high-level SMTP methods: `sendmail()` internally constructs the MAIL FROM, RCPT TO, and DATA commands using the library's own framing logic, which does not allow untrusted input to split commands. The method passes envelope addresses as structured data rather than raw strings, preventing delimiter injection.

## Behaviour changes

- **Removed manual EHLO**: The `smtplib.SMTP` constructor already sends EHLO to the server on connection, so the explicit `docmd("EHLO", ...)` call is redundant and removed.
- **Replaced manual envelope construction**: The `sendmail()` method internally generates the MAIL FROM, RCPT TO, and DATA commands, eliminating the raw `docmd()` calls and the string-concatenation vulnerability.
- **Same functionality preserved**: The message body content is unchanged; the message still contains the subject and body text, and delivery occurs to the same recipients.
- **No additional validation required in this case**: `sendmail()` validates that addresses are well-formed email addresses and raises an exception if an address contains CR or LF characters, providing a second line of defense beyond the structural safety of parameterized commands.
