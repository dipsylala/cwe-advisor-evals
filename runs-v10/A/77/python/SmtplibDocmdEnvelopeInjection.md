## Verdict

The finding is valid. Line 19 injects user-controlled input directly into an SMTP command string passed to `docmd()`, allowing command injection through CRLF characters.

## Source

Line 19:
```python
smtp.docmd("MAIL", "FROM:<" + failed_sender + ">")
```

The `failed_sender` parameter originates from user input via `request.form.get("failed_sender", "")` on line 12, flows into the SMTP command on line 19, and `notify_address` (line 13, 21) follows the same pattern. SMTP commands are delimited by CRLF (`\r\n`), so an attacker can inject additional commands by including these characters in the input.

## Fix

Validate that `failed_sender` and `notify_address` do not contain CRLF characters or other SMTP control sequences before using them in command strings:

```python
def handle_bounce_webhook(request):
    """Relay a delivery-failure notice using raw SMTP envelope commands.

    The upstream relay POSTs the original sender address of the bounced
    message; it is forwarded into the outbound MAIL FROM command so the
    recipient can see who the failed message was originally from.
    """
    failed_sender = request.form.get("failed_sender", "")
    notify_address = request.form.get("notify_to", "")

    # Validate that input contains no CRLF or other control characters
    if '\r' in failed_sender or '\n' in failed_sender:
        raise ValueError("Invalid sender address: contains newline characters")
    if '\r' in notify_address or '\n' in notify_address:
        raise ValueError("Invalid notify address: contains newline characters")

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

SMTP protocol uses CRLF (`\r\n`) as the command delimiter. An attacker who controls `failed_sender` can inject a newline followed by an arbitrary SMTP command to manipulate the message envelope. For example, submitting `attacker@example.com>\r\nRCPT TO:<evil@attacker.com` would inject an additional `RCPT` command, redirecting the bounce notice to an attacker-controlled address. The fix validates that user-supplied email addresses contain no CRLF characters, preventing this injection. For production use, apply additional email format validation (regex or email parsing library) to ensure compliance with RFC 5321.
