## Verdict

Exploitable.

## Source

`request.form.get("failed_sender", "")` — untrusted HTTP form input.

## Fix

**Vulnerable code (line 19):**
```python
smtp.docmd("MAIL", "FROM:<" + failed_sender + ">")
```

**Fixed code:**
```python
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

    message = (
        b"Subject: Delivery Failure Notice\r\n\r\n"
        b"Your message could not be delivered.\r\n"
    )
    smtp.sendmail(failed_sender, [notify_address], message)
    smtp.quit()
    return "OK"
```

## Explanation

The vulnerable code builds SMTP envelope commands by concatenating untrusted input into command strings. `smtplib.SMTP.docmd()` sends raw SMTP protocol commands without sanitizing embedded CRLF characters, which are SMTP's command delimiters; an attacker can inject `\r\n` sequences to append arbitrary SMTP commands (e.g., to set a different envelope recipient or inject message headers). The fix replaces manual `docmd()` calls with `smtplib.SMTP.sendmail()`, which takes envelope addresses as separate structured parameters and validates them to reject embedded CR/LF characters. This closes the command-injection vector while maintaining the same functional behaviour.

## Behaviour changes

The `sendmail()` method handles the MAIL FROM, RCPT TO, and DATA commands internally, eliminating the need for manual `docmd()` calls. The message is passed as a parameter rather than sent separately via `smtp.send()`, which simplifies the code and ensures the message is properly framed as part of the SMTP transaction. No functional change to the outcome—delivery failure notices are still sent to the notify address from the specified sender.
