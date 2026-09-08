## Verdict

Exploitable. Untrusted HTTP form input (`failed_sender`) is concatenated directly into an SMTP command string passed to `smtp.docmd()`, enabling CRLF injection to split the command and inject arbitrary SMTP operations.

## Source

Line 12: `failed_sender = request.form.get("failed_sender", "")` - untrusted HTTP form input

## Fix

### File: SmtplibDocmdEnvelopeInjection.py

```python
"""Webhook handler for a delivery-failure bounce notice from the mail relay."""
import smtplib


def handle_bounce_webhook(request):
    """Relay a delivery-failure notice using the SMTP sendmail() API.

    The upstream relay POSTs the original sender address of the bounced
    message; it is forwarded as the MAIL FROM parameter to sendmail(),
    which properly frames it so embedded SMTP delimiters cannot split
    commands.
    """
    failed_sender = request.form.get("failed_sender", "")
    notify_address = request.form.get("notify_to", "")

    smtp = smtplib.SMTP("relay.internal.example.com")
    smtp.ehlo("bounce-notifier.example.com")
    
    message = ("Subject: Delivery Failure Notice\r\n"
               "\r\n"
               "Your message could not be delivered.\r\n")
    
    smtp.sendmail(failed_sender, [notify_address], message)
    smtp.quit()
    return "OK"
```

## Explanation

The vulnerability arises from using `smtp.docmd()` to manually construct SMTP commands via string concatenation. An attacker controlling `failed_sender` can inject CRLF sequences to split the MAIL command and inject arbitrary SMTP operations—for example, `attacker@evil.com\r\nRCPT TO:<attacker@evil.com>\r\n` would add an unintended recipient.

The fix replaces the manual `docmd()` calls with `smtp.sendmail()`, which is the parameterized SMTP API. The `sendmail()` method accepts sender address, recipient list, and message as separate arguments that are properly framed in the SMTP wire protocol, preventing any embedded delimiters from being interpreted as command boundaries. The sender and recipient addresses are no longer part of a concatenated command string, and embedded CRLF sequences are transmitted as literal data within the protocol's frame structure.

## Behaviour changes

1. **EHLO replaced with smtplib method**: Changed from `smtp.docmd("EHLO", "bounce-notifier.example.com")` to `smtp.ehlo("bounce-notifier.example.com")`. Reason: Use the library's typed method instead of raw command.

2. **MAIL/RCPT/DATA consolidated into sendmail()**: Replaced three separate `docmd()` calls with a single `sendmail(from_addr, to_addrs, message)` call. Reason: `sendmail()` handles MAIL FROM, RCPT TO, and DATA automatically while properly parameterizing each address.

3. **Address parameters separated**: `failed_sender` and `notify_address` are now passed as distinct parameters (`from_addr` and `to_addrs` list) instead of being concatenated into command strings. Reason: Parameterization prevents injection; the second parameter is now a list as required by `sendmail()`.

4. **Message formatting consolidated**: Combined the separate `smtp.send()` call with the message headers into a single string parameter to `sendmail()`. Reason: `sendmail()` handles the DATA command and message transmission; the low-level `send()` call is no longer needed.

5. **Return value of sendmail()**: The method returns a dictionary of refused recipients, which is now discarded (consistent with the original code's lack of error handling). Reason: This preserves the original behavior; if stricter error handling is desired, the caller can inspect this dictionary.

**Verification**: Python syntax check passed (python -m py_compile).

