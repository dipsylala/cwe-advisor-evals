## Verdict
exploitable

## Source
`failed_sender = request.form.get("failed_sender", "")` (line 12) flows untrusted to the SMTP command sink.

An attacker can inject CRLF sequences into `failed_sender`. For example, posting `failed_sender=attacker@evil.com>\r\nRCPT TO:<admin@example.com` creates a malformed MAIL command that, when parsed by the relay, also injects a second RCPT TO recipient not intended by the application. The same technique works for other envelope-injection vectors: injecting CC/BCC headers, forwarding the message to alternate recipients, or manipulating the message body.

## Fix

**Vulnerable code (lines 15–25):**
```python
smtp = smtplib.SMTP("relay.internal.example.com")
smtp.docmd("EHLO", "bounce-notifier.example.com")

# SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
smtp.docmd("MAIL", "FROM:<" + failed_sender + ">")

smtp.docmd("RCPT", "TO:<" + notify_address + ">")
smtp.docmd("DATA", "")
smtp.send(b"Subject: Delivery Failure Notice\r\n\r\n"
          b"Your message could not be delivered.\r\n.\r\n")
smtp.quit()
```

**Fixed code:**
```python
smtp = smtplib.SMTP("relay.internal.example.com")

message = ("Subject: Delivery Failure Notice\r\n\r\n"
           "Your message could not be delivered.\r\n")
smtp.sendmail(failed_sender, [notify_address], message)
smtp.quit()
```

## Explanation
The fix replaces raw `smtp.docmd()` calls that concatenate untrusted input (`failed_sender` and `notify_address`) into SMTP command strings with `smtplib.SMTP.sendmail()`, which takes sender and recipient addresses as separate structured arguments. The `sendmail()` method internally constructs and sends EHLO, MAIL FROM, RCPT TO, and DATA commands using the proper SMTP protocol flow without string concatenation. Because `failed_sender` is no longer part of a concatenated command string, an attacker cannot inject CRLF sequences to split the MAIL command or inject additional recipients. The `sendmail()` method also validates the input and rejects embedded CR/LF characters in both sender and recipient addresses (on Python 3.6.15 and later), providing an additional defence layer.

## Behaviour changes
**Message body format**: The original code sent bytes to `.send()` including the SMTP DATA terminator (`.\r\n`); the fixed code passes the message body as a string to `sendmail()`, which adds the terminator automatically. Both transmit an identical message to the server; the change trades manual protocol handling for the library's built-in correct SMTP message framing.

**Automatic EHLO**: The original code explicitly issued a separate `smtp.docmd("EHLO", ...)` call; `sendmail()` sends EHLO automatically on first use if no prior greeting has been sent. Both approaches ensure the server receives EHLO before the message envelope.

**No explicit QUIT timing**: The original code issued `smtp.quit()` after `smtp.send()` returns. The fixed code calls `smtp.quit()` after `smtp.sendmail()` returns, which is the same sequence; both cleanly close the connection.

These behaviour changes preserve the application's intended logic: the message is routed to the same recipient, sent from the same sender address, and the connection is cleanly closed.
