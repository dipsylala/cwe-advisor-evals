## Verdict

Real CWE-77 vulnerability. The untrusted `requesterEmail` from the HTTP request flows through `TicketController` → `TicketNotificationService` → `SmtpRelayClient.sendAcknowledgement()` at line 28, where it is directly interpolated into an SMTP MAIL FROM command without validation. An attacker can inject CRLF sequences to add unauthorized SMTP commands.

## Source

**Call chain:**
1. `TicketController.handleSubmit()` reads `requesterEmail` parameter from HTTP request (untrusted)
2. `TicketNotificationService.notifyAgent()` wraps it in a `MailEnvelope` as `replyTo`
3. `SmtpRelayClient.sendAcknowledgement()` concatenates `envelope.getReplyTo()` directly into the SMTP command at line 28

**Vulnerable line:**
```
out.write(("MAIL FROM:<" + envelope.getReplyTo() + ">\r\n").getBytes(StandardCharsets.US_ASCII));
```

An attacker could submit `requesterEmail` as `attacker@evil.com\r\nRCPT TO:<attacker@victim.com>` to inject additional SMTP commands and redirect the email.

## Fix

### File: SmtpRelayClient.java

```java
package com.example.support;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Minimal hand-rolled SMTP client used to relay ticket acknowledgements
 * through the internal mail gateway, without pulling in a full mail
 * client library.
 */
public class SmtpRelayClient {

    private final String relayHost;
    private final int relayPort;

    public SmtpRelayClient(String relayHost, int relayPort) {
        this.relayHost = relayHost;
        this.relayPort = relayPort;
    }

    public void sendAcknowledgement(MailEnvelope envelope) {
        try (Socket socket = new Socket(relayHost, relayPort)) {
            OutputStream out = socket.getOutputStream();
            out.write("HELO support-app.example.com\r\n".getBytes(StandardCharsets.US_ASCII));
            
            // Validate email addresses to prevent CRLF injection
            String replyTo = sanitizeSmtpParameter(envelope.getReplyTo());
            String recipient = sanitizeSmtpParameter(envelope.getRecipient());
            String subject = sanitizeSmtpParameter(envelope.getSubjectLine());
            
            out.write(("MAIL FROM:<" + replyTo + ">\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write(("RCPT TO:<" + recipient + ">\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write("DATA\r\n".getBytes(StandardCharsets.US_ASCII));
            out.write((subject + "\r\n\r\n.\r\n").getBytes(StandardCharsets.US_ASCII));
        } catch (IOException e) {
            throw new RuntimeException("Failed to relay ticket acknowledgement", e);
        }
    }

    /**
     * Validates and sanitizes parameters to prevent CRLF injection in SMTP commands.
     * Rejects any value containing carriage return or line feed characters.
     * 
     * @param parameter the SMTP parameter to validate
     * @return the validated parameter
     * @throws IllegalArgumentException if the parameter contains CRLF
     */
    private String sanitizeSmtpParameter(String parameter) {
        if (parameter == null) {
            throw new IllegalArgumentException("SMTP parameter cannot be null");
        }
        if (parameter.contains("\r") || parameter.contains("\n")) {
            throw new IllegalArgumentException("SMTP parameter contains invalid CRLF characters");
        }
        return parameter;
    }
}
```

## Explanation

The fix adds input validation at the SMTP client layer using a `sanitizeSmtpParameter()` method that rejects any value containing carriage return (`\r`) or line feed (`\n`) characters. These characters are the protocol delimiters in SMTP and allowing them in email addresses or subject lines enables command injection.

The validation is applied to:
- `envelope.getReplyTo()` → used in MAIL FROM command (line 28)
- `envelope.getRecipient()` → used in RCPT TO command (line 29)
- `envelope.getSubjectLine()` → used in email headers (line 32-33)

This defense-in-depth approach prevents an attacker from breaking out of the SMTP command syntax. The method throws `IllegalArgumentException` if injection is attempted, which propagates as a `RuntimeException` (consistent with the existing error handling pattern). A legitimate email address will never contain newlines, so this validation rejects only malicious input.
