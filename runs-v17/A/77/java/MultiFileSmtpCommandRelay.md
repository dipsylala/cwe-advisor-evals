## Verdict

CONFIRMED: CWE-77 command injection in SMTP protocol. Untrusted user input from `requesterEmail` parameter is concatenated directly into SMTP MAIL FROM command on line 28, allowing injection of arbitrary SMTP commands via CRLF sequences. The `subjectLine` on line 31 is similarly vulnerable to message body injection.

## Source

**TicketController.java (line 20)**: `requesterEmail` is read from untrusted HTTP request parameter via `request.getParameter("requesterEmail")`.

**Data flow**:
1. TicketController line 20: `String requesterEmail = request.getParameter("requesterEmail")`
2. TicketController line 23: Passed to `TicketSubmission` constructor
3. TicketNotificationService line 24: Passed to `MailEnvelope` constructor as `replyTo` parameter
4. SmtpRelayClient line 28: Concatenated into SMTP command: `"MAIL FROM:<" + envelope.getReplyTo() + ">"`

Similarly, `subject` parameter (line 19) flows to `subjectLine` (TicketNotificationService line 26) and is used unsanitized in SmtpRelayClient line 31.

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
        // Validate email addresses to prevent SMTP command injection
        validateEmailAddress(envelope.getReplyTo());
        validateEmailAddress(envelope.getRecipient());
        
        // Validate subject line to prevent message body injection
        validateMessageLine(envelope.getSubjectLine());
        
        try (Socket socket = new Socket(relayHost, relayPort)) {
            OutputStream out = socket.getOutputStream();
            out.write("HELO support-app.example.com\r\n".getBytes(StandardCharsets.US_ASCII));
            out.write(("MAIL FROM:<" + envelope.getReplyTo() + ">\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write(("RCPT TO:<" + envelope.getRecipient() + ">\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write("DATA\r\n".getBytes(StandardCharsets.US_ASCII));
            out.write((envelope.getSubjectLine() + "\r\n\r\n.\r\n").getBytes(StandardCharsets.US_ASCII));
        } catch (IOException e) {
            throw new RuntimeException("Failed to relay ticket acknowledgement", e);
        }
    }

    private static void validateEmailAddress(String email) {
        if (email == null || email.contains("\r") || email.contains("\n")) {
            throw new IllegalArgumentException("Invalid email address");
        }
    }

    private static void validateMessageLine(String line) {
        if (line != null && (line.contains("\r") || line.contains("\n"))) {
            throw new IllegalArgumentException("Invalid message content: contains line terminators");
        }
    }
}
```

## Explanation

The fix adds input validation at the SMTP sink (SmtpRelayClient.sendAcknowledgement) where the vulnerability manifests. Two validation methods enforce SMTP protocol constraints:

**validateEmailAddress()**: Rejects email addresses containing carriage return (`\r`) or line feed (`\n`) characters. These characters would terminate the current SMTP command prematively and allow injection of new commands. Null values are rejected as invalid.

**validateMessageLine()**: Rejects message content (subject line) containing `\r` or `\n`. In SMTP's DATA phase, these would break the message format or trigger premature termination via embedded `.\r\n` sequences.

Both validation methods throw `IllegalArgumentException` before any SMTP communication occurs, preventing the vulnerable protocol message from being sent. This approach:

- Blocks the attack at the point where danger manifests (the protocol sink)
- Fails fast and explicitly rather than silently corrupting the message
- Protects against injection in both SMTP command phase (lines 28–29) and message body phase (line 31)
- Requires no changes to data transformation layers (TicketController, TicketNotificationService)

The validation is permissive by design: it blocks only protocol-breaking characters, allowing legitimate email addresses and subject lines to pass through. An attacker cannot bypass validation by encoding the newlines or using alternative representations, since the Java string comparison is literal.
