## Verdict

CONFIRMED. The `envelope.getReplyTo()` and `envelope.getRecipient()` values—both derived from untrusted HTTP request parameters—are concatenated directly into SMTP protocol commands without validation. An attacker can inject CRLF characters followed by additional SMTP directives (e.g., `BCC`, `RCPT TO`) to alter message routing or add unintended recipients.

## Source

```java
public void sendAcknowledgement(MailEnvelope envelope) {
    try (Socket socket = new Socket(relayHost, relayPort)) {
        OutputStream out = socket.getOutputStream();
        out.write("HELO support-app.example.com\r\n".getBytes(StandardCharsets.US_ASCII));
        // VULNERABLE: User-controlled email address concatenated into SMTP command
        out.write(("MAIL FROM:<" + envelope.getReplyTo() + ">\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(("RCPT TO:<" + envelope.getRecipient() + ">\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write("DATA\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write((envelope.getSubjectLine() + "\r\n\r\n.\r\n").getBytes(StandardCharsets.US_ASCII));
    } catch (IOException e) {
        throw new RuntimeException("Failed to relay ticket acknowledgement", e);
    }
}
```

The call chain flows from `TicketController.handleSubmit()` (which reads `requesterEmail` from HTTP request parameters) → `TicketNotificationService.notifyAgent()` (which passes it as `replyTo` to `MailEnvelope`) → `SmtpRelayClient.sendAcknowledgement()` (which concatenates it unsanitized into the SMTP `MAIL FROM` command).

## Fix

Add a validation method to `SmtpRelayClient` that rejects email addresses containing SMTP-relevant special characters, and call it before writing commands:

```java
public class SmtpRelayClient {

    private final String relayHost;
    private final int relayPort;

    public SmtpRelayClient(String relayHost, int relayPort) {
        this.relayHost = relayHost;
        this.relayPort = relayPort;
    }

    /**
     * Validates an email address to prevent SMTP command injection.
     * Rejects addresses containing CRLF or other characters that could
     * terminate the current SMTP command and introduce a new one.
     */
    private void validateSmtpEmailAddress(String email) throws IllegalArgumentException {
        if (email == null || email.isEmpty()) {
            throw new IllegalArgumentException("Email address cannot be null or empty");
        }
        // Reject CRLF (line termination) which would allow command injection
        if (email.contains("\r") || email.contains("\n")) {
            throw new IllegalArgumentException("Email address contains invalid characters");
        }
        // Basic sanity check: email should have @ and not exceed reasonable length
        if (!email.contains("@") || email.length() > 254) {
            throw new IllegalArgumentException("Email address is malformed");
        }
    }

    public void sendAcknowledgement(MailEnvelope envelope) {
        // Validate email addresses before using them in SMTP commands
        validateSmtpEmailAddress(envelope.getReplyTo());
        validateSmtpEmailAddress(envelope.getRecipient());

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
}
```

## Explanation

SMTP is a text protocol where commands are delimited by CRLF (`\r\n`). When email addresses derived from user input are concatenated directly into SMTP commands without validation, an attacker can embed CRLF characters to terminate the current command and inject new SMTP directives.

**Attack example:** If `requesterEmail` is crafted as `attacker@evil.com>\r\nBCC:<victim@target.com`, the resulting SMTP stream becomes:
```
MAIL FROM:<attacker@evil.com>
BCC:<victim@target.com>
```

This injects an unauthorized recipient into the message.

**The fix:** The `validateSmtpEmailAddress()` method performs input validation before the email addresses are used in SMTP protocol commands. It checks for:
- CRLF characters (`\r` and `\n`) which would allow command termination and injection
- Presence of an `@` symbol (basic email format check)
- Reasonable length bounds (RFC 5321 specifies a 254-octet limit)

By validating at the entry point to the SMTP relay logic (in the `sendAcknowledgement()` method), we ensure that no untrusted data ever reaches the protocol layer.
