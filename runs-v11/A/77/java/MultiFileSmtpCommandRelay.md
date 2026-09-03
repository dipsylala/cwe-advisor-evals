## Verdict
Confirmed. The vulnerability allows SMTP command injection through untrusted email addresses concatenated directly into SMTP protocol commands.

## Source
User input enters through `TicketController.handleSubmit()` as the `requesterEmail` parameter (line 20 of TicketController.java). This value flows unchanged through `TicketNotificationService.notifyAgent()` (line 24) and into `MailEnvelope` (line 23-26), then surfaces in `SmtpRelayClient.sendAcknowledgement()` where it is embedded unsafely into the SMTP MAIL FROM command at line 28.

## Fix
Add a private validation method to `SmtpRelayClient` and call it before constructing SMTP commands:

```java
private void validateEmailAddress(String email) {
    if (email == null || email.isEmpty()) {
        throw new IllegalArgumentException("Email address cannot be empty");
    }
    if (email.contains("\r") || email.contains("\n")) {
        throw new IllegalArgumentException("Email address contains invalid characters");
    }
    if (!email.matches("^[^@\\s]+@[^@\\s]+$")) {
        throw new IllegalArgumentException("Invalid email address format");
    }
}
```

Then modify `sendAcknowledgement()` to call this validation:

```java
public void sendAcknowledgement(MailEnvelope envelope) {
    validateEmailAddress(envelope.getReplyTo());
    validateEmailAddress(envelope.getRecipient());
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
```

## Explanation
The vulnerability arises because user-controlled email addresses are directly embedded into SMTP protocol commands without validation. An attacker could inject CRLF sequences (carriage return and line feed) to terminate the current SMTP command and inject new commands, for example: `attacker@evil.com>\r\nBCC:<victim@example.com` would inject a BCC field, allowing the attacker to add recipients to the email.

The fix validates email addresses before use by:
1. Rejecting null or empty values
2. Explicitly rejecting strings containing CRLF characters that would terminate the SMTP command
3. Applying a basic regex check to enforce email format (local-part@domain), preventing injection of special SMTP protocol characters

This prevents command injection while maintaining normal email functionality. The validation occurs at the point where the dangerous operation (SMTP command construction) happens, before the untrusted data is used.
