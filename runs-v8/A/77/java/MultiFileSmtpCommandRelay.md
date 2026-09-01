## Verdict

The finding is valid. Line 28 of `SmtpRelayClient.java` concatenates user-controlled email address data directly into an SMTP protocol command without validation, allowing SMTP command injection.

## Source

User input originates from the HTTP request parameter `requesterEmail` in `TicketController.handleSubmit()` (line 20). It flows through `TicketSubmission` to `MailEnvelope`, and reaches the sink as `envelope.getReplyTo()` in `SmtpRelayClient.sendAcknowledgement()`.

## Fix

Add input validation in `SmtpRelayClient.sendAcknowledgement()` to reject email addresses containing SMTP protocol control characters before concatenating them into commands:

```java
public void sendAcknowledgement(MailEnvelope envelope) {
    try (Socket socket = new Socket(relayHost, relayPort)) {
        OutputStream out = socket.getOutputStream();
        
        // Validate email addresses before using in SMTP commands
        validateSmtpAddress(envelope.getReplyTo());
        validateSmtpAddress(envelope.getRecipient());
        
        out.write("HELO support-app.example.com\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write(("MAIL FROM:<" + envelope.getReplyTo() + ">\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(("RCPT TO:<" + envelope.getRecipient() + ">\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write("DATA\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write((envelope.getSubjectLine() + "\r\n\r\n.\r\n").getBytes(StandardCharsets.US_ASCII));
    } catch (IOException e) {
        throw new RuntimeException("Failed to relay ticket acknowledgement", e);
    }
}

private void validateSmtpAddress(String address) {
    if (address == null || address.isEmpty()) {
        throw new IllegalArgumentException("Email address cannot be empty");
    }
    // Reject addresses containing SMTP protocol control characters
    if (address.contains("\r") || address.contains("\n") || 
        address.contains(">") || address.contains("<")) {
        throw new IllegalArgumentException("Invalid email address: contains SMTP control characters");
    }
    // Enforce basic email format: local-part@domain
    if (!address.matches("^[^@\\s]+@[^@\\s]+$")) {
        throw new IllegalArgumentException("Invalid email address format");
    }
}
```

## Explanation

SMTP command injection occurs when user-controlled data is directly concatenated into protocol commands. An attacker can inject `\r\n` sequences to terminate the current command and inject arbitrary SMTP directives. By validating that email addresses conform to a strict format (no whitespace, exactly one `@` separator) and explicitly rejecting strings containing SMTP control characters (`\r`, `\n`, `>`, `<`), the attacker cannot break out of the `MAIL FROM:` or `RCPT TO:` command syntax. The validation occurs at the sink where the data is used, ensuring all entry points are protected.
