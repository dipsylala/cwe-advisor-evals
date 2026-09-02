## Verdict

CWE-77 Command Injection confirmed. Unsanitized user-supplied email addresses are concatenated directly into SMTP protocol commands, allowing injection of arbitrary SMTP directives through control characters.

## Source

User-controlled `requesterEmail` parameter from `TicketController.handleSubmit()` flows through `TicketSubmission` → `TicketNotificationService.notifyAgent()` → `MailEnvelope` → `SmtpRelayClient.sendAcknowledgement()`.

The injection point occurs at line 28 of `SmtpRelayClient.java`:
```java
out.write(("MAIL FROM:<" + envelope.getReplyTo() + ">\r\n").getBytes(StandardCharsets.US_ASCII));
```

An attacker submitting `requesterEmail` containing `\r\n` sequences can inject additional SMTP commands into the protocol stream. Example payload: `attacker@example.com\r\nRSET\r\nMAIL FROM:<attacker2@example.com>` would inject a RSET and second MAIL FROM command.

Line 29 (`RCPT TO`) is similarly vulnerable, though the recipient is hardcoded. Line 31 (subject line) shares the same risk, as `subjectLine` is constructed from user input.

## Fix

Validate all email addresses and other SMTP command parameters before use. Reject any value containing CR (`\r`, U+000D) or LF (`\n`, U+000A) characters, and enforce a valid email address format:

```java
public void sendAcknowledgement(MailEnvelope envelope) {
    validateSmtpParameter(envelope.getReplyTo(), "replyTo");
    validateSmtpParameter(envelope.getRecipient(), "recipient");
    validateSmtpParameter(envelope.getSubjectLine(), "subjectLine");
    
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

private void validateSmtpParameter(String value, String paramName) {
    if (value == null || value.isEmpty()) {
        throw new IllegalArgumentException(paramName + " cannot be null or empty");
    }
    if (value.contains("\r") || value.contains("\n")) {
        throw new IllegalArgumentException(paramName + " contains invalid control characters");
    }
    // For email addresses, enforce basic format validation
    if (paramName.equals("replyTo") || paramName.equals("recipient")) {
        if (!value.matches("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {
            throw new IllegalArgumentException(paramName + " is not a valid email address");
        }
    }
}
```

## Explanation

SMTP is a line-oriented text protocol where commands are terminated by `\r\n` sequences. By including these characters in an email parameter, an attacker injects additional SMTP directives that the server will interpret as separate commands rather than data. This allows relaying mail from arbitrary addresses, resetting connections, or other SMTP protocol abuse.

The fix validates input at the point of use by rejecting any value containing carriage return or line feed characters. For email-specific fields, a regex enforces the standard email address format, preventing malformed addresses that could bypass SMTP parsing. Validation at the SMTP client layer ensures no attacker-controlled input reaches the protocol stream without verification.
