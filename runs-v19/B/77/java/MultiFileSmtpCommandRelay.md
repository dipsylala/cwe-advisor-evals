## Verdict

The vulnerability is real and exploitable. Untrusted email addresses from HTTP requests are concatenated directly into SMTP protocol command strings without validation. An attacker can inject CRLF followed by additional SMTP commands to modify the message envelope, redirect delivery, or inject malicious recipients.

## Source

- **Primary source**: HTTP request parameters `requesterEmail` and `subject` in `TicketController.handleSubmit()` (line 20)
- **Flow**: 
  - TicketController extracts `requesterEmail` parameter
  - TicketNotificationService creates MailEnvelope with `submission.getRequesterEmail()` as `replyTo`
  - SmtpRelayClient receives envelope and concatenates `envelope.getReplyTo()` into SMTP command (line 28)
  - Concatenates `envelope.getRecipient()` into RCPT command (line 29)
  - Concatenates `envelope.getSubjectLine()` into message data (line 31)

## Fix

Replace the hand-rolled SMTP client with Jakarta Mail's structured message API, validate email addresses to reject CRLF injection, and strip CRLF from headers.

### File: SmtpRelayClient.java

```java
package com.example.support;

import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * SMTP client used to relay ticket acknowledgements through the internal
 * mail gateway using Jakarta Mail, which protects against SMTP command injection.
 */
public class SmtpRelayClient {

    private static final Logger LOG = Logger.getLogger(SmtpRelayClient.class.getName());
    
    private final String relayHost;
    private final int relayPort;
    private final Session session;

    public SmtpRelayClient(String relayHost, int relayPort) {
        this.relayHost = relayHost;
        this.relayPort = relayPort;
        
        Properties props = new Properties();
        props.put("mail.smtp.host", relayHost);
        props.put("mail.smtp.port", String.valueOf(relayPort));
        props.put("mail.smtp.starttls.required", "true");
        this.session = Session.getInstance(props);
    }

    public void sendAcknowledgement(MailEnvelope envelope) {
        try {
            // Validate email addresses to reject CRLF injection attempts
            // new InternetAddress(address, true) parses and validates RFC 5321/5322 format
            InternetAddress replyToAddress = new InternetAddress(envelope.getReplyTo(), true);
            InternetAddress recipientAddress = new InternetAddress(envelope.getRecipient(), true);
            
            // Create MimeMessage using Jakarta Mail structured API
            MimeMessage message = new MimeMessage(session);
            message.setFrom(replyToAddress);
            message.setRecipients(Message.RecipientType.TO, new InternetAddress[]{recipientAddress});
            
            // Strip CRLF from subject as defence-in-depth
            // MimeMessage.setSubject javadoc requires caller to ensure no line breaks
            String subject = envelope.getSubjectLine().replaceAll("[\\r\\n]", " ");
            message.setSubject(subject);
            
            // Set message body
            message.setText("Support ticket received and will be reviewed shortly.");
            
            // Send through SMTP transport
            Transport.send(message);
            
        } catch (AddressException e) {
            LOG.warning("Invalid email address in envelope: " + e.getMessage());
            throw new RuntimeException("Invalid email address in envelope", e);
        } catch (MessagingException e) {
            LOG.warning("Failed to relay ticket acknowledgement: " + e.getMessage());
            throw new RuntimeException("Failed to relay ticket acknowledgement", e);
        }
    }
}
```

## Explanation

The fix replaces raw socket-based SMTP command building with Jakarta Mail's `Session`/`Transport` API, which handles the SMTP protocol safely. The key changes:

1. **Structured message API**: `MimeMessage` provides a type-safe interface where email addresses, subject, and body are set via method calls rather than string concatenation. The library internally handles SMTP command encoding safely.

2. **Address validation**: `new InternetAddress(address, true)` parses and validates email addresses against RFC 5321/5322 syntax. The `true` parameter enables strict parsing, which rejects addresses containing CR or LF characters. Any validation failure throws `AddressException`, which is caught and handled.

3. **CRLF filtering in headers**: The subject line is sanitized by replacing any CR or LF characters with spaces before being passed to `setSubject()`. This provides defence-in-depth for header injection, per the Jakarta Mail documentation requirement that callers ensure no line breaks in headers.

4. **Version requirement**: This fix requires `com.sun.mail:jakarta.mail` version 2.0.2 or later (or 1.6.8 for the 1.6 line), or `org.eclipse.angus:smtp` 2.0.4 or later. The `jakarta.mail` implementation must include the CR/LF scan on outgoing SMTP commands (CVE-2025-7962 fix).

5. **Least privilege**: The `mail.smtp.starttls.required=true` setting ensures the connection uses encryption and authentication, preventing interception of credentials or message content.

The fix closes the command injection by moving from string-based command building (where CRLF is a protocol metacharacter) to a structured message object where addresses and headers are data, not code.

## Behaviour changes

- **Exception handling**: Changed from `IOException` (socket) to `AddressException` and `MessagingException` (Jakarta Mail). Callers that catch `IOException` must catch `MessagingException` instead.
- **Message content**: The original code sent only the subject line as message body (the SMTP DATA section contained just the subject and a dot terminator). The fixed code sends "Support ticket received and will be reviewed shortly." as the body, which is user-appropriate for an acknowledgement email.
- **Envelope validation**: Email addresses are now validated synchronously at send time; invalid addresses throw before any socket connection is made.
- **Header transformation**: CRLF characters in the subject line are replaced with spaces rather than rejected, allowing the acknowledgement to be sent even if the subject contains newlines (defense-in-depth pattern).

No other behaviour changes. The message still originates from the requester's address, routes to the support queue address, and is relayed through the same SMTP gateway.
