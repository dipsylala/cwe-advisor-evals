## Verdict

The issue is real and exploitable. Untrusted input from HTTP request parameters flows directly into SMTP command construction via string concatenation without any neutralization of CRLF characters. An attacker can inject CRLF sequences followed by additional SMTP commands to modify the message routing or inject extra recipients.

## Source

- **Primary source:** `request.getParameter("requesterEmail")` in TicketController.handleSubmit() (line 19)
- **Secondary source:** `request.getParameter("subject")` in TicketController.handleSubmit() (line 19), concatenated into subject line at TicketNotificationService line 26
- **Data flow:** requesterEmail → TicketSubmission.requesterEmail → MailEnvelope.replyTo → SmtpRelayClient.sendAcknowledgement() concatenation at line 28; subject → MailEnvelope.subjectLine → line 31 concatenation
- **Sink:** SmtpRelayClient.java lines 28-31 where envelope fields are concatenated directly into SMTP protocol strings sent to Socket.getOutputStream()

## Fix

### File: SmtpRelayClient.java

```java
package com.example.support;

import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.util.Properties;

/**
 * Sends ticket acknowledgements through Jakarta Mail, which properly
 * neutralizes SMTP command injection through parameterized message APIs
 * instead of raw socket command building.
 */
public class SmtpRelayClient {

    private final String relayHost;
    private final int relayPort;

    public SmtpRelayClient(String relayHost, int relayPort) {
        this.relayHost = relayHost;
        this.relayPort = relayPort;
    }

    public void sendAcknowledgement(MailEnvelope envelope) {
        try {
            // Validate both email addresses with strict parsing to reject embedded CRLF.
            // InternetAddress(..., true) performs additional syntax checks and will throw
            // AddressException if CR or LF is present in the address.
            InternetAddress replyToAddress = new InternetAddress(envelope.getReplyTo(), true);
            InternetAddress recipientAddress = new InternetAddress(envelope.getRecipient(), true);
            
            // Strip CR/LF from subject line as defense-in-depth, even though
            // MimeMessage.setSubject should handle this safely.
            String subject = stripCRLF(envelope.getSubjectLine());
            
            // Configure SMTP session with secure defaults
            Properties props = new Properties();
            props.put("mail.smtp.host", relayHost);
            props.put("mail.smtp.port", String.valueOf(relayPort));
            // Require STARTTLS to fail rather than falling back to plaintext
            props.put("mail.smtp.starttls.required", "true");
            
            Session session = Session.getInstance(props);
            
            // Build message using Jakarta Mail's parameterized API,
            // which neutralizes SMTP command delimiters automatically
            MimeMessage message = new MimeMessage(session);
            message.setFrom(replyToAddress);
            message.setRecipient(Message.RecipientType.TO, recipientAddress);
            message.setSubject(subject);
            message.setText("Ticket acknowledgement");
            
            // Send through Transport API, which handles SMTP protocol safely
            Transport.send(message);
        } catch (AddressException e) {
            // Address validation failed; reject with no detail to prevent leaking structure
            throw new RuntimeException("Invalid email address in request", e);
        } catch (MessagingException e) {
            throw new RuntimeException("Failed to relay ticket acknowledgement", e);
        }
    }
    
    /**
     * Strip CR and LF characters from a string as defense-in-depth against
     * header injection. This is an extra safety layer; the Jakarta Mail library
     * should also reject these characters.
     */
    private String stripCRLF(String value) {
        if (value == null) {
            return "";
        }
        return value.replaceAll("[\r\n]", "");
    }
}
```

## Explanation

The original code built SMTP protocol commands by concatenating untrusted input directly into strings, then sending those strings over a socket. This allowed CRLF injection: an attacker's input like `attacker@evil.com\r\nRCPT TO:<attacker@example.com>` would split into multiple commands when written to the SMTP server.

The fix replaces raw socket-based SMTP command construction with Jakarta Mail's parameterized `MimeMessage` and `Transport.send()` APIs. These APIs treat email addresses, subjects, and bodies as data, not command syntax, automatically escaping or rejecting special characters. The key changes:

1. **Parameterized message construction:** `MimeMessage.setFrom()`, `setRecipient()`, and `setSubject()` take parsed objects or strings that are treated as data values, not command template syntax. The library encodes them safely when building the actual SMTP commands.

2. **Address validation:** `new InternetAddress(address, true)` performs strict parsing that rejects embedded CR, LF, or other RFC 5322 syntax violations, throwing `AddressException` if the address is invalid. This catches injection attempts before they reach the network.

3. **Header sanitization:** The `stripCRLF()` method removes CR and LF characters from the subject line as an additional defensive layer. While `MimeMessage.setSubject()` should handle this, the dual validation follows the principle of defense-in-depth.

4. **Secure SMTP configuration:** The `mail.smtp.starttls.required=true` setting ensures the connection fails rather than falling back to plaintext if STARTTLS is not available, preventing downgrade attacks.

The sink contract is preserved: the method still sends an email notification through the SMTP relay, but now through a safe, vetted library API instead of raw socket writes.

## Behaviour changes

- **Connection handling:** The application now uses Jakarta Mail's Session and Transport APIs instead of opening a raw Socket. This means network operations are managed by the library's connection pooling and error handling.
- **SMTP protocol handling:** The library automatically constructs SMTP commands, properly encoding email addresses and headers, rather than relying on string concatenation.
- **Transport security:** The connection now requires STARTTLS (`mail.smtp.starttls.required=true`), causing the send to fail if the server does not support encryption rather than falling back to plaintext.
- **Email address validation:** Both sender and recipient addresses are now validated with strict RFC 5322 parsing, which rejects addresses containing CR/LF or other syntax violations. Invalid addresses throw `AddressException` instead of being silently forwarded to the SMTP server.
- **Subject handling:** The subject line is now sanitized to remove CR/LF characters before being passed to the message API.
- **Error reporting:** The application now catches `AddressException` separately from general `MessagingException`, distinguishing invalid-input errors from transport failures.
