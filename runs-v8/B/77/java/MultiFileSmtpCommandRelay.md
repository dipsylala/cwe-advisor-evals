## Verdict

Exploitable. Untrusted user input (requesterEmail) flows from the HTTP request through TicketController → TicketNotificationService → MailEnvelope to SmtpRelayClient.sendAcknowledgement(), where it is concatenated into an SMTP MAIL FROM command without validation. An attacker can inject CRLF characters followed by additional SMTP commands.

## Source

`TicketController.handleSubmit()` line 20: `String requesterEmail = request.getParameter("requesterEmail");`

This untrusted value is passed to `TicketSubmission` (line 23), then to `TicketNotificationService.notifyAgent()` (line 24), which creates a `MailEnvelope` with it as the `replyTo` (line 24), and finally to `SmtpRelayClient.sendAcknowledgement()` where it reaches the sink.

## Fix

**Vulnerable code (SmtpRelayClient.java lines 23-35):**

```java
public void sendAcknowledgement(MailEnvelope envelope) {
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

**Fixed code (SmtpRelayClient.java):**

```java
package com.example.support;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * Uses Jakarta Mail to relay ticket acknowledgements through the internal
 * mail gateway, leveraging the library's protocol command serialization
 * to prevent SMTP command injection.
 */
public class SmtpRelayClient {

    private static final Logger LOG = Logger.getLogger(SmtpRelayClient.class.getName());
    private final String relayHost;
    private final int relayPort;

    public SmtpRelayClient(String relayHost, int relayPort) {
        this.relayHost = relayHost;
        this.relayPort = relayPort;
    }

    public void sendAcknowledgement(MailEnvelope envelope) {
        try {
            // Validate the reply-to address; AddressException is thrown if invalid.
            // The second parameter (true) enables strict RFC 5321 parsing to reject
            // addresses containing CR or LF characters.
            InternetAddress replyTo = new InternetAddress(envelope.getReplyTo(), true);
            InternetAddress recipient = new InternetAddress(envelope.getRecipient(), true);

            // Strip any line breaks from the subject to prevent header injection via
            // Message-ID or other header fields. This is a defence-in-depth measure
            // after address validation.
            String subjectLine = envelope.getSubjectLine().replaceAll("[\\r\\n]", "");

            Properties props = new Properties();
            props.put("mail.smtp.host", relayHost);
            props.put("mail.smtp.port", String.valueOf(relayPort));

            Session session = Session.getInstance(props);
            MimeMessage message = new MimeMessage(session);
            message.setFrom(replyTo);
            message.setRecipients(Message.RecipientType.TO, new InternetAddress[]{recipient});
            message.setSubject(subjectLine);
            message.setText("");

            Transport.send(message);
        } catch (AddressException e) {
            LOG.warning("Rejected malformed email address in envelope: " + e.getMessage());
            throw new RuntimeException("Invalid email address in envelope", e);
        } catch (MessagingException e) {
            throw new RuntimeException("Failed to relay ticket acknowledgement", e);
        }
    }
}
```

## Explanation

The vulnerability is SMTP command injection: the hand-rolled socket-based SMTP client concatenates untrusted email addresses directly into protocol commands (e.g., `MAIL FROM:<attacker@example.com\r\nRCPT TO:<victim@example.com>>`). An attacker can inject CRLF characters followed by additional SMTP commands, hijacking the message delivery.

The fix replaces the hand-rolled socket approach with Jakarta Mail's Session/Transport API, which properly serializes SMTP commands and prevents injection. The `InternetAddress` constructor with strict mode (`true`) validates that email addresses conform to RFC 5321 syntax and rejects any containing CR or LF characters before they reach the Transport layer. The subject line is also sanitized to remove any embedded line breaks, preventing header injection in the message envelope itself. This layered approach—structured API + strict address validation + header sanitization—eliminates the concatenation-based injection pattern entirely.

## Behaviour changes

1. **Dependency addition**: Requires `javax.mail:javax.mail-api` (or `jakarta.mail:jakarta.mail-api` for newer versions) and an implementation such as `com.sun.mail:javax.mail` or `com.sun.mail:jakarta.mail`. The caller must ensure the implementation version includes the CVE-2025-7962 fix (transport CR/LF scan): `com.sun.mail:jakarta.mail` **2.0.2** or **1.6.8**, or `org.eclipse.angus:smtp` **2.0.4** or later. Below these versions, the Transport will still forward CR/LF that address parsing omits, so validation via `InternetAddress` is a required defence-in-depth layer.

2. **Address validation becomes mandatory**: Malformed or untrusted addresses (those containing CR/LF) now throw `AddressException` at validation time rather than silently passing through to the SMTP server. Applications must handle this exception and reject invalid input rather than attempting to send.

3. **Logging added**: Rejected addresses are logged at WARNING level for monitoring purposes (without echoing the untrusted input verbatim, only the validation error).

4. **Subject sanitization**: Embedded line breaks in the subject are stripped, which may affect subjects intentionally containing `\r\n` (rare and security-inappropriate; stripping is the correct behaviour).

5. **Message format change**: The fixed code sends an empty message body instead of the original's raw text after the final dot. If the subject is meant to serve as the entire message body, the application logic must be adjusted to populate `message.setText(subjectLine)` or equivalent.

6. **SMTP server interaction**: The Transport API handles STARTTLS and authentication negotiation internally. Applications should configure `mail.smtp.starttls.required=true` to enforce encryption and `mail.smtp.auth=true` with credentials for authenticated relays; the original code had no such protection.
