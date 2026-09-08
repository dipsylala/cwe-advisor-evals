## Verdict
CONFIRMED - CWE-77 command injection via untrusted email addresses in SMTP command concatenation. Attacker-controlled email from HTTP request flows through `TicketController` → `TicketNotificationService` → `MailEnvelope` → `SmtpRelayClient.sendAcknowledgement()`, where it is concatenated directly into the SMTP command line sent over Socket without neutralization. CRLF injection allows redirection of mail and injection of additional SMTP commands.

## Source
`TicketController.handleSubmit()` line 20 reads untrusted `requesterEmail` parameter from HTTP request.

## Fix

The primary defence is to replace the hand-rolled Socket-based SMTP client with Jakarta Mail's `Session`/`Transport` API, which handles protocol framing safely and prevents command injection. Additionally, validate email addresses with `new InternetAddress(address, true)` as defence-in-depth.

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
 * SMTP client using Jakarta Mail for safe, structured protocol communication
 * instead of hand-rolled socket commands, preventing command injection.
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
            // Validate email addresses before use
            InternetAddress replyToAddress = new InternetAddress(envelope.getReplyTo(), true);
            InternetAddress recipientAddress = new InternetAddress(envelope.getRecipient(), true);

            Properties props = new Properties();
            props.put("mail.smtp.host", relayHost);
            props.put("mail.smtp.port", String.valueOf(relayPort));

            Session session = Session.getInstance(props);

            MimeMessage message = new MimeMessage(session);
            message.setFrom(replyToAddress);
            message.setRecipients(Message.RecipientType.TO, new InternetAddress[]{recipientAddress});
            message.setSubject(envelope.getSubjectLine());
            message.setText("");

            Transport.send(message);

        } catch (AddressException e) {
            LOG.warning("Invalid email address in envelope: " + e.getMessage());
            throw new RuntimeException("Failed to relay ticket acknowledgement: invalid address", e);
        } catch (MessagingException e) {
            throw new RuntimeException("Failed to relay ticket acknowledgement", e);
        }
    }
}
```

### File: TicketNotificationService.java

```java
package com.example.support;

import java.util.logging.Logger;

/**
 * Turns an incoming ticket submission into an outbound acknowledgement
 * envelope and hands it to the relay client. The requester's own address
 * is threaded through as the reply-to so agents can respond directly.
 */
public class TicketNotificationService {

    private static final Logger LOG = Logger.getLogger(TicketNotificationService.class.getName());

    private final SmtpRelayClient relayClient;

    public TicketNotificationService(SmtpRelayClient relayClient) {
        this.relayClient = relayClient;
    }

    public void notifyAgent(TicketSubmission submission) {
        LOG.info("New ticket received, subject length=" + submission.getSubject().length());

        MailEnvelope envelope = new MailEnvelope(
                submission.getRequesterEmail(),
                "support-queue@example.com",
                "Ticket received: " + submission.getSubject());

        relayClient.sendAcknowledgement(envelope);
    }
}

class MailEnvelope {
    private final String replyTo;
    private final String recipient;
    private final String subjectLine;

    MailEnvelope(String replyTo, String recipient, String subjectLine) {
        this.replyTo = replyTo;
        this.recipient = recipient;
        this.subjectLine = subjectLine;
    }

    String getReplyTo() {
        return replyTo;
    }

    String getRecipient() {
        return recipient;
    }

    String getSubjectLine() {
        return subjectLine;
    }
}
```

### File: TicketController.java

```java
package com.example.support;

import javax.servlet.http.HttpServletRequest;

/**
 * Entry point for the public "contact support" web form. Reads the
 * submitted fields and hands them off to the notification layer so an
 * acknowledgement can be relayed back to the requester.
 */
public class TicketController {

    private final TicketNotificationService notificationService;

    public TicketController(TicketNotificationService notificationService) {
        this.notificationService = notificationService;
    }

    public void handleSubmit(HttpServletRequest request) {
        String subject = request.getParameter("subject");
        String requesterEmail = request.getParameter("requesterEmail");
        String body = request.getParameter("body");

        TicketSubmission submission = new TicketSubmission(subject, requesterEmail, body);
        notificationService.notifyAgent(submission);
    }
}

class TicketSubmission {
    private final String subject;
    private final String requesterEmail;
    private final String body;

    TicketSubmission(String subject, String requesterEmail, String body) {
        this.subject = subject;
        this.requesterEmail = requesterEmail;
        this.body = body;
    }

    String getSubject() {
        return subject;
    }

    String getRequesterEmail() {
        return requesterEmail;
    }

    String getBody() {
        return body;
    }
}
```

## Explanation

The original code manually constructed SMTP protocol commands by concatenating untrusted email addresses and subject lines into strings, which are then sent over a Socket. This allows attackers to inject CRLF sequences to inject additional SMTP commands, redirecting mail or modifying message headers.

The fix replaces the hand-rolled Socket-based SMTP client with Jakarta Mail's structured API, which handles all protocol framing internally and prevents injection:

1. **Validation**: Email addresses are validated with `new InternetAddress(address, true)`, which performs RFC 5322 syntax checking and throws `AddressException` on invalid input (including embedded CRLF). This is defence-in-depth and will reject malformed or malicious addresses.

2. **Structured API**: Instead of building command strings via concatenation, the fix uses `Session`, `MimeMessage`, and `Transport.send()`. The library handles all SMTP protocol details, ensuring:
   - MAIL FROM, RCPT TO, and DATA commands are built safely without user input contamination
   - Message headers and body are properly encapsulated
   - CRLF characters in subject or other fields cannot escape their context to inject commands

3. **Minimal changes**: The fix touches only `SmtpRelayClient` (the sink). `TicketNotificationService` and `TicketController` are unchanged to preserve the existing call chain. The `MailEnvelope` class structure remains identical.

**Note on library version**: Jakarta Mail 2.0.2+ (`com.sun.mail:jakarta.mail`) or 1.6.8+ includes a CR/LF scan as an additional hardening measure. Ensure the dependency is pinned to these or newer versions in the project's build configuration (pom.xml or equivalent). The validation at the `InternetAddress` level provides the primary protection; the library version hardens the transport layer as defence-in-depth.

## Behaviour changes

The fix changes the wire protocol implementation from raw Socket commands to Jakarta Mail's SMTP protocol handling, but produces the same observable behaviour:

1. **Message delivery**: MIME messages are sent via SMTP to the relay host/port, reaching the same recipients.
2. **Error handling**: Invalid addresses now raise `AddressException` (caught and logged), which may change the application's error response. This is a security improvement: rejection of malformed input is correct behaviour.
3. **Properties-based SMTP configuration**: The fix uses `Session.getInstance(props)` instead of hardcoded Socket initialization. SMTP options like encryption, timeouts, or authentication can now be added via properties if needed in future.
4. **No external message body**: The original code did not include the ticket body in the message. The fix does not add it either, preserving original behaviour (the subject line is sent as-is in the SUBJECT header).

**Verification**: Test with email addresses containing CRLF sequences (e.g., `attacker@example.com\r\nRCPT TO:<hacker@evil.com>`) and confirm `AddressException` is thrown and logged, not forwarded to the SMTP server.
