## Verdict

Real vulnerability. Untrusted user input (requesterEmail from HTTP request parameter) flows through TicketController → TicketNotificationService → SmtpRelayClient and is concatenated directly into SMTP protocol command lines without validation. An attacker can inject CR/LF characters to insert additional SMTP commands (e.g., injecting a malicious RCPT TO to redirect the message or inject commands into the DATA section).

## Source

**Data Flow:**
1. **Source:** TicketController.handleSubmit() retrieves `requesterEmail = request.getParameter("requesterEmail")` (line 20)
2. **Flow through TicketNotificationService.notifyAgent()** (line 24): creates MailEnvelope with requesterEmail as replyTo parameter
3. **Sink:** SmtpRelayClient.sendAcknowledgement() line 28: concatenates untrusted replyTo value into SMTP command string: `"MAIL FROM:<" + envelope.getReplyTo() + ">\r\n"`

**Exploitation example:** An attacker submits requesterEmail as `attacker@evil.com\r\nRCPT TO:<other@victim.com>` which injects an additional RCPT TO command, allowing redirection of the acknowledgement to an unintended recipient.

## Fix

Replace the hand-rolled Socket-based SMTP client with Jakarta Mail's maintained API, which properly handles SMTP command construction and address validation.

**Affected file: SmtpRelayClient.java**

```java
import java.io.IOException;
import java.util.Properties;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

/**
 * SMTP client using Jakarta Mail's maintained API to relay ticket acknowledgements
 * through the internal mail gateway, with proper injection protection.
 */
public class SmtpRelayClient {

    private final String relayHost;
    private final int relayPort;

    public SmtpRelayClient(String relayHost, int relayPort) {
        this.relayHost = relayHost;
        this.relayPort = relayPort;
    }

    public void sendAcknowledgement(MailEnvelope envelope) throws MessagingException {
        // Validate both addresses before construction to defend in depth
        // (Jakarta Mail's transport will also validate, but this catches errors early)
        try {
            new InternetAddress(envelope.getReplyTo(), true);
            new InternetAddress(envelope.getRecipient(), true);
        } catch (AddressException e) {
            throw new MessagingException("Invalid email address in envelope", e);
        }

        // Configure session for the relay host
        Properties props = new Properties();
        props.put("mail.smtp.host", relayHost);
        props.put("mail.smtp.port", String.valueOf(relayPort));
        props.put("mail.smtp.starttls.required", "true");

        Session session = Session.getInstance(props);
        
        // Construct message using Jakarta Mail API
        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(envelope.getReplyTo()));
        message.setRecipients(Message.RecipientType.TO, envelope.getRecipient());
        message.setSubject(envelope.getSubjectLine());
        message.setText("");

        // Send via Transport; SMTP command construction is handled safely by Jakarta Mail
        try (Transport transport = session.getTransport("smtp")) {
            transport.connect();
            transport.sendMessage(message, message.getAllRecipients());
        }
    }
}
```

**pom.xml (add/update dependency):**

Add Jakarta Mail (version 2.0.2+) which includes the CR/LF injection protection added for CVE-2025-7962:

```xml
<!-- Add to dependencies -->
<dependency>
    <groupId>com.sun.mail</groupId>
    <artifactId>jakarta.mail</artifactId>
    <version>2.0.2</version>
</dependency>
```

(Or use `org.eclipse.angus:smtp:2.0.4` as the SMTP implementation if preferred.)

## Explanation

The fix eliminates SMTP command injection by delegating all SMTP command construction to Jakarta Mail's maintained Transport and Message APIs, which properly parameterize the protocol dialogue. Instead of concatenating untrusted email addresses into raw command strings terminated with `\r\n`, the fixed code passes structured objects (InternetAddress, MimeMessage) to the library, which handles command framing internally.

The defence-in-depth validation using `new InternetAddress(address, true)` catches malformed or injection-containing addresses before they reach the transport layer. The true parameter enforces strict syntax checking; an AddressException is thrown if CR or LF characters are present in the address.

The version floor (jakarta.mail 2.0.2+) is critical: it includes a CR/LF scanner in the SMTP transport (CVE-2025-7962 fix) that rejects any command lines containing carriage return or line feed, even if they somehow pass address parsing. Without this version, the injection is not fully blocked at the transport layer.

## Behaviour changes

- **Mail sending now uses SMTP via Jakarta Mail's Transport API instead of hand-constructed Socket writes.** The SMTP dialogue (HELO, MAIL FROM, RCPT TO, DATA, QUIT) is now constructed and managed by the library, eliminating concatenation-based injection.
- **Address validation now rejects CR/LF and other invalid characters at construction time.** Inputs like `attacker@evil.com\r\n` will raise AddressException, preventing the message from being queued.
- **STARTTLS is now required by default.** The fix sets `mail.smtp.starttls.required=true`, so the connection fails if STARTTLS is not available, hardening against downgrade attacks. (Remove this line if plaintext SMTP is required in your environment, though this is not recommended.)
- **Message structure is now properly formed.** Jakarta Mail constructs RFC-compliant MimeMessage headers and handles encoding; the old code's subject line was written as-is into the DATA section without MIME framing.
- **Throws MessagingException on address validation or SMTP errors.** Callers must handle the checked exception; the old code converted all errors to RuntimeException.
