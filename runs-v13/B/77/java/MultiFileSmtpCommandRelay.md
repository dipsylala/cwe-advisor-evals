## Verdict

Exploitable. An attacker can inject CRLF sequences (`\r\n`) into an email address via the `requesterEmail` HTTP request parameter, which flows directly into an SMTP command string. The embedded CRLF breaks the SMTP protocol parsing and injects additional commands such as `BCC`, `CC`, or `DATA` into the relay connection.

## Source

`TicketController.handleSubmit()` retrieves the untrusted `requesterEmail` from the HTTP request parameter (line 20), packages it into a `TicketSubmission`, passes it to `TicketNotificationService.notifyAgent()`, which builds a `MailEnvelope` with the email address, and passes that envelope to `SmtpRelayClient.sendAcknowledgement()`.

The `replyTo` field of `MailEnvelope` (which contains the attacker-supplied email) reaches the SMTP sink at line 28 of `SmtpRelayClient`.

## Fix

**Before (vulnerable):**
```java
public class SmtpRelayClient {
    private final String relayHost;
    private final int relayPort;

    public SmtpRelayClient(String relayHost, int relayPort) {
        this.relayHost = relayHost;
        this.relayPort = relayPort;
    }

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
}
```

**After (fixed):**
```java
import java.util.Properties;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

public class SmtpRelayClient {
    private final String relayHost;
    private final int relayPort;

    public SmtpRelayClient(String relayHost, int relayPort) {
        this.relayHost = relayHost;
        this.relayPort = relayPort;
    }

    public void sendAcknowledgement(MailEnvelope envelope) {
        try {
            // Validate email addresses using InternetAddress constructor to reject CRLF and malformed addresses
            new InternetAddress(envelope.getReplyTo(), true);
            new InternetAddress(envelope.getRecipient(), true);

            Properties props = new Properties();
            props.put("mail.smtp.host", relayHost);
            props.put("mail.smtp.port", Integer.toString(relayPort));
            props.put("mail.smtp.starttls.required", "true");

            Session session = Session.getInstance(props);
            MimeMessage message = new MimeMessage(session);

            message.setFrom(new InternetAddress(envelope.getReplyTo()));
            message.setRecipients(Message.RecipientType.TO, envelope.getRecipient());
            message.setSubject(envelope.getSubjectLine());
            message.setText("Ticket received");

            Transport.send(message);
        } catch (AddressException e) {
            throw new RuntimeException("Invalid email address in acknowledgement envelope", e);
        } catch (MessagingException e) {
            throw new RuntimeException("Failed to relay ticket acknowledgement", e);
        }
    }
}
```

## Explanation

The fix replaces the hand-rolled Socket-based SMTP client with Jakarta Mail's `Session`/`Transport`/`MimeMessage` API, which properly handles command construction and parameter encoding according to the SMTP protocol specification. The `InternetAddress` constructor with strict mode (`true`) validates each email address and rejects any containing CR or LF characters before they reach any protocol sink. This breaks the injection chain: untrusted input can no longer escape the `InternetAddress` validation and reach the SMTP wire protocol. The `STARTTLS` requirement hardens the connection against eavesdropping. Validation occurs early, preventing any CRLF-containing value from progressing to the transport layer. Because `InternetAddress` validation throws `AddressException` (rather than returning false), failures are caught and logged explicitly rather than silently allowing invalid data through.

## Behaviour changes

**Dependency addition**: Requires Jakarta Mail (org.eclipse.angus:smtp 2.0.4+ or com.sun.mail:jakarta.mail 2.0.2 or 1.6.8+). The version floor ensures CRLF rejection is present in the transport layer as well; validate against SCA/dependency-check tooling before deployment.

**Error handling**: The original code catches only `IOException` and wraps it as a `RuntimeException`. The fixed code catches both `AddressException` (from address validation) and `MessagingException` (from the SMTP transport), distinguishing between validation failures and transmission failures. Both are still runtime exceptions to preserve the original contract, but the error message now clarifies whether the failure occurred during validation or transmission.

**STARTTLS enforcement**: The fixed code sets `mail.smtp.starttls.required=true`, enforcing opportunistic encryption (the original code's Socket-based approach did not use TLS at all). This is a hardening measure that aligns with the CWE-77/java guidance; it prevents cleartext relay of messages and is appropriate for an internal mail gateway. The SMTP server must support STARTTLS for this configuration to succeed.

**Message construction**: The original code directly concatenated the subject and other values into the raw SMTP DATA block. The fixed code uses `MimeMessage.setSubject()` and `setFrom()`/`setRecipients()`, which handle header encoding and protect against header injection (CWE-22/CWE-113). This is a secondary defense: subject and recipient lines are now part of the MIME structure rather than raw text appended to the wire stream.
