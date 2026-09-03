## Verdict

**Confirmed.** Untrusted email address flows from HTTP request parameter through `TicketController` → `TicketNotificationService` → `SmtpRelayClient`, reaching the SMTP command string at line 28 without validation. An attacker can inject CRLF and additional SMTP commands (e.g., BCC, RCPT TO) to alter message routing.

## Source

- File: `SmtpRelayClient.java`, line 28
- Pattern: `out.write(("MAIL FROM:<" + envelope.getReplyTo() + ">\r\n")...)`
- Untrusted input: `envelope.getReplyTo()` originates from `request.getParameter("requesterEmail")` in `TicketController`

## Fix

Replace the hand-rolled SMTP client with Jakarta Mail's `Session`/`Transport`/`MimeMessage` API. Update `SmtpRelayClient.java`:

```java
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.util.Properties;

public class SmtpRelayClient {

    private final String relayHost;
    private final int relayPort;

    public SmtpRelayClient(String relayHost, int relayPort) {
        this.relayHost = relayHost;
        this.relayPort = relayPort;
    }

    public void sendAcknowledgement(MailEnvelope envelope) {
        try {
            Properties props = new Properties();
            props.put("mail.smtp.host", relayHost);
            props.put("mail.smtp.port", String.valueOf(relayPort));
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.starttls.required", "true");

            Session session = Session.getInstance(props);
            MimeMessage message = new MimeMessage(session);

            // Validate and set sender address with strict InternetAddress parsing
            try {
                message.setFrom(new InternetAddress(envelope.getReplyTo(), true));
            } catch (jakarta.mail.internet.AddressException e) {
                throw new IllegalArgumentException("Invalid sender address: " + e.getMessage());
            }

            // Validate and set recipient address
            try {
                message.setRecipients(Message.RecipientType.TO,
                    new InternetAddress[] { new InternetAddress(envelope.getRecipient(), true) });
            } catch (jakarta.mail.internet.AddressException e) {
                throw new IllegalArgumentException("Invalid recipient address: " + e.getMessage());
            }

            // Subject already contains concatenated text; strip any embedded CRLF
            String cleanSubject = envelope.getSubjectLine()
                .replaceAll("[\r\n]", " ");
            message.setSubject(cleanSubject);

            message.setText("Ticket received");

            // Send via SMTP transport
            Transport.send(message);

        } catch (MessagingException e) {
            throw new RuntimeException("Failed to relay ticket acknowledgement", e);
        }
    }
}
```

Add the Jakarta Mail dependency to your build file:

**Maven (pom.xml):**
```xml
<dependency>
    <groupId>com.sun.mail</groupId>
    <artifactId>jakarta.mail</artifactId>
    <version>2.0.2</version>
</dependency>
```

**Gradle (build.gradle):**
```gradle
implementation 'com.sun.mail:jakarta.mail:2.0.2'
```

Version floor: `com.sun.mail:jakarta.mail` **2.0.2** or `org.eclipse.angus:smtp` **2.0.4** or later. These versions include CVE-2025-7962 fix which scans outgoing SMTP commands for embedded CRLF. Below this floor, the `InternetAddress` constructor provides narrower protection (rejects unquoted local-part CRLF but allows quoted-string CRLF).

## Explanation

The original code built SMTP protocol commands by string concatenation, allowing untrusted email addresses to inject CRLF and secondary commands like `RCPT TO` or `BCC`. 

The fix:
1. **Replaces the socket-based approach** with Jakarta Mail's `Transport.send()`, which encapsulates all SMTP command building and removes the burden of manually constructing protocol syntax.
2. **Validates email addresses** using `new InternetAddress(address, true)` with strict parsing enabled. The `true` parameter enforces RFC 5321 address syntax validation. Malformed or CRLF-containing addresses throw `AddressException`, which is caught and rejected before reaching any command.
3. **Sanitizes message headers** by stripping embedded `\r\n` from the subject line, even though `Transport` is now handling the SMTP dialogue. This aligns with the Jakarta Mail best practice documented in `MimeMessage.setSubject()` javadoc.
4. **Enforces STARTTLS** with `mail.smtp.starttls.required=true`, which prevents downgrade attacks and plaintext fallback.
5. **Applies the version floor** (2.0.2+), which includes an outgoing-command scan for CRLF that hardens the library itself; this is defence-in-depth against any addresses that bypass parsing.

The fix changes none of the caller's contract - `sendAcknowledgement()` still accepts a `MailEnvelope` and sends a message. It preserves the IOException-to-RuntimeException mapping (now catches `MessagingException` instead, which is the broader superclass).

## Behaviour changes

- **Invalid email addresses now reject with `IllegalArgumentException`** instead of silently passing invalid syntax to SMTP. This is correct: malformed addresses indicate a bug in data entry or validation upstream, not a recoverable transient error.
- **Message subject is sanitized** to remove embedded line breaks. This is safe: the subject text reaches the recipient's mail client, and line breaks in subjects either render as spaces or cause header parsing issues in strict readers. Stripping them preserves readability.
- **STARTTLS is now required**. In the original code, `mail.smtp.starttls.enable=true` continues in plaintext if the server does not advertise STARTTLS. The fix enforces the upgrade or fails. This may break against legacy SMTP servers that do not support STARTTLS, but is the secure default for modern infrastructure.
- **Logging:** The original code logs to `java.util.logging`; Jakarta Mail does not. Remove or add explicit error logging around the `catch (MessagingException e)` block if detailed diagnostic logging is required.
