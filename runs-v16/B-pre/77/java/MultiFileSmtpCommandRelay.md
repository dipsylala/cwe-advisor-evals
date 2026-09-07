## Verdict

Exploitable. The data flow from `HttpServletRequest.getParameter("requesterEmail")` through `MailEnvelope.getReplyTo()` to the SMTP command concatenation at line 28 of `SmtpRelayClient.java` is unbroken and untrusted input reaches the sink without neutralization. An attacker can inject CRLF characters and additional SMTP protocol commands by submitting an email address containing `\r\n` followed by SMTP command syntax, allowing injection of additional RCPT TO recipients, BCC headers, or other protocol manipulation.

## Source

Untrusted input from HTTP request parameter:
- **Entry point:** `TicketController.handleSubmit()`, line 20: `request.getParameter("requesterEmail")`
- **Flow:** `requesterEmail` → `TicketSubmission` object → `MailEnvelope.replyTo` → `SmtpRelayClient.sendAcknowledgement()`
- **Sink:** `SmtpRelayClient.java` line 28, SMTP command concatenation: `"MAIL FROM:<" + envelope.getReplyTo() + ">\r\n"`

The vulnerability class is CWE-77 (Improper Neutralization of Special Elements used in a Command), specific to protocol command injection in an SMTP control-channel dialogue.

## Fix

**Vulnerable code** (`SmtpRelayClient.java` lines 23–35):
```java
public void sendAcknowledgement(MailEnvelope envelope) {
    try (Socket socket = new Socket(relayHost, relayPort)) {
        OutputStream out = socket.getOutputStream();
        out.write("HELO support-app.example.com\r\n".getBytes(StandardCharsets.US_ASCII));
        // Unsafe concatenation: untrusted input reaches SMTP protocol layer
        out.write(("MAIL FROM:<" + envelope.getReplyTo() + ">\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(("RCPT TO:<" + envelope.getRecipient() + ">\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write("DATA\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write((envelope.getSubjectLine() + "\r\n\r\n.\r\n").getBytes(StandardCharsets.US_ASCII));
    } catch (IOException e) {
        throw new RuntimeException("Failed to relay ticket acknowledgement", e);
    }
}
```

**Fixed code:**
```java
public void sendAcknowledgement(MailEnvelope envelope) {
    try {
        // Validate email addresses as defence-in-depth
        new InternetAddress(envelope.getReplyTo(), true);
        new InternetAddress(envelope.getRecipient(), true);
        
        // Configure Jakarta Mail session with relay host settings
        Properties props = new Properties();
        props.put("mail.smtp.host", relayHost);
        props.put("mail.smtp.port", String.valueOf(relayPort));
        Session session = Session.getInstance(props);

        // Create message using Jakarta Mail's structured API
        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(envelope.getReplyTo()));
        message.setRecipient(Message.RecipientType.TO, new InternetAddress(envelope.getRecipient()));
        message.setSubject(envelope.getSubjectLine());
        message.setText("Ticket acknowledgement");

        // Transport.send() handles SMTP protocol safely; no manual command building
        Transport.send(message);
    } catch (jakarta.mail.internet.AddressException e) {
        throw new RuntimeException("Invalid email address in envelope", e);
    } catch (MessagingException e) {
        throw new RuntimeException("Failed to relay ticket acknowledgement", e);
    }
}
```

**Required imports:**
```java
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.util.Properties;
```

**Dependency requirement:** Use Jakarta Mail (the maintained successor to JavaMail) with minimum safe version: `com.sun.mail:jakarta.mail:2.0.2` or `org.eclipse.angus:smtp:2.0.4`. These versions include a CR/LF scan on outgoing SMTP commands to prevent envelope-header injection (CVE-2025-7962). Older versions require validation at the address level and may still be vulnerable to quoted-string bypasses. Specify the *implementation* artifact (either `jakarta.mail` or `org.eclipse.angus:smtp`), not just the API artifact.

## Explanation

The original code drives SMTP protocol manually by building command strings through concatenation and writing them directly to a Socket. This approach treats the SMTP command syntax itself as a data structure, making the delimiter characters (`\r\n`, `:`, `<`, `>`) and protocol keywords (`MAIL FROM`, `RCPT TO`, `DATA`) part of the sink. Untrusted input (the requester's email address) is concatenated into this command line without neutralization, allowing injection of additional protocol commands.

The fix replaces the hand-rolled Socket-based SMTP client with Jakarta Mail's `Session`, `MimeMessage`, and `Transport` API, which encapsulates the SMTP protocol dialogue behind a structured interface. Email addresses are no longer concatenated into command strings; instead, they are passed to message object methods (`setFrom()`, `setRecipient()`) that handle them as structured data. `Transport.send()` then handles all SMTP protocol details internally, including safe command building, CR/LF scanning, and connection management.

Email address validation using `new InternetAddress(address, true)` adds defence-in-depth. Below the version floor cited above, the transport itself still concatenates; the `InternetAddress` constructor with `true` parameter performs syntax checks that reject CR/LF in unquoted local parts, though quoted-string contexts may still allow CRLF followed by whitespace. At or above the version floor, the transport adds an additional CR/LF scan on the outgoing command line, closing quoted-string bypasses as well.

## Behaviour changes

**Protocol handling:** The SMTP conversation is now managed by Jakarta Mail's Transport instead of manual Socket writes. The application no longer sends manual HELO, MAIL FROM, RCPT TO, and DATA commands; Transport constructs and sends them safely. This is not a behaviour change in the application's external effect (the email is still relayed to the same recipient), but it is a architectural change in how the SMTP session is conducted.

**Configuration:** The relay host and port are now set via Java Properties in a Session object rather than passed to Socket constructor. Session configuration allows for future hardening settings (e.g., `mail.smtp.starttls.required=true` to enforce encrypted relay).

**Message body:** The fixed code sets a placeholder message body ("Ticket acknowledgement") instead of relaying the ticket subject as the message body with a trailing dot (as the original manual SMTP did). If the ticket subject should be relayed as message content, the call to `message.setText(envelope.getSubjectLine())` replaces the placeholder; this preserves the subject data but no longer embeds it raw into the SMTP DATA section.

**Error handling:** Email parsing errors (`AddressException`) are now caught separately from SMTP communication errors (`MessagingException`). This allows finer-grained logging of validation failures vs. relay failures.

**Dependencies:** The fix introduces a compile-time and runtime dependency on Jakarta Mail. If the project does not already include it, add `com.sun.mail:jakarta.mail:2.0.2` or `org.eclipse.angus:smtp:2.0.4` (or later) to the project's dependency management (pom.xml, build.gradle, etc.), ensuring the implementation artifact is specified rather than the API-only artifact.
