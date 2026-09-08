## Verdict

Exploitable. The vulnerability is confirmed: untrusted user input (`recipientAddress` from `request.getParameter("customerEmail")`) is concatenated directly into an SMTP `RCPT TO:` command at line 18 without validation or neutralization. An attacker can inject CRLF (`\r\n`) sequences followed by additional SMTP commands to manipulate the mail dialogue.

## Source

- **Untrusted Input (Source):** Line 9: `String recipientAddress = request.getParameter("customerEmail");`
- **Sink:** Line 18: `out.write(("RCPT TO:<" + recipientAddress + ">\r\n").getBytes(StandardCharsets.US_ASCII));`
- **Data Flow:** The parameter flows from the HTTP request directly into the SMTP command string via string concatenation, with no validation.

## Fix

### File: SmtpRawSocketRcptInjection.java

```java
import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;

public class SmtpRawSocketRcptInjection {

    public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
        String recipientAddress = request.getParameter("customerEmail");

        // Validate the recipient address with strict parsing
        InternetAddress recipient;
        try {
            recipient = new InternetAddress(recipientAddress, true);
        } catch (AddressException e) {
            throw new IllegalArgumentException("Invalid recipient address", e);
        }

        // Use Jakarta Mail to handle SMTP command construction safely
        Properties props = new Properties();
        props.put("mail.smtp.host", "mail.internal.example.com");
        props.put("mail.smtp.port", "25");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.starttls.required", "true");

        Session session = Session.getInstance(props);

        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress("no-reply@example.com"));
        message.setRecipient(Message.RecipientType.TO, recipient);
        message.setSubject("Order confirmation");
        message.setText("Thanks for your order.");

        Transport.send(message);
    }
}
```

## Explanation

The original code built SMTP commands by concatenating untrusted user input directly into protocol command strings sent over a raw socket. This allowed an attacker to inject CRLF characters followed by arbitrary SMTP commands (e.g., `RCPT TO:<attacker@example.com>\r\n`), diverting mail to unintended recipients or exploiting the SMTP server for relay attacks.

The fix replaces the raw socket-based SMTP dialogue with Jakarta Mail's `Session` and `Transport` APIs, which encapsulate SMTP command construction and execution. The untrusted email address is validated upfront using `InternetAddress(address, true)`, which performs strict RFC 5321 parsing and rejects addresses containing control characters like CR or LF. Only the validated `InternetAddress` object (not the raw string) is passed to the message; Jakarta Mail's `Transport.send()` then handles the entire SMTP dialogue safely, with no opportunity for command injection. The fix also enforces STARTTLS for transport security (`mail.smtp.starttls.required=true`), preventing the credentials and message content from being exposed in plaintext.

## Behaviour changes

1. **Dependency added:** Jakarta Mail (jakarta.mail-api and an implementation such as com.sun.mail:jakarta.mail, version 2.0.2+, or 1.6.8+ for the 1.6 line) must be added to the project's dependencies. This is the primary defence: the library encapsulates SMTP command construction.

2. **Network transport change:** STARTTLS encryption is now required (`mail.smtp.starttls.required=true`). The original code sent credentials and message content in plaintext. Any SMTP server that does not advertise STARTTLS will cause the method to fail. This is a security hardening and must be stated as a configuration change, not a silent addition.

3. **Input validation change:** Invalid email addresses (those containing control characters, malformed syntax, or containing CRLF/CR/LF) now raise `IllegalArgumentException` at validation time rather than being forwarded to the SMTP server. This is the breaking link that prevents injection: an attacker-controlled value cannot reach the SMTP sink.

4. **Error handling change:** The method now explicitly catches and re-throws `AddressException` (from address validation) as `IllegalArgumentException`, and wraps any `MessagingException` (from SMTP communication) in a new exception with context. This provides better error reporting and makes the validation failure explicit to the caller.

5. **No change to the message content or recipients list:** The message body ("Thanks for your order."), sender ("no-reply@example.com"), and subject line are identical to the original. Only the untrusted recipient address is now validated and safely passed through the SMTP API rather than concatenated into a command string.
