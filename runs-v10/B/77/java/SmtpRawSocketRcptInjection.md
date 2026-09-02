## Verdict

exploitable

## Source

Line 9: `String recipientAddress = request.getParameter("customerEmail");`

The recipient email address comes directly from untrusted user input via `HttpServletRequest.getParameter()`.

## Fix

**Vulnerable code (line 14–18):**
```java
out.write("MAIL FROM:<no-reply@example.com>\r\n".getBytes(StandardCharsets.US_ASCII));

// SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
out.write(("RCPT TO:<" + recipientAddress + ">\r\n").getBytes(StandardCharsets.US_ASCII));
```

**Fixed code:**
```java
import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import java.util.Properties;

public class SmtpRawSocketRcptInjection {

    public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
        String recipientAddress = request.getParameter("customerEmail");
        
        // Validate recipient address to reject CRLF injection and malformed addresses
        try {
            new InternetAddress(recipientAddress, true);
        } catch (AddressException e) {
            throw new IllegalArgumentException("Invalid recipient address: " + e.getMessage(), e);
        }

        Properties props = new Properties();
        props.put("mail.smtp.host", "mail.internal.example.com");
        props.put("mail.smtp.port", "25");
        props.put("mail.smtp.starttls.required", "true");

        Session session = Session.getInstance(props);

        try {
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress("no-reply@example.com"));
            message.setRecipients(Message.RecipientType.TO, recipientAddress);
            message.setSubject("Order confirmation");
            message.setText("Thanks for your order.");

            Transport.send(message);
        } catch (MessagingException e) {
            throw new Exception("Failed to send email: " + e.getMessage(), e);
        }
    }
}
```

## Explanation

The fix replaces raw socket-based SMTP command construction with Jakarta Mail's `Session`/`Transport`/`MimeMessage` API. Instead of manually building protocol strings by concatenation (which allows CRLF injection), the library's `Transport.send()` method encapsulates all SMTP command generation and includes built-in CR/LF filtering in the SMTP transport layer (Jakarta Mail ≥ 2.0.2 or 1.6.8; `org.eclipse.angus:smtp` ≥ 2.0.4). The recipient address is validated via `new InternetAddress(address, true)`, which parses the address syntax strictly and rejects malformed input, providing defence-in-depth before the address reaches the transport. The `mail.smtp.starttls.required=true` setting hardens the configuration by failing the connection if the server does not support TLS, preventing opportunistic (cleartext-fallback) vulnerabilities.

## Behaviour changes

- **Exception types:** Original socket code throws generic `Exception` and socket-level errors; fixed code throws `AddressException` (on invalid address) and `MessagingException` (on SMTP/transport errors). Callers must handle these distinct exception types appropriately.
- **Implicit dependency:** Code now requires Jakarta Mail library. Add dependency: `org.eclipse.angus:angus-mail:2.0.4` (or `com.sun.mail:jakarta.mail:2.0.2` or later) to Maven/Gradle.
- **Authentication/TLS:** Original code sends plaintext SMTP over the wire. Fixed code enforces TLS via `mail.smtp.starttls.required=true`, breaking the connection if STARTTLS is unavailable. Credentials should be added to the Properties and Session if the SMTP server requires authentication (original code did not authenticate; this is unrelated to the injection fix but represents a configuration improvement).
- **Message handling:** Fixed code uses Jakarta Mail's message object rather than raw socket writes. The entire SMTP dialogue (EHLO, MAIL FROM, RCPT TO, DATA, message body) is managed by the library; the original sequence of `out.write()` calls is encapsulated inside `Transport.send()`.
