## Verdict

Real vulnerability confirmed. The `recipientAddress` parameter from the HTTP request is concatenated directly into an SMTP `RCPT TO` command without validation, allowing injection of additional SMTP commands via embedded CRLF sequences.

## Source

Line 9: `String recipientAddress = request.getParameter("customerEmail");`

Untrusted HTTP input flows directly into the SMTP command at line 18.

## Fix

The vulnerable code uses raw socket I/O to build SMTP commands via string concatenation. The fix replaces this with Jakarta Mail's `Transport` API, which handles SMTP protocol details safely and validates addresses for CR/LF injection.

### File: SmtpRawSocketRcptInjection.java

```java
import java.util.Properties;
import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;

public class SmtpRawSocketRcptInjection {

    public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
        String recipientAddress = request.getParameter("customerEmail");

        // Validate the recipient address; InternetAddress constructor with strict=true
        // rejects any CR/LF characters and throws AddressException if present
        InternetAddress recipient;
        try {
            recipient = new InternetAddress(recipientAddress, true);
        } catch (jakarta.mail.internet.AddressException e) {
            throw new IllegalArgumentException("Invalid email address: " + e.getMessage(), e);
        }

        // Use Jakarta Mail's Transport API instead of raw socket I/O
        Properties props = new Properties();
        props.put("mail.smtp.host", "mail.internal.example.com");
        props.put("mail.smtp.port", "25");

        Session session = Session.getInstance(props);

        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress("no-reply@example.com", true));
        message.setRecipient(Message.RecipientType.TO, recipient);
        message.setSubject("Order confirmation");
        message.setText("Thanks for your order.");

        Transport.send(message);
    }
}
```

## Explanation

The fix eliminates the command injection by replacing raw socket-based SMTP protocol handling with Jakarta Mail's `Transport.send()` API. Instead of manually concatenating untrusted input into SMTP commands, the library handles all protocol details and command construction safely.

The address validation uses `new InternetAddress(recipientAddress, true)`, where the second parameter (`strict=true`) enables RFC 5322 strict parsing. This constructor rejects any CR or LF characters in the address, preventing CRLF injection attacks. If the address is invalid, it throws `AddressException`, which the code catches and converts to an `IllegalArgumentException`.

Key differences from the original:
1. **No raw socket I/O** — `Transport.send()` manages the connection and protocol dialogue, not user code
2. **Address validation** — `InternetAddress` constructor validates syntax and rejects CR/LF
3. **Message construction** — `MimeMessage` API ensures headers and body are properly encoded and cannot be confused with protocol commands
4. **Cleaner taint break** — only the validated `InternetAddress` object is used, never the raw string

This approach aligns with the CWE-77 remediation guidance: use the library's structured API instead of building command strings via concatenation.

## Behaviour changes

- **Protocol handling:** Connection management and SMTP dialogue are now handled by Jakarta Mail instead of manual socket I/O
- **Error handling:** Invalid email addresses now raise an exception at validation time rather than reaching the SMTP server
- **Configuration:** SMTP host and port are set via `Properties` instead of hardcoded in the socket creation
- **Message format:** The message is now a proper `MimeMessage` with MIME headers, rather than raw protocol text

These changes are beneficial: they move validation earlier, leverage a maintained library, and eliminate the injection point entirely.
