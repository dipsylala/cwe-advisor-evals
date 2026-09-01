## Verdict

Confirmed. The `recipientAddress` parameter from the HTTP request flows directly into the SMTP `RCPT TO:` command without validation. An attacker can inject CRLF characters to send arbitrary additional SMTP commands.

## Source

**Input source**: `request.getParameter("customerEmail")` at line 9.

**Data flow**: The untrusted `recipientAddress` is concatenated directly into the SMTP command string at line 18: `"RCPT TO:<" + recipientAddress + ">\r\n"`.

**Sink**: `out.write()` writing the constructed command to the SMTP socket at line 18.

**Exploitation scenario**: A malicious `customerEmail` parameter such as `attacker@example.com\r\nRCPT TO:<victim@example.com>\r\n` would inject an additional SMTP command, allowing the attacker to add arbitrary recipients to the email.

## Fix

Replace the raw Socket-based SMTP communication with Jakarta Mail's `Session` and `Transport` API. This delegates the SMTP protocol handling to a maintained library that properly constructs and validates SMTP commands.

```java
import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;

public class SmtpRawSocketRcptInjection {

    public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
        String recipientAddress = request.getParameter("customerEmail");
        
        // Validate the recipient address before using it
        try {
            new InternetAddress(recipientAddress, true);
        } catch (AddressException e) {
            throw new IllegalArgumentException("Invalid email address provided", e);
        }

        // Set up Jakarta Mail session properties
        Properties props = new Properties();
        props.put("mail.smtp.host", "mail.internal.example.com");
        props.put("mail.smtp.port", "25");
        props.put("mail.smtp.starttls.required", "true");
        props.put("mail.smtp.auth", "false");

        Session session = Session.getInstance(props);

        // Create and send the message using the safe API
        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress("no-reply@example.com"));
        message.setRecipients(Message.RecipientType.TO, recipientAddress);
        message.setSubject("Order confirmation");
        message.setText("Thanks for your order.");

        Transport.send(message);
    }
}
```

## Explanation

The fixed code replaces raw socket manipulation with Jakarta Mail's structured API, which internally handles SMTP protocol construction safely. Instead of concatenating user input into command strings, the code:

1. **Validates the email address** using `new InternetAddress(recipientAddress, true)` with strict parsing enabled (`true` parameter), which throws `AddressException` if the address contains CRLF or other invalid characters. Below version 2.0.2/1.6.8 of the implementation (org.eclipse.angus:smtp or com.sun.mail:jakarta.mail), address validation alone is not sufficient due to allowances for CR/LF in quoted strings, so the SMTP transport itself must include CRLF scanning (added in the versions listed).

2. **Uses the parameterized API** - `setRecipients()` accepts a validated `InternetAddress` and ensures it cannot be misinterpreted as part of the SMTP protocol syntax.

3. **Delegates protocol construction** to Jakarta Mail's `Transport.send()`, which constructs SMTP commands safely without string concatenation.

4. **Hardens the session configuration** with `mail.smtp.starttls.required=true` to enforce encryption rather than opportunistically attempting it.

The dependency requirement is `com.sun.mail:jakarta.mail` version 2.0.2 or later (1.6.8 for the 1.x line) or `org.eclipse.angus:smtp` 2.0.4 or later for the CRLF scan in the transport itself.

## Behaviour changes

- **Changed**: SMTP communication now uses Jakarta Mail's maintained library instead of raw socket writes.
- **Changed**: Email construction uses the `MimeMessage` API instead of manual command-line assembly.
- **Changed**: STARTTLS is now required (`mail.smtp.starttls.required=true`) instead of optional, enforcing transport encryption.
- **Added**: Address validation with `new InternetAddress(address, true)` before use, rejecting malformed or CRLF-bearing input with `AddressException`.
- **Removed**: Manual `EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`, and `QUIT` command assembly.
- **Preserved**: Message metadata (sender, recipient, subject, body) and SMTP server target remain unchanged.
- **Preserved**: Error handling via exceptions from Jakarta Mail's APIs (e.g., `MessagingException`, `AddressException`).
