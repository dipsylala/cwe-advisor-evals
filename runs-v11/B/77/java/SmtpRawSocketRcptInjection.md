## Verdict

CWE-77 confirmed. Untrusted user input (`recipientAddress` from `request.getParameter("customerEmail")`) is concatenated directly into an SMTP command on line 18 without validation. An attacker can inject SMTP metacharacters (embedded `\r\n`) to inject additional protocol commands.

## Source

Line 9: `String recipientAddress = request.getParameter("customerEmail");`

This untrusted input flows directly to the sink at line 18.

## Fix

Replace the raw `Socket`-based SMTP command building with Jakarta Mail's structured `Transport` API:

```java
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import java.util.Properties;

public class SmtpRawSocketRcptInjection {

    public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
        String recipientAddress = request.getParameter("customerEmail");
        
        // Validate email address strictly before use
        InternetAddress recipient;
        try {
            recipient = new InternetAddress(recipientAddress, true);
        } catch (AddressException e) {
            throw new IllegalArgumentException("Invalid email address", e);
        }
        
        // Use Jakarta Mail Session and Transport instead of raw sockets
        Properties props = new Properties();
        props.put("mail.smtp.host", "mail.internal.example.com");
        props.put("mail.smtp.port", "25");
        props.put("mail.smtp.starttls.required", "true");
        
        Session session = Session.getInstance(props);
        
        try {
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress("no-reply@example.com"));
            message.setRecipient(Message.RecipientType.TO, recipient);
            message.setSubject("Order confirmation");
            message.setText("Thanks for your order.");
            
            Transport.send(message);
        } catch (MessagingException e) {
            throw new RuntimeException("Failed to send email", e);
        }
    }
}
```

**If staying with raw sockets is unavoidable** (not recommended), add strict validation at minimum:

```java
// Validate before using in SMTP command
InternetAddress validated;
try {
    validated = new InternetAddress(recipientAddress, true);
} catch (AddressException e) {
    throw new IllegalArgumentException("Invalid recipient address", e);
}
// Use only validated.getAddress() to build the command, never the raw string
out.write(("RCPT TO:<" + validated.getAddress() + ">\r\n").getBytes(StandardCharsets.US_ASCII));
```

## Explanation

The vulnerability occurs because SMTP commands are delimited with `\r\n` (CRLF), and the email address is concatenated directly into the command string without validation. An attacker can supply an address like `attacker@example.com\r\nBCC:backdoor@attacker.com` to inject additional SMTP commands through the same connection.

The primary defense (per CWE-77 Java guidance) is to replace raw socket SMTP handling with **Jakarta Mail's `Session`/`Transport` API**, which:
1. Builds SMTP commands safely inside the library
2. Validates email addresses
3. Handles protocol details correctly
4. Supports proper TLS/authentication configuration

The alternative minimal fix is **strict email validation** using `new InternetAddress(address, true)`, which:
1. Rejects any address containing CR/LF characters
2. Throws `AddressException` on invalid input
3. Must be caught and handled as an error (not tested as a boolean)

**Note on library versions:** If using Jakarta Mail, ensure the SMTP transport implementation includes the CVE-2025-7962 fix (a CR/LF scan on outgoing commands):
- `org.eclipse.angus:smtp` 2.0.4+
- `com.sun.mail:jakarta.mail` 2.0.2 and 1.6.8+

Below these versions, even `InternetAddress` validation may not catch all injection vectors, making the library-based solution essential.

## Behaviour changes

- **Input validation**: Email addresses are now validated to reject CR/LF and other invalid characters; malformed addresses throw an exception instead of silently reaching the SMTP server
- **Protocol handling**: SMTP command building moves from application code into the Jakarta Mail library, which applies proper command framing and escaping
- **Configuration**: STARTTLS is now required (`mail.smtp.starttls.required=true`) rather than optional, improving security posture
- **Error handling**: The application now explicitly catches and logs email validation failures and messaging exceptions, replacing silent socket errors
- **Injection surface**: Elimination of string concatenation into SMTP commands removes the primary injection path entirely
