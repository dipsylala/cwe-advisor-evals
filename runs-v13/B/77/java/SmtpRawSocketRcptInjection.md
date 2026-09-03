## Verdict

The finding is confirmed. The recipient address is read unsanitized from HTTP request and concatenated directly into an SMTP RCPT TO command sent over a raw socket. An attacker can inject CRLF characters to insert additional SMTP commands into the same connection.

## Source

Line 9: `String recipientAddress = request.getParameter("customerEmail");`

The parameter value reaches line 18 via direct string concatenation without validation or sanitization.

## Fix

**Dependency Version Floor**

Add or update Jakarta Mail implementation dependency:
- `org.eclipse.angus:angus-mail` >= 2.0.4, OR
- `com.sun.mail:jakarta.mail` >= 2.0.2 or 1.6.8

(These versions include the CR/LF scan that blocks CRLF injection in SMTP protocol commands; earlier versions remain vulnerable.)

**Fixed Code**

Replace the entire method with:

```java
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import java.util.Properties;

public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
    String recipientAddress = request.getParameter("customerEmail");
    
    // Validate address before using it - rejects CR/LF and other syntax errors
    InternetAddress validatedRecipient;
    try {
        validatedRecipient = new InternetAddress(recipientAddress, true);
    } catch (MessagingException e) {
        throw new IllegalArgumentException("Invalid email address", e);
    }
    
    // Use Jakarta Mail instead of raw socket
    Properties props = new Properties();
    props.put("mail.smtp.host", "mail.internal.example.com");
    props.put("mail.smtp.port", "25");
    // Require STARTTLS to harden against interception
    props.put("mail.smtp.starttls.required", "true");
    
    Session session = Session.getInstance(props);
    Message message = new MimeMessage(session);
    message.setFrom(new InternetAddress("no-reply@example.com"));
    // Use validated InternetAddress object, not raw string
    message.setRecipient(Message.RecipientType.TO, validatedRecipient);
    message.setSubject("Order confirmation");
    message.setText("Thanks for your order.");
    
    Transport.send(message);
}
```

## Explanation

The original code opened a raw socket to the SMTP server and built protocol commands via string concatenation. This exposes the sink to CRLF injection: an attacker supplying `victim@example.com\r\nRCPT TO:<attacker@example.com>` would insert an additional RCPT command and add themselves as a recipient, bypassing application-level authorization.

The fix replaces raw socket I/O with Jakarta Mail's `Session`/`MimeMessage`/`Transport` API. This library layer owns the SMTP dialogue and sanitizes command assembly. The recipe:

1. **Validate the address** with `new InternetAddress(address, true)` — this constructor runs syntax checks including CR/LF detection and throws `AddressException` on failure. Catch and reject with a generic error message (do not echo the raw input).
2. **Use the validated InternetAddress object** for the message, not the original request parameter. This ensures the library works with a known-safe value.
3. **Pin the implementation dependency version** to ensure the transport includes the CR/LF scan (CVE-2025-7962 fix). Earlier versions forward CR/LF that address parsing allowed through; the version floor closes that gap.
4. **Harden transport configuration** by setting `mail.smtp.starttls.required=true` to enforce encryption and prevent downgrade attacks.

The library now owns command escaping and protocol framing; no hand-rolled quoting or escaping is needed.

## Behaviour changes

**Functional changes:**
- Address validation now rejects malformed or dangerous input (e.g., addresses containing CRLF, missing @-sign, or invalid syntax). Previously malformed input would be sent to the SMTP server, which would reject it. Now the application rejects it earlier with a clearer error.
- STARTTLS is now mandatory (requires STARTTLS support on the server). Previously the connection was unencrypted.
- The message API is now used instead of raw protocol commands, so the message construction is more robust.

**Error handling:**
- `InternetAddress` construction throws `MessagingException` on invalid syntax; this is caught and converted to `IllegalArgumentException` for consistency. The application should handle this by returning a user-facing error.
- `Transport.send()` may throw `MessagingException` on SMTP server errors, SMTP protocol violations, or network issues. This propagates as-is; the calling code should wrap it if different error handling is needed.

**Security:**
- CRLF injection is blocked by validation + library sanitization.
- STARTTLS is required, protecting message contents in transit.
- The attacker no longer controls the SMTP command assembly; the library does.
