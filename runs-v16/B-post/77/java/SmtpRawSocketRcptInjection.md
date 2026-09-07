## Verdict

exploitable

## Source

Line 9: `String recipientAddress = request.getParameter("customerEmail");` - untrusted user input from HTTP request parameter

## Fix

**Vulnerable code (line 18):**
```java
out.write(("RCPT TO:<" + recipientAddress + ">\r\n").getBytes(StandardCharsets.US_ASCII));
```

**Fixed code:**
```java
import java.util.Properties;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;

public class SmtpRawSocketRcptInjection {

    public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
        String recipientAddress = request.getParameter("customerEmail");
        
        // Validate recipient address - reject injection attempts
        try {
            new InternetAddress(recipientAddress, true);
        } catch (javax.mail.internet.AddressException e) {
            throw new IllegalArgumentException("Invalid email address", e);
        }
        
        // Use Jakarta Mail API instead of raw socket - eliminates command injection
        Properties props = new Properties();
        props.put("mail.smtp.host", "mail.internal.example.com");
        props.put("mail.smtp.port", "25");
        props.put("mail.smtp.starttls.required", "true");
        
        Session session = Session.getInstance(props);
        
        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress("no-reply@example.com"));
        message.setRecipients(Message.RecipientType.TO, recipientAddress);
        message.setSubject("Order confirmation");
        message.setText("Thanks for your order.");
        
        Transport.send(message);
    }
}
```

**Library recommendation:**
Use Jakarta Mail implementation with version floor:
- `org.eclipse.angus:smtp` ≥ 2.0.4, or
- `com.sun.mail:jakarta.mail` ≥ 2.0.2 or ≥ 1.6.8

These versions include a CR/LF scan in `SMTPTransport` that rejects injected protocol commands (CVE-2025-7962 fix). Upgrading only the API jar (`jakarta.mail:jakarta.mail-api`) is insufficient; the implementation artifact must be updated.

## Explanation

The original code builds an SMTP command by concatenating untrusted user input directly into a protocol string, then sends it over a raw socket. An attacker can inject embedded CRLF sequences (`\r\n`) to break out of the `RCPT TO:` command and inject additional SMTP commands (e.g., `user@example.com\r\nBCC:attacker@evil.com\r\n`). 

The fix eliminates the command-injection vector by replacing the raw socket and string concatenation with Jakarta Mail's `Session`/`Transport`/`MimeMessage` API, which handles all SMTP command construction internally and protects against delimiter injection. Additionally, the recipient address is validated using `new InternetAddress(address, true)` before being passed to the API, providing defence-in-depth: the validation catches malformed addresses with embedded line breaks before they reach the transport layer. The version floor ensures the transport implementation itself includes CR/LF scanning as a secondary control.

## Behaviour changes

- **Arguments supplied:** The fixed code constructs a `Properties` object with SMTP host, port, and TLS configuration rather than passing them directly to `Socket`. The default `Session.getInstance(props)` calls now specify required STARTTLS (`mail.smtp.starttls.required=true`), which is stricter than the original code's opportunistic TLS approach.
- **Return value:** The original code called `Socket.close()` at the end; the fixed code does not explicitly close the socket because `Transport.send()` manages the connection lifecycle internally. This is intentional and correct - the underlying SMTP connection is properly closed by the Jakarta Mail implementation.
- **Output discarded:** The original code wrote a multi-line SMTP dialogue (EHLO, MAIL FROM, RCPT TO, DATA, QUIT) by hand. The fixed code lets `Transport.send()` construct and manage the full SMTP sequence, which is more robust and includes additional protocol handling (envelope-from, message formatting, error recovery).
- **Exception handling:** The fixed code adds validation that throws `IllegalArgumentException` for malformed email addresses. This is a breaking change only for callers expecting to send invalid addresses, which is the desired security behaviour.
- **Message content:** The original code sends a multi-line message body with bare text; the fixed code uses `message.setText()` which wraps the body in proper MIME headers and encoding. The resulting message is better-formed for recipient mail servers.

All other aspects of the original contract (sending to the internal SMTP server, using the configured host, one recipient, basic message structure) are preserved.
