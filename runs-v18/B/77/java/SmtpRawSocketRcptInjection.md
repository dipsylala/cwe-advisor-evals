## Verdict

**CWE-77 confirmed**: Line 18 concatenates untrusted `recipientAddress` from user input directly into an SMTP `RCPT TO:` command string without validation. An attacker can inject `\r\n` characters followed by additional SMTP commands, allowing them to modify the recipient list or execute arbitrary SMTP commands on the internal mail server.

## Source

**Untrusted input**: `request.getParameter("customerEmail")` at line 9 receives unvalidated user input.

**Taint sink**: Line 18, `out.write(("RCPT TO:<" + recipientAddress + ">\r\n").getBytes(...))` - concatenates the untrusted value directly into an SMTP command sent over a raw socket.

**Vulnerability**: The SMTP protocol uses `\r\n` (CRLF) as command delimiters. An input like `test@example.com\r\nRCPT TO:<attacker@example.com>` splits into two separate commands, allowing command injection.

**Data flow**: User input (line 9) → concatenation into command string (line 18) → sent over socket (line 18) with no intermediary validation.

## Fix

### File: SmtpRawSocketRcptInjection.java

```java
import jakarta.mail.*;
import jakarta.mail.internet.*;
import javax.servlet.http.HttpServletRequest;
import java.util.Properties;

public class SmtpRawSocketRcptInjection {

    public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
        String recipientAddress = request.getParameter("customerEmail");

        // Validate the recipient address - rejects CRLF and other invalid characters
        InternetAddress recipient;
        try {
            recipient = new InternetAddress(recipientAddress, true);
        } catch (AddressException e) {
            throw new IllegalArgumentException("Invalid email address", e);
        }

        // Use Jakarta Mail's Session and Transport instead of raw socket
        Properties props = new Properties();
        props.put("mail.smtp.host", "mail.internal.example.com");
        props.put("mail.smtp.port", "25");
        props.put("mail.smtp.starttls.required", "true");

        Session session = Session.getInstance(props);

        // Create message using structured API
        MimeMessage message = new MimeMessage(session);
        message.setFrom("no-reply@example.com");
        message.setRecipient(Message.RecipientType.TO, recipient);
        message.setSubject("Order confirmation");
        message.setText("Thanks for your order.");

        // Send through Transport - CRLF validation is built-in (CVE-2025-7962 fix)
        Transport.send(message);
    }
}
```

## Explanation

The fix replaces raw socket-based SMTP command construction with Jakarta Mail's structured `Session`/`Transport`/`MimeMessage` API. This eliminates the vulnerability through two complementary mechanisms:

1. **Input validation**: `new InternetAddress(recipientAddress, true)` parses and validates the recipient address, rejecting any value containing CR/LF characters that could inject additional SMTP commands. The validated `InternetAddress` object is then used for all downstream operations, breaking the taint chain.

2. **Parameterized API**: Jakarta Mail's `Transport.send(message)` constructs SMTP commands internally using a parameterized API rather than string concatenation. As of the version floor (jakarta.mail 2.0.2, 1.6.8, or org.eclipse.angus:smtp 2.0.4), the transport itself includes a CR/LF scan (CVE-2025-7962 fix) to prevent any CRLF that escaped address parsing from reaching the socket. The structured API ensures that message fields (recipient, subject, body) are handled according to SMTP/MIME encoding rules, not raw command injection rules.

Additionally, `mail.smtp.starttls.required=true` ensures the connection is encrypted and authenticated, reducing the internal attack surface even if network access is compromised.

## Behaviour changes

- **Input validation is now stricter**: Addresses containing CR/LF characters, or other characters invalid in email address syntax, are rejected with an `IllegalArgumentException` instead of being passed through to the server (and potentially being accepted by a lenient server).

- **Encryption is enforced**: The SMTP connection now requires STARTTLS (`mail.smtp.starttls.required=true`), whereas the original code sent all commands in plaintext. If the mail server does not advertise STARTTLS, the connection fails instead of falling back to cleartext.

- **Message headers are handled safely**: Subject and body are now set through `setSubject()`/`setText()`, which properly encodes header values according to MIME standards. The original code included hardcoded headers in the DATA section; this is unchanged, but headers set programmatically are now protected against injection.

- **Exception handling**: Invalid addresses now raise `IllegalArgumentException` (wrapping `AddressException`), requiring the caller to handle validation errors explicitly. The original code would have sent invalid addresses to the server and relied on the server to reject them (if at all).

- **Dependency requirement**: The application now requires Jakarta Mail (or javax.mail for legacy codebases). Ensure the version is at or above the floor (jakarta.mail 2.0.2, 1.6.8, or org.eclipse.angus:smtp 2.0.4) to obtain the CVE-2025-7962 fix.
