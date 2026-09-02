## Verdict

Real vulnerability. The `recipientAddress` parameter is read directly from untrusted user input via `request.getParameter()` and concatenated into an SMTP command string without validation. An attacker can inject additional SMTP commands by providing input containing CRLF sequences (e.g., `attacker@evil.com>\r\nRCPT TO:<victim@example.com>\r\n`), causing emails to be sent to unintended recipients.

## Source

Line 9: `String recipientAddress = request.getParameter("customerEmail");`

The parameter flows unsanitized into the SMTP command on line 18.

## Fix

```java
import java.util.regex.Pattern;

public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
    String recipientAddress = request.getParameter("customerEmail");
    
    // Validate email format and reject CRLF/special SMTP characters
    if (recipientAddress == null || !isValidEmail(recipientAddress)) {
        throw new IllegalArgumentException("Invalid email address");
    }

    Socket socket = new Socket("mail.internal.example.com", 25);
    OutputStream out = socket.getOutputStream();

    out.write("EHLO app.example.com\r\n".getBytes(StandardCharsets.US_ASCII));
    out.write("MAIL FROM:<no-reply@example.com>\r\n".getBytes(StandardCharsets.US_ASCII));

    out.write(("RCPT TO:<" + recipientAddress + ">\r\n").getBytes(StandardCharsets.US_ASCII));

    out.write("DATA\r\n".getBytes(StandardCharsets.US_ASCII));
    out.write(("Subject: Order confirmation\r\n\r\nThanks for your order.\r\n.\r\n")
            .getBytes(StandardCharsets.US_ASCII));
    out.write("QUIT\r\n".getBytes(StandardCharsets.US_ASCII));

    socket.close();
}

private static final Pattern EMAIL_PATTERN = 
    Pattern.compile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$");

private boolean isValidEmail(String email) {
    return email != null && 
           !email.contains("\r") && 
           !email.contains("\n") && 
           EMAIL_PATTERN.matcher(email).matches();
}
```

## Explanation

SMTP protocol uses CRLF (`\r\n`) as command delimiters. By injecting CRLF sequences into the email address, an attacker can break out of the current command and inject arbitrary SMTP commands (e.g., additional `RCPT TO` recipients, different subject, etc.). This is command injection at the SMTP protocol level, classified as CWE-77.

The fix validates that the email address:
1. Is non-null
2. Contains no carriage return (`\r`) or line feed (`\n`) characters
3. Matches a standard email format pattern (RFC 5322 simplified)

This prevents SMTP command injection by ensuring the input cannot break out of the `RCPT TO:<...>` command syntax. Only properly formatted email addresses without embedded CRLF or other metacharacters are accepted.

