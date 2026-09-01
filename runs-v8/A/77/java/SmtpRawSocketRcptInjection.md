## Verdict
Command injection in SMTP protocol via unvalidated email address.

## Source
Line 9: `String recipientAddress = request.getParameter("customerEmail");`

User-controlled input from HTTP request parameter is extracted without validation.

## Fix
```java
import java.util.regex.Pattern;

public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
    String recipientAddress = request.getParameter("customerEmail");
    
    // Validate email format and reject dangerous characters
    if (!isValidEmailAddress(recipientAddress)) {
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
    Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}$");

private boolean isValidEmailAddress(String email) {
    if (email == null || email.isEmpty()) {
        return false;
    }
    // Reject if contains SMTP control characters
    if (email.contains("\r") || email.contains("\n") || email.contains("\0")) {
        return false;
    }
    // Validate email format
    return EMAIL_PATTERN.matcher(email).matches();
}
```

## Explanation
The vulnerability exists because user-supplied email address is concatenated directly into an SMTP protocol command without validation. An attacker can inject SMTP commands by supplying an email containing CR (`\r`) or LF (`\n`) characters, which are SMTP command separators. For example, input like `attacker@evil.com>\r\nRCPT TO:<victim@example.com>` would cause the injected RCPT command to be processed.

The fix adds email validation before using the parameter. It:
1. Checks for null/empty input
2. Rejects any input containing SMTP control characters (`\r`, `\n`, `\0`)
3. Validates the email address against a standard email format pattern

This ensures only properly formatted email addresses are accepted and prevents SMTP command injection.
