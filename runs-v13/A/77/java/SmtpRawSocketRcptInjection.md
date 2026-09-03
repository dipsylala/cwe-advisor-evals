## Verdict

Confirmed CWE-77 command injection vulnerability in SMTP protocol context.

## Source

Line 18: `out.write(("RCPT TO:<" + recipientAddress + ">\r\n").getBytes(StandardCharsets.US_ASCII));`

The `recipientAddress` parameter comes from untrusted user input via `request.getParameter("customerEmail")` at line 9. It is concatenated directly into an SMTP protocol command without any validation, allowing an attacker to inject additional SMTP commands by including protocol separators.

## Fix

Validate the recipient email address before use. Use a regex pattern that matches valid email format and explicitly rejects values containing SMTP protocol separators and control characters:

```java
public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
    String recipientAddress = request.getParameter("customerEmail");
    
    // Validate email format and reject SMTP injection attempts
    String emailPattern = "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$";
    if (recipientAddress == null || !recipientAddress.matches(emailPattern)) {
        throw new IllegalArgumentException("Invalid email address");
    }

    Socket socket = new Socket("mail.internal.example.com", 25);
    OutputStream out = socket.getOutputStream();

    out.write("EHLO app.example.com\r\n".getBytes(StandardCharsets.US_ASCII));
    out.write("MAIL FROM:<no-reply@example.com>\r\n".getBytes(StandardCharsets.US_ASCII));
    out.write(("RCPT TO:<" + recipientAddress + ">\r\n").getBytes(StandardCharsets.US_ASCII));
    // ... rest of method
}
```

## Explanation

The SMTP protocol uses `\r\n` as command delimiters. An attacker can exploit the lack of input validation to inject arbitrary SMTP commands. For example, input like `user@example.com\r\nBCC:<attacker@evil.com>` would cause the application to send the message to both the intended and the attacker's addresses.

The fix validates that the email address matches a standard email format (RFC 5322 simplified) which inherently rejects control characters, carriage returns, newlines, and other characters that would allow SMTP command injection. This prevents the injection of additional SMTP commands while still accepting legitimate email addresses.

The validation occurs before the email is used in the SMTP command, following the defense-in-depth principle of validating untrusted input as early as possible.
