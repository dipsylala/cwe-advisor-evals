## Verdict
Confirmed. The `recipientAddress` parameter is read directly from user input without validation and concatenated into an SMTP RCPT command, allowing injection of SMTP protocol elements (such as CRLF sequences) to execute additional commands.

## Source
Line 9: `String recipientAddress = request.getParameter("customerEmail");`
The parameter is obtained from user-controlled HTTP request input.

## Fix
### File: SmtpRawSocketRcptInjection.java

```java
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;

public class SmtpRawSocketRcptInjection {

    public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
        String recipientAddress = request.getParameter("customerEmail");
        
        // Validate email format before using in SMTP command
        if (!isValidEmail(recipientAddress)) {
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
    
    private static boolean isValidEmail(String email) {
        if (email == null || email.isEmpty()) {
            return false;
        }
        
        // Reject SMTP command injection characters
        if (email.contains("\r") || email.contains("\n") || email.contains(">")) {
            return false;
        }
        
        // Basic email validation: localpart@domain.tld
        String emailPattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
        return email.matches(emailPattern);
    }
}
```

## Explanation
The fix adds email validation before the user-supplied address is used in the SMTP command. The `isValidEmail()` method:

1. Rejects null or empty input
2. Explicitly rejects SMTP injection characters (`\r`, `\n`, `>`) that could break out of the RCPT command
3. Validates the email format against a pattern that permits standard email addresses while rejecting many invalid formats

By validating the input before constructing the SMTP command, an attacker cannot inject SMTP protocol commands through the email address parameter. For example, an input like `attacker@evil.com>\r\nRCPT TO:<victim@victim.com` is rejected because it contains both `>` and `\r`.
