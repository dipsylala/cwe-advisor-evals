## Verdict
CONFIRMED. The code concatenates untrusted request parameter `recipientAddress` directly into an SMTP protocol command without validation, allowing an attacker to inject SMTP directives via newline characters.

## Source
The vulnerability is introduced at line 9 where user input is read from the request parameter:
```java
String recipientAddress = request.getParameter("customerEmail");
```

The taint flows into the SMTP command at line 18:
```java
out.write(("RCPT TO:<" + recipientAddress + ">\r\n").getBytes(StandardCharsets.US_ASCII));
```

An attacker can supply input like `victim@evil.com\r\nBCC: attacker@steal.com\r\n` to inject unauthorized SMTP commands and alter the message delivery.

## Fix

### File: SmtpRawSocketRcptInjection.java

```java
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;

public class SmtpRawSocketRcptInjection {

    private static final Pattern VALID_EMAIL = Pattern.compile(
        "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    );

    public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
        String recipientAddress = request.getParameter("customerEmail");

        if (recipientAddress == null || recipientAddress.isEmpty()) {
            throw new IllegalArgumentException("Email address is required");
        }

        if (!isValidEmailAddress(recipientAddress)) {
            throw new IllegalArgumentException("Invalid email address format");
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

    private boolean isValidEmailAddress(String email) {
        if (email == null || email.length() > 254) {
            return false;
        }
        if (email.contains("\r") || email.contains("\n")) {
            return false;
        }
        return VALID_EMAIL.matcher(email).matches();
    }
}
```

## Explanation
The fix adds input validation before using `recipientAddress` in the SMTP command:

1. **Null and empty check**: Reject missing input.
2. **Newline rejection**: Explicitly reject strings containing `\r` or `\n`, which are the primary injection vector for SMTP command injection.
3. **Email format validation**: Use a regex pattern to validate that the input is a properly formatted email address, rejecting any unexpected characters or structures.
4. **Exception throwing**: Raise `IllegalArgumentException` for invalid input, which prevents the malicious command from being sent.

The validation is placed before socket creation, so invalid input is rejected before any network operation occurs. The email regex restricts input to valid email format, making it structurally impossible to inject SMTP command separators.
