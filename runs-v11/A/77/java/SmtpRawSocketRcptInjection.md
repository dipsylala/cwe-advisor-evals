## Verdict

Confirmed. The application accepts user-supplied email addresses from HTTP request parameters and directly concatenates them into SMTP protocol commands without validation, enabling SMTP command injection.

## Source

```java
String recipientAddress = request.getParameter("customerEmail");  // Line 9: untrusted input
// ...
out.write(("RCPT TO:<" + recipientAddress + ">\r\n").getBytes(StandardCharsets.US_ASCII));  // Line 18: sink
```

An attacker can supply an email parameter containing SMTP metacharacters (newlines, angle brackets, commands) to break out of the intended `RCPT TO` command and inject arbitrary SMTP commands. For example: `attacker@example.com>\r\nBCC:<attacker@evil.com` rewrites the recipient list.

## Fix

```java
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;

public class SmtpRawSocketRcptInjection {

    private static final Pattern VALID_EMAIL = Pattern.compile(
        "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    );

    public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
        String recipientAddress = request.getParameter("customerEmail");

        // Validate email format strictly
        if (recipientAddress == null || !VALID_EMAIL.matcher(recipientAddress).matches()) {
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
}
```

## Explanation

SMTP is a text-based protocol where commands are separated by `\r\n`. Concatenating an unsanitized email address directly into a command string allows an attacker to inject additional commands by including newlines and SMTP syntax. The fix adds validation before the sink: a strict regex pattern that permits only valid email characters (`[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]` before the `@` and alphanumerics with hyphens after) and rejects anything containing or structured to contain SMTP metacharacters. Any malformed input now throws an exception instead of reaching the protocol sink. This ensures only well-formed email addresses can reach the SMTP command, preventing command injection.

