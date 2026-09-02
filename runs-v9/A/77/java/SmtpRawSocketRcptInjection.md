## Verdict

Confirmed. `recipientAddress` comes from an HTTP request parameter and is concatenated directly into a raw SMTP `RCPT TO` command written to a socket, with no neutralization of CR/LF or other protocol-significant characters.

## Source

`request.getParameter("customerEmail")` in `sendOrderConfirmation(HttpServletRequest request)` (line 9) - attacker-controlled HTTP request parameter, used unvalidated at the sink on line 18.

## Fix

```java
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;

public class SmtpRawSocketRcptInjection {

    // Conservative allowlist for a single SMTP RCPT TO address: rejects CR/LF and any
    // other character that isn't valid in a simple, unquoted email address.
    private static final Pattern SAFE_EMAIL =
            Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
        String recipientAddress = request.getParameter("customerEmail");

        if (recipientAddress == null || !SAFE_EMAIL.matcher(recipientAddress).matches()) {
            throw new IllegalArgumentException("Invalid recipient email address");
        }

        Socket socket = new Socket("mail.internal.example.com", 25);
        try {
            OutputStream out = socket.getOutputStream();

            out.write("EHLO app.example.com\r\n".getBytes(StandardCharsets.US_ASCII));
            out.write("MAIL FROM:<no-reply@example.com>\r\n".getBytes(StandardCharsets.US_ASCII));

            out.write(("RCPT TO:<" + recipientAddress + ">\r\n").getBytes(StandardCharsets.US_ASCII));

            out.write("DATA\r\n".getBytes(StandardCharsets.US_ASCII));
            out.write(("Subject: Order confirmation\r\n\r\nThanks for your order.\r\n.\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            out.write("QUIT\r\n".getBytes(StandardCharsets.US_ASCII));
        } finally {
            socket.close();
        }
    }
}
```

## Explanation

The handler speaks raw SMTP over a socket it opens itself, so every line it writes is a live protocol command with no framework in between to escape or reject anything - the string concatenation on line 18 puts the user-supplied value directly into that command stream. Because SMTP is line-oriented and delimited by `\r\n`, any `\r` or `\n` the attacker includes in `customerEmail` terminates the `RCPT TO` command early and starts a new one that the server will execute as if the application sent it. For example, a value like `victim@example.com>\r\nRCPT TO:<attacker@evil.example>\r\nDATA\r\nSubject: pwned\r\n\r\nbody\r\n.\r\n` lets the attacker add extra recipients, rewrite the message body, or issue arbitrary SMTP commands (relay abuse, spoofed mail, header/body injection) all under the identity of the application's trusted mail relay.

The correct fix here is strict input validation before the value ever reaches the socket, not escaping or stripping: this is a single structured field (an email address) being written into a binary protocol, so there is no "safe" way to encode a CR or LF inside it that the SMTP server would treat as data rather than a command separator - the field simply must not contain one. Validating against a conservative allowlist pattern that only matches a well-formed, single-line email address rejects any input containing `\r`, `\n`, or other structurally unexpected characters, and rejects the request outright rather than attempting to sanitize and continue. This preserves the intended behavior (a valid, single recipient) while making command injection into the SMTP session structurally impossible, and it is a substantive change: the current code performs no format check at all, so any string - however malformed - reaches the sink unchanged. The `try/finally` for `socket.close()` is a minor robustness addition (the original code leaks the socket on any exception before the close call) and is not itself part of the CWE-77 fix.
