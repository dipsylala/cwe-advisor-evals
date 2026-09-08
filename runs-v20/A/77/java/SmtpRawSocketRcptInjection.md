## Verdict

Confirmed. `recipientAddress` comes from an HTTP request parameter and is concatenated directly into the `RCPT TO:<...>` line written to a raw SMTP socket. Because SMTP commands are delimited by CRLF, an attacker who supplies a value containing `\r\n` can terminate the `RCPT TO` command early and inject arbitrary additional SMTP commands (extra `RCPT TO` lines, a rewritten `MAIL FROM`, or content that manipulates the `DATA` section), giving them control over message recipients and/or contents.

## Source

`request.getParameter("customerEmail")` in `sendOrderConfirmation(HttpServletRequest request)` (line 9), flowing unmodified into the `out.write(...)` call at line 18.

## Fix

### File: SmtpRawSocketRcptInjection.java
```java
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;

public class SmtpRawSocketRcptInjection {

    // RFC 5321-style mailbox: local-part @ domain, restricted to characters that
    // cannot contain CR/LF or otherwise break out of the RCPT TO command line.
    private static final Pattern VALID_EMAIL =
            Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
        String recipientAddress = request.getParameter("customerEmail");

        if (recipientAddress == null || !VALID_EMAIL.matcher(recipientAddress).matches()) {
            throw new IllegalArgumentException("Invalid recipient email address");
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

The fix validates `recipientAddress` against a strict mailbox pattern (`local-part@domain.tld`, restricted to the character classes that constitute a valid email address) before it is used to build the raw SMTP command. Because the allowed character set excludes `\r`, `\n`, and any other control or whitespace characters, an attacker cannot smuggle a CRLF sequence into the `RCPT TO` line to terminate it early and inject additional SMTP commands. Any value that isn't a syntactically valid email address - including one containing CR/LF or other injection payloads - causes the method to throw before the socket is even opened, so no partial or attacker-influenced SMTP transaction is sent.

This is an allowlist applied to a value the application already requires to be a well-formed email address for the feature to work at all (it is used as the SMTP recipient), so the validation is not an added restriction beyond what the domain already demands - it rejects only inputs that could never be a legitimate recipient address in the first place.
