## Verdict

Exploitable (high confidence). `recipientAddress` comes straight from `request.getParameter("customerEmail")` with no validation or neutralization anywhere between the source and the socket write, so a value containing `\r\n` reaches the SMTP command channel intact.

## Source

`HttpServletRequest.getParameter("customerEmail")` at line 9 (`sendOrderConfirmation`). Attacker-controlled: any client submitting the order-confirmation request chooses this value directly, and nothing on the path constrains its character set.

## Fix

**Library recommendation:** replace the hand-rolled SMTP dialogue with Jakarta Mail's `Session`/`Transport`/`MimeMessage` API. Per the loaded guidance, pin the *implementation* artifact, not just the API jar: `com.sun.mail:jakarta.mail` >= 2.0.2 (or 1.6.8 on the 1.6.x line), or `org.eclipse.angus:smtp` >= 2.0.4 if using the Angus implementation — these versions add the CR/LF scan on the outgoing command (CVE-2025-7962); below that floor the transport still forwards an injected CRLF that address parsing let through. Confirm the resolved version against SCA/dependency-check tooling before merging — this is guidance, not a live scan.

Manifest change (Maven, `pom.xml`):

```xml
<dependency>
    <groupId>com.sun.mail</groupId>
    <artifactId>jakarta.mail</artifactId>
    <version>2.0.2</version>
</dependency>
```

**Vulnerable code:**

```java
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;

public class SmtpRawSocketRcptInjection {

    public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
        String recipientAddress = request.getParameter("customerEmail");

        Socket socket = new Socket("mail.internal.example.com", 25);
        OutputStream out = socket.getOutputStream();

        out.write("EHLO app.example.com\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write("MAIL FROM:<no-reply@example.com>\r\n".getBytes(StandardCharsets.US_ASCII));

        // VULNERABLE: recipientAddress is concatenated raw into an SMTP command line.
        // A value containing "\r\n" injects additional SMTP commands into this connection.
        out.write(("RCPT TO:<" + recipientAddress + ">\r\n").getBytes(StandardCharsets.US_ASCII));

        out.write("DATA\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write(("Subject: Order confirmation\r\n\r\nThanks for your order.\r\n.\r\n")
                .getBytes(StandardCharsets.US_ASCII));
        out.write("QUIT\r\n".getBytes(StandardCharsets.US_ASCII));

        socket.close();
    }
}
```

**Fixed code:**

```java
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;

public class SmtpRawSocketRcptInjection {

    public void sendOrderConfirmation(HttpServletRequest request) throws MessagingException {
        String recipientAddress = request.getParameter("customerEmail");

        // Validate and parse the untrusted address; construction alone is not a check,
        // so the strict two-argument form is required and failure must be caught.
        InternetAddress recipient;
        try {
            recipient = new InternetAddress(recipientAddress, true);
        } catch (AddressException e) {
            throw new MessagingException("Invalid recipient address", e);
        }

        Properties props = new Properties();
        props.put("mail.smtp.host", "mail.internal.example.com");
        props.put("mail.smtp.port", "25");
        props.put("mail.smtp.starttls.required", "true");

        Session session = Session.getInstance(props);

        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress("no-reply@example.com"));
        // Break taint: the sink uses the validated InternetAddress object, never the raw string.
        message.setRecipient(Message.RecipientType.TO, recipient);
        message.setSubject("Order confirmation");
        message.setText("Thanks for your order.\r\n");

        Transport.send(message);
    }
}
```

## Explanation

The vulnerable code drives the entire SMTP dialogue by writing hand-built command lines to a raw `Socket`, and concatenates the untrusted `recipientAddress` directly into the `RCPT TO:` line; any `\r\n` in that value terminates the intended command and lets the attacker append arbitrary further SMTP commands (additional recipients, a forged `DATA` body, or `MAIL FROM` for a different envelope) on the same connection. The fix removes the hand-rolled protocol client entirely and lets Jakarta Mail's `Session`/`Transport`/`MimeMessage` API construct and send the message, per the primary defence in the loaded Java guidance. Before that API is reached, the address is parsed and validated with the two-argument `InternetAddress(address, true)` constructor inside a try/catch, and only the resulting validated `InternetAddress` object — never the original string — is passed to `setRecipient`, so the taint never reaches a place it could inject a delimiter. `Transport.send` on a library at or above the stated version floor (`jakarta.mail` 2.0.2 / 1.6.8, or `angus:smtp` 2.0.4) additionally scans the outgoing command for CR/LF, closing the gap that existed even after address parsing on older versions. `mail.smtp.starttls.required=true` is set per the guidance's hardening step so the connection fails rather than silently falling back to plaintext.

## Behaviour changes

- **Transport mechanism replaced:** raw `Socket` + manual `EHLO`/`MAIL FROM`/`RCPT TO`/`DATA`/`QUIT` writes are replaced by `Transport.send(message)`, which performs the same SMTP dialogue internally. Required to remove the injectable command-string construction; this is the guidance's stated primary defence, not an incidental change.
- **Recipient validation added:** an invalid or malicious `customerEmail` now throws `MessagingException` (wrapping `AddressException`) instead of being written to the wire unchecked. This is the defence-in-depth step the guidance prescribes; it rejects a request that previously would have silently succeeded (or injected commands).
- **Exception type narrowed:** the method now declares `throws MessagingException` instead of the original's blanket `throws Exception`. `MessagingException` is what `InternetAddress` construction and `Transport.send` actually throw; callers catching the previous broad `Exception` still catch this, since `MessagingException` is a subtype path reachable through it in typical handling, but a caller matching on the original method's exact declared type should widen or add a catch clause for `MessagingException`.
- **STARTTLS now required:** `mail.smtp.starttls.required=true` is set, so the send fails if the server does not offer STARTTLS, rather than continuing in plaintext as the original raw-socket code did (which had no TLS at all). This is the guidance's configuration-hardening step, applied because the fix already touches the connection setup; flag for review if the internal mail relay is not known to support STARTTLS.
- **Message body reframed as a proper MIME message:** the original wrote a bare `Subject:`/body block as literal DATA bytes; `MimeMessage.setSubject`/`setText` produce a correctly-framed MIME message instead. Necessary because message construction moved to the `MimeMessage` object; per the guidance, header injection into `setSubject`/`setHeader` is the caller's responsibility and out of scope for this specific finding since `Subject` is a fixed literal here, not attacker-controlled.
- Socket lifecycle management (`new Socket(...)`, explicit `close()`) is gone — `Transport.send` opens and closes its own connection. This is an unavoidable consequence of removing the raw-socket transport, not a discretionary addition.
