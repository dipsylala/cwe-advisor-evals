## Verdict

- **CWE-77** (Improper Neutralization of Special Elements used in a Command / SMTP command injection)
- **Verdict:** exploitable
- **Confidence:** high

## Source

- **Source:** `request.getParameter("customerEmail")` (`HttpServletRequest`), line 9 - attacker-controlled HTTP request parameter.
- **Sink:** `out.write(("RCPT TO:<" + recipientAddress + ">\r\n").getBytes(...))` via `Socket.getOutputStream().write()`, line 18.
- **Data flow:** `recipientAddress` is read from the request with no validation and concatenated directly into a hand-built `RCPT TO:` SMTP command line terminated with `\r\n`, then written to the raw socket. A value containing an embedded `\r\n` closes that command early and injects an attacker-chosen line as a new SMTP command in the same session (e.g. an extra `RCPT TO:` to add a blind-copy recipient, or content that reaches the `DATA` phase), because nothing rejects CR/LF before it reaches the wire.

## Fix

The primary defence per the loaded Java-specific guidance for CWE-77 is to replace the hand-rolled `Socket` SMTP dialogue with Jakarta Mail's `Session`/`Transport`/`MimeMessage` API, and to validate the recipient with `new InternetAddress(address, true)` so a malformed or CRLF-bearing address is rejected before it becomes part of any protocol command.

**Library recommendation:** use `com.sun.mail:jakarta.mail` (the `jakarta.mail`/`jakarta.mail.internet` packages), minimum version **2.0.2** on the Jakarta line (or **1.6.8** on the legacy `javax.mail` line) - below that floor the transport's own `MAIL FROM`/`RCPT TO` construction did not scan for CR/LF (CVE-2025-7962), so an address that passed `InternetAddress` parsing could still reach the wire intact. If the runtime resolves `org.eclipse.angus:angus-mail` as the implementation instead, its floor is **2.0.4** for the same fix. No manifest file (`pom.xml`/`build.gradle`) is present in this case's file chain, so the dependency declaration/version bump itself cannot be shown here - add the dependency and confirm the resolved version with SCA/dependency-check tooling before merging, per the version-floor guidance.

### File: SmtpRawSocketRcptInjection.java

```java
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;

import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

public class SmtpRawSocketRcptInjection {

    public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
        String recipientAddress = request.getParameter("customerEmail");

        // Validate and canonicalize the recipient before it reaches any protocol
        // command; a malformed or CRLF-bearing value throws instead of being
        // forwarded to the mail server.
        InternetAddress recipient;
        try {
            recipient = new InternetAddress(recipientAddress, true);
        } catch (AddressException e) {
            throw new IllegalArgumentException("Invalid recipient address", e);
        }

        Properties props = new Properties();
        props.put("mail.smtp.host", "mail.internal.example.com");
        props.put("mail.smtp.port", "25");
        props.put("mail.smtp.localhost", "app.example.com");

        Session session = Session.getInstance(props);

        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress("no-reply@example.com"));
        message.setRecipient(Message.RecipientType.TO, recipient);
        message.setSubject("Order confirmation");
        message.setText("Thanks for your order.\r\n");

        // Transport.send() carries the EHLO/MAIL FROM/RCPT TO/DATA/QUIT dialogue
        // itself, using the validated InternetAddress rather than a concatenated
        // command string.
        Transport.send(message);
    }
}
```

## Explanation

The vulnerability was a hand-built SMTP `RCPT TO:` command line assembled by string concatenation and written straight to a raw `Socket`, so any CR/LF in the `customerEmail` request parameter terminated that command and let the attacker inject an arbitrary follow-on SMTP command into the session. The fix removes the raw socket and hand-written protocol lines entirely and lets Jakarta Mail's `Transport.send()` carry the EHLO/MAIL FROM/RCPT TO/DATA/QUIT dialogue, using a `MimeMessage` built from library APIs (`setFrom`, `setRecipient`, `setSubject`, `setText`) instead of concatenated strings. Before the recipient is used at all, it is parsed with `new InternetAddress(recipientAddress, true)`, which performs strict RFC 822 syntax validation and rejects an address carrying stray CR/LF in the unquoted local part; only that validated `InternetAddress` object - never the original raw string - is passed to `setRecipient`. This closes the injection at both layers the guidance calls out: the input is validated before use, and the library version required (`jakarta.mail` >= 2.0.2 / 1.6.8, or `angus-mail` >= 2.0.4) additionally scans the outgoing command itself for CR/LF as a second layer, since address parsing alone does not catch every case (e.g. CRLF+whitespace inside a quoted string is legal address syntax).

## Behaviour changes

- **Recipient is now validated and can throw:** `new InternetAddress(recipientAddress, true)` rejects a malformed or CRLF-bearing address with `AddressException`, which is wrapped and re-thrown as `IllegalArgumentException`. Previously any value, valid or not, was silently written to the socket. This is the intended effect of the fix, not incidental - it is what closes the injection.
- **EHLO/client identity preserved explicitly:** the original code sent the literal client hostname `app.example.com` in its hand-written `EHLO` line. `Transport`/`Session` do not reuse that string automatically (it otherwise defaults to the local machine's hostname), so `mail.smtp.localhost=app.example.com` is set to keep the same identity string on the wire.
- **No TLS added:** the original opened a plain `Socket` on port 25 with no STARTTLS. The fix does not set `mail.smtp.starttls.*` either, so the connection remains plaintext, matching prior behaviour; enabling STARTTLS is a separate hardening change per the loaded guidance, not bundled here since it would change what happens against a server that doesn't advertise it.
- **Message content unchanged:** subject ("Order confirmation") and body ("Thanks for your order.") are reproduced via `setSubject`/`setText` with the same text as the original hand-written `DATA` payload.
- **Exception contract unchanged:** the method still declares `throws Exception`, so the checked exceptions now thrown by `InternetAddress`, `MimeMessage`, and `Transport.send()` (`MessagingException`/`AddressException`) propagate the same way `IOException` did from the raw socket writes - no caller-visible signature change.
- **Connection lifecycle:** `Transport.send()` opens, uses, and closes its own connection (including `QUIT`) internally, replacing the explicit `socket.close()`; no connection is left open longer than before.

**Verification:** compiled with `javac` (JDK 26) against the real dependencies - `jakarta.mail-2.0.2.jar` (the guidance's version floor), `jakarta.mail-api-2.0.1.jar`, `jakarta.activation-1.2.2.jar`, and `javax.servlet-api-4.0.1.jar`, all fetched from Maven Central - with `-Xlint:all`. Result: zero errors, zero warnings. This confirms every newly introduced name (`Session`, `Transport`, `MimeMessage`, `Message.RecipientType`, `InternetAddress`, `AddressException`, and each method call/argument shape) resolves correctly against the actual Jakarta Mail 2.0.2 API.

**Assumptions:**
- No `pom.xml`/`build.gradle` exists in this case's file chain, so the dependency version floor is stated as guidance rather than shown as a manifest diff.
- Preserving the original `app.example.com` EHLO identity via `mail.smtp.localhost` was inferred as the closest equivalent to the original hand-written `EHLO` line; the guidance does not specify this property name for the CWE-77 fix itself, but it is a standard JavaMail session property confirmed against the compiled API.
