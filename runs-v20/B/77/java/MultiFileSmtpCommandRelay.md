## Verdict

Exploitable. Confidence: high.

## Source

- **Source:** `TicketController.handleSubmit(HttpServletRequest request)` reads `request.getParameter("requesterEmail")` (and `subject`), both fully attacker-controlled via the public "contact support" web form. These flow into a `TicketSubmission`, then into `TicketNotificationService.notifyAgent`, which builds a `MailEnvelope(requesterEmail, "support-queue@example.com", "Ticket received: " + subject)` and passes it to `SmtpRelayClient.sendAcknowledgement`.
- **Sink:** `SmtpRelayClient.sendAcknowledgement`, `SmtpRelayClient.java` line 28 - `out.write(("MAIL FROM:<" + envelope.getReplyTo() + ">\r\n").getBytes(...))`. `envelope.getReplyTo()` is the untrusted `requesterEmail` value, concatenated directly into a raw SMTP command line written to the socket. A value containing `\r\n` terminates the `MAIL FROM` command early and injects arbitrary additional SMTP commands (e.g. a forged `RCPT TO` to exfiltrate mail, or a full second message) into the same connection to the relay host. The adjacent `RCPT TO` line (line 29) is not independently exploitable since `envelope.getRecipient()` is the hardcoded literal `"support-queue@example.com"`, but the subject line written into the `DATA` payload (line 31) is the same untrusted-concatenation pattern and is addressed by the same fix.

## Fix

**Library recommendation:** JavaMail (`javax.mail` API), per the loaded CWE-77/Java guidance's primary defence of using the `Session`/`Transport`/`MimeMessage` API instead of hand-writing SMTP command lines over a raw `Socket`. Minimum safe version: **`com.sun.mail:jakarta.mail:1.6.8`** (this line ships under the `javax.mail` package namespace, matching this codebase's existing `javax.servlet` usage) - the guidance's cited floor for the CR/LF command-line scan fixed under CVE-2025-7962; the `jakarta.mail`-namespaced line reaches the same fix at `2.0.2`. Below either floor, `SMTPTransport` forwards a CR/LF sequence that address parsing lets through. Add the dependency to the project's manifest, e.g. in `pom.xml`:

```xml
<dependency>
    <groupId>com.sun.mail</groupId>
    <artifactId>jakarta.mail</artifactId>
    <version>1.6.8</version>
</dependency>
```

Confirm the resolved version against SCA/dependency-check tooling before merging.

### File: SmtpRelayClient.java

```java
package com.example.support;

import java.util.Properties;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

/**
 * SMTP client used to relay ticket acknowledgements through the internal
 * mail gateway. Built on the JavaMail Session/Transport API so the
 * protocol dialogue is framed by the library instead of hand-written
 * command lines.
 */
public class SmtpRelayClient {

    private final String relayHost;
    private final int relayPort;

    public SmtpRelayClient(String relayHost, int relayPort) {
        this.relayHost = relayHost;
        this.relayPort = relayPort;
    }

    public void sendAcknowledgement(MailEnvelope envelope) {
        try {
            InternetAddress from = new InternetAddress(envelope.getReplyTo(), true);
            InternetAddress to = new InternetAddress(envelope.getRecipient(), true);

            Properties props = new Properties();
            props.put("mail.smtp.host", relayHost);
            props.put("mail.smtp.port", String.valueOf(relayPort));
            props.put("mail.smtp.localhost", "support-app.example.com");

            Session session = Session.getInstance(props);
            MimeMessage message = new MimeMessage(session);
            message.setFrom(from);
            message.setRecipient(Message.RecipientType.TO, to);
            message.setText(envelope.getSubjectLine());

            Transport.send(message);
        } catch (AddressException e) {
            throw new RuntimeException("Rejected malformed address in ticket acknowledgement", e);
        } catch (MessagingException e) {
            throw new RuntimeException("Failed to relay ticket acknowledgement", e);
        }
    }
}
```

## Explanation

The vulnerable code built raw SMTP protocol lines by string concatenation and wrote them straight to the socket, so a `requesterEmail` containing `\r\n` could terminate the `MAIL FROM` command early and inject arbitrary follow-on SMTP commands into the relay connection. The fix removes the hand-rolled socket dialogue entirely and lets JavaMail's `Session`/`Transport`/`MimeMessage` API frame the SMTP command channel: `Transport.send` builds and terminates each command line itself rather than accepting caller-built strings, and per the version floor above it also scans the outgoing command for embedded CR/LF. As defence-in-depth ahead of the library call, both untrusted addresses are parsed with `new InternetAddress(address, true)` (strict mode) inside the try block, so a value carrying CR/LF or otherwise malformed is rejected with `AddressException` before it ever reaches the transport, and only the validated `InternetAddress` objects - never the raw strings - are used downstream on `message.setFrom`/`setRecipient`. This also closes the same concatenation pattern in the `DATA` payload (originally line 31): `setText` hands the subject-line content to the library's message-body writer, which applies MIME-standard dot-stuffing/line framing, so a value containing `\r\n.\r\n` can no longer terminate `DATA` early and smuggle a second SMTP command into the connection.

## Behaviour changes

- **Envelope sender (`MAIL FROM`):** preserved. JavaMail's `SMTPTransport` uses the message's `From` header address as the `MAIL FROM` value when no `mail.smtp.from` session property is set, so `message.setFrom(from)` reproduces the original `MAIL FROM:<replyTo>` semantics with `from` now a validated `InternetAddress`.
- **Recipient (`RCPT TO`) and `To:` header:** the `RCPT TO` target is preserved (`envelope.getRecipient()`, the fixed literal). A `To:` header now appears in the message content, which the original hand-written wire traffic never sent (it emitted no message headers at all). This is an unavoidable consequence of building a `MimeMessage`, which requires a recipient to send; it does not change which mailbox receives the mail.
- **Message body:** preserved in content - `envelope.getSubjectLine()` is still the entire body text, exactly as the original wrote it after `DATA`. No `Subject:` header is added, matching the original's behaviour of never having sent one (the original wrote the "subject" text as raw body content, not as a header, despite the field's name).
- **Local hostname:** preserved - `mail.smtp.localhost` is set to `"support-app.example.com"` so the client identifies itself the same way the original hand-written `HELO` line did; JavaMail issues the greeting itself instead of the code writing it.
- **Failure behaviour:** preserved at the boundary - `sendAcknowledgement` still throws an unchecked `RuntimeException` on any failure (now covering both a rejected malformed address and any transport-level `MessagingException`), matching the original's `IOException`-to-`RuntimeException` contract that callers already rely on.
- **New failure mode surfaced:** a `requesterEmail` or the fixed recipient value that fails strict `InternetAddress` parsing now causes the acknowledgement to fail loudly (`RuntimeException` wrapping `AddressException`) rather than being silently written to the wire. This is intended - such input was the injection vector - but it means a malformed-but-previously-"tolerated" requester email now blocks the acknowledgement instead of best-effort sending.
- **Not enabled - flagged, not silently added:** the relay connection remains unencrypted, matching the original's plain `Socket`. The guidance's `mail.smtp.starttls.required=true` hardening is a separate, non-default-preserving change (it fails the send instead of continuing in plaintext against a relay that doesn't advertise STARTTLS) and is left as a follow-up recommendation rather than folded into this fix.
- **Public API:** unchanged - `SmtpRelayClient`'s constructor and `sendAcknowledgement(MailEnvelope)` signature are identical, so `TicketNotificationService.java` and `TicketController.java` require no changes and compile against this file as-is.
- **Assumption:** the codebase's existing `javax.servlet.http.HttpServletRequest` import indicates a pre-Jakarta-EE-9 stack, so the `javax.mail` (not `jakarta.mail` package) namespace was chosen for the fix, backed by the `com.sun.mail:jakarta.mail:1.6.8` artifact that ships that namespace at the guidance's fixed version.
- **Verification:** compiled with `javac` (JDK 26) against `com.sun.mail:jakarta.mail:1.6.8` (the recommended version floor) on the classpath, alongside the unmodified `TicketNotificationService.java` and `TicketController.java` (with `javax.servlet-api:4.0.1` for the latter) copied from the case directory into a scratch build dir - all four classes compiled with no errors or warnings, confirming every JavaMail symbol used (`Session.getInstance`, `MimeMessage`, `InternetAddress`, `AddressException`, `Message.RecipientType.TO`, `Transport.send`) exists at that version and that the fixed file's public surface still matches what the two unmodified callers expect.
