## Verdict

CWE-77 (Improper Neutralization of Special Elements used in a Command, applied here to the SMTP control-channel dialogue) - **exploitable**. Confidence: high.

- Location: `SmtpRelayClient.java`, `sendAcknowledgement()`, line 28 (`MAIL FROM:<...>` write).
- No validation or CRLF stripping occurs anywhere on the path from the HTTP parameter to the socket write.

## Source

`TicketController.handleSubmit(HttpServletRequest request)`, line 20:

```
String requesterEmail = request.getParameter("requesterEmail");
```

Call chain (no sanitization at any hop):

1. `TicketController.handleSubmit` reads `requesterEmail` from the HTTP request and wraps it in a `TicketSubmission` (line 23), then calls `notificationService.notifyAgent(submission)` (line 24).
2. `TicketNotificationService.notifyAgent` passes `submission.getRequesterEmail()` straight through as the first constructor argument of `MailEnvelope` (line 24), which is the `replyTo` field.
3. `SmtpRelayClient.sendAcknowledgement` calls `envelope.getReplyTo()` and concatenates it into the raw SMTP command line at line 28:
   `out.write(("MAIL FROM:<" + envelope.getReplyTo() + ">\r\n").getBytes(...))`.

Sink: `Socket.getOutputStream().write()` on a hand-built SMTP command string, terminated with a literal `\r\n`. An attacker-controlled `requesterEmail` containing an embedded `\r\n` breaks out of the `MAIL FROM` command and injects arbitrary additional SMTP commands into the same connection (e.g. reroute `RCPT TO`, forge additional `MAIL FROM`, or inject `DATA` content) - full SMTP command injection to the internal mail gateway.

A secondary, related path also reaches this sink object: `submission.getSubject()` flows into `MailEnvelope.subjectLine` (`TicketNotificationService`, line 26) and is written raw into the `DATA` section at line 31 with no header formatting and no CRLF handling. Per the language guidance, the CR/LF scan added to fix CVE-2025-7962 covers only the command channel, not anything inside `DATA`, so this is a second, independent injection point reachable through the same call chain.

## Fix

**Library recommendation:** Jakarta Mail's `Session`/`Transport`/`MimeMessage` API (artifact `com.sun.mail:jakarta.mail`), replacing the hand-rolled `Socket` protocol writer. The codebase uses the pre-Jakarta-EE9 `javax.*` namespace (`javax.servlet.http.HttpServletRequest`), so the matching implementation line is the `javax.mail.*`-namespaced branch: minimum **1.6.8**, which is where the CR/LF scan on outgoing SMTP commands (CVE-2025-7962) first ships for that branch. Confirm the resolved version against SCA/dependency-check tooling before merging; do not treat the library alone as sufficient - address validation below is still required, since a CRLF inside a quoted local part in `InternetAddress` parsing is accepted by design.

```xml
<dependency>
    <groupId>com.sun.mail</groupId>
    <artifactId>jakarta.mail</artifactId>
    <version>1.6.8</version>
</dependency>
```

**Vulnerable code** (`SmtpRelayClient.java`):

```java
public void sendAcknowledgement(MailEnvelope envelope) {
    try (Socket socket = new Socket(relayHost, relayPort)) {
        OutputStream out = socket.getOutputStream();
        out.write("HELO support-app.example.com\r\n".getBytes(StandardCharsets.US_ASCII));
        // VULNERABLE: envelope.getReplyTo() is attacker-controlled (HTTP "requesterEmail"
        // parameter) and concatenated directly into an SMTP command line. An embedded
        // \r\n injects arbitrary additional SMTP commands.
        out.write(("MAIL FROM:<" + envelope.getReplyTo() + ">\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(("RCPT TO:<" + envelope.getRecipient() + ">\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write("DATA\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write((envelope.getSubjectLine() + "\r\n\r\n.\r\n").getBytes(StandardCharsets.US_ASCII));
    } catch (IOException e) {
        throw new RuntimeException("Failed to relay ticket acknowledgement", e);
    }
}
```

**Fixed code** (`SmtpRelayClient.java`):

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
 * mail gateway, via Jakarta Mail's Session/Transport API.
 */
public class SmtpRelayClient {

    private final String relayHost;
    private final int relayPort;

    public SmtpRelayClient(String relayHost, int relayPort) {
        this.relayHost = relayHost;
        this.relayPort = relayPort;
    }

    public void sendAcknowledgement(MailEnvelope envelope) {
        Properties props = new Properties();
        props.put("mail.smtp.host", relayHost);
        props.put("mail.smtp.port", String.valueOf(relayPort));

        Session session = Session.getInstance(props);
        try {
            // Break taint: construct and validate InternetAddress objects instead of
            // writing the raw strings into a command line. Strict parsing (the `true`
            // argument) rejects CR/LF in an unquoted local part.
            InternetAddress from = new InternetAddress(envelope.getReplyTo(), true);
            InternetAddress recipient = new InternetAddress(envelope.getRecipient(), true);

            MimeMessage message = new MimeMessage(session);
            message.setFrom(from);
            message.setRecipient(Message.RecipientType.TO, recipient);
            // Strip CR/LF explicitly: MimeMessage.setSubject() does not neutralize
            // embedded line breaks itself - the caller is responsible for that.
            message.setSubject(envelope.getSubjectLine().replaceAll("[\r\n]", ""));
            message.setText("");

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

The vulnerability was command-string concatenation: `envelope.getReplyTo()` (ultimately the HTTP `requesterEmail` parameter) was written directly into a `MAIL FROM:<...>\r\n` line sent over a raw `Socket`, so any embedded `\r\n` in that value terminated the intended command and let the attacker append further SMTP commands of their choosing. The fix removes the hand-rolled protocol dialogue entirely and lets Jakarta Mail's `Session`/`Transport`/`MimeMessage` API frame the SMTP commands: `InternetAddress(address, true)` performs strict address parsing and rejects CR/LF in an unquoted local part before the value ever reaches the network, and at version 1.6.8+ the transport layer itself scans outgoing command lines for CR/LF as a second layer of defense. The subject line - a secondary path into the `DATA` section that the command-channel scan does not cover - is explicitly stripped of CR/LF before being handed to `setSubject()`, since the JavaMail contract places that responsibility on the caller. Both the primary MAIL FROM injection (line 28) and the secondary DATA-section injection (line 31, reached through the same `subject` parameter) are closed by this change.

## Behaviour changes

- Malformed or CRLF-bearing addresses (`requesterEmail` or the hardcoded recipient) are now rejected with `AddressException` before any network write occurs, instead of being written raw to the socket. Required to close the injection.
- The subject is stripped of `\r` and `\n` before use. Required to close the secondary DATA-section injection path, since `MimeMessage.setSubject()` does not do this itself.
- The outgoing message now carries standard MIME headers (`From`, `To`, `Subject`, `Date`, `Message-ID`, `MIME-Version`, `Content-Type`) generated by `MimeMessage`/`Transport`. The original wrote a non-standard payload with no header block at all (just the raw subject line followed by the end-of-data marker). This is an unavoidable side effect of replacing the hand-rolled protocol writer with a standards-compliant mail API, not a deliberate feature addition.
- SMTP-level send failures (e.g. the server rejecting an address, a 5xx response) now surface as a thrown exception. The original code never read the server's response after writing each command, so such failures were previously silent. Both old and new code ultimately throw `RuntimeException` to the caller, matching `TicketNotificationService.notifyAgent`'s existing catch-free propagation, so the change is in what triggers the exception, not in how it propagates.
- No TLS or authentication configuration was added; the connection remains plaintext by default, unchanged from the original. The Java guidance recommends setting `mail.smtp.starttls.required=true` as further hardening, but that is independent of the injection weakness and could break connectivity if the relay does not support STARTTLS - left as a follow-up for the developer to confirm against the actual relay configuration rather than bundled into this fix.

**Assumptions:** the existing `MailEnvelope`/`TicketSubmission` field order (`replyTo`, `recipient`, `subjectLine`) was taken from the constructor call sites in `TicketNotificationService`, not from any doc comment, since the doc comment's description ("threaded through as reply-to") describes the field's intended use but the code actually uses it as the SMTP envelope-from address - this is a pre-existing naming/design detail in the fixture, not something altered by the fix; the `From` address in the fixed code is set to the same value the original used for `MAIL FROM` (envelope.getReplyTo()) to preserve identical addressing semantics.
