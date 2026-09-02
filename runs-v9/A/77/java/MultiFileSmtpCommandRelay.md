## Verdict

Confirmed. `SmtpRelayClient.sendAcknowledgement` (line 28, and also line 29/31) writes attacker-controlled strings directly into raw SMTP protocol lines over the socket, with no check for CR/LF or SMTP metacharacters. This is CWE-77 (Improper Neutralization of Special Elements used in a Command) specialized as SMTP command/header injection.

## Source

`TicketController.handleSubmit` reads `requesterEmail` (and `subject`) straight from `HttpServletRequest.getParameter(...)` with no validation (`TicketController.java:20`). It flows unchanged into a `TicketSubmission`, then into `TicketNotificationService.notifyAgent`, which copies `submission.getRequesterEmail()` into `MailEnvelope.replyTo` and `"Ticket received: " + submission.getSubject()` into `MailEnvelope.subjectLine` (`TicketNotificationService.java:23-26`). `SmtpRelayClient.sendAcknowledgement` then concatenates `envelope.getReplyTo()` into the `MAIL FROM:<...>` command and `envelope.getSubjectLine()` into the DATA block (`SmtpRelayClient.java:28,31`), writing the result directly to the socket. Nothing between the HTTP parameter and the socket write strips or rejects `\r`, `\n`, `<`, `>`, or other characters meaningful to the SMTP command grammar.

## Fix

Add centralized validation/neutralization at the point the values are placed into protocol data — the `SmtpRelayClient` sink — rather than trusting every caller to have sanitized first, since the client is reused wherever an envelope is built:

```java
package com.example.support;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * Minimal hand-rolled SMTP client used to relay ticket acknowledgements
 * through the internal mail gateway, without pulling in a full mail
 * client library.
 */
public class SmtpRelayClient {

    // Conservative RFC 5321-style mailbox check: no CR/LF, no angle
    // brackets, no whitespace, no control characters can reach the
    // command line this value is interpolated into.
    private static final Pattern SAFE_MAILBOX =
            Pattern.compile("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    private final String relayHost;
    private final int relayPort;

    public SmtpRelayClient(String relayHost, int relayPort) {
        this.relayHost = relayHost;
        this.relayPort = relayPort;
    }

    public void sendAcknowledgement(MailEnvelope envelope) {
        String replyTo = requireSafeMailbox(envelope.getReplyTo(), "replyTo");
        String recipient = requireSafeMailbox(envelope.getRecipient(), "recipient");
        String subjectLine = stripCrlf(envelope.getSubjectLine());

        try (Socket socket = new Socket(relayHost, relayPort)) {
            OutputStream out = socket.getOutputStream();
            out.write("HELO support-app.example.com\r\n".getBytes(StandardCharsets.US_ASCII));
            out.write(("MAIL FROM:<" + replyTo + ">\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write(("RCPT TO:<" + recipient + ">\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write("DATA\r\n".getBytes(StandardCharsets.US_ASCII));
            out.write((subjectLine + "\r\n\r\n.\r\n").getBytes(StandardCharsets.US_ASCII));
        } catch (IOException e) {
            throw new RuntimeException("Failed to relay ticket acknowledgement", e);
        }
    }

    private static String requireSafeMailbox(String value, String fieldName) {
        if (value == null || !SAFE_MAILBOX.matcher(value).matches()) {
            throw new IllegalArgumentException("Invalid " + fieldName + " address for SMTP relay");
        }
        return value;
    }

    private static String stripCrlf(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\r", "").replace("\n", "");
    }
}
```

Reject, don't merely strip, on the two address fields (`replyTo`, `recipient`): they are used as SMTP path arguments inside `<...>`, so a value that fails to parse as a plain mailbox should be treated as an application error (bad submission) rather than silently coerced, which is also what stops an attacker from smuggling extra `RCPT TO`/`DATA` commands via CR/LF or from breaking out of the `<>` wrapper via a bare `>`. The subject line only feeds the free-text DATA section immediately followed by the hard-coded `\r\n\r\n.\r\n` terminator, so stripping embedded CR/LF (rather than rejecting) is sufficient there — it removes the only characters that could open a fake header block or prematurely terminate the message with a `.` line, without rejecting legitimate ticket subjects.

If a richer mail feature set is ever needed (attachments, MIME headers, HTML bodies), replace this hand-rolled client with a maintained library such as Jakarta Mail (`jakarta.mail:jakarta.mail-api` + an implementation like `org.eclipse.angus:angus-mail`), which builds and encodes SMTP commands and message headers itself instead of via raw string concatenation.

## Explanation

`MAIL FROM:<...>` and `RCPT TO:<...>` are literal command lines in the SMTP protocol (RFC 5321); the DATA block terminates on a line containing only `.`. Because the client builds every one of these lines by string concatenation and writes the raw bytes to the socket, any `\r\n` embedded in `requesterEmail` or `subject` is indistinguishable from a real protocol line break to the receiving mail server. A requester who submits an email address like `victim@example.com>\r\nRCPT TO:<attacker@evil.example>\r\nDATA\r\nSpoofed body\r\n.\r\n` (or similar in the subject) can inject additional SMTP commands — adding extra recipients, rewriting the message body, or issuing further protocol commands — turning the support form into an open mail relay / spam or phishing vector, entirely independent of what the legitimate `MAIL FROM`/`RCPT TO`/`DATA` calls intended to send. Validating the two address fields against a strict mailbox grammar and stripping CR/LF from the subject removes the attacker's ability to insert protocol-significant bytes into any of the four interpolation points, closing the injection while leaving normal ticket submissions unaffected.
