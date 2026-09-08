## Verdict

Confirmed. `SmtpRelayClient.sendAcknowledgement` builds raw SMTP protocol lines by string concatenation and writes them directly to the socket, with no neutralization of CR/LF (or NUL) in the interpolated values. An attacker who controls those values can terminate the current SMTP command (or the `DATA` block) early and inject arbitrary additional SMTP commands into the session - e.g. adding extra `RCPT TO:` recipients to relay spam through the internal gateway, or forging the message body after prematurely closing `DATA` with a lone `.` line.

## Source

`TicketController.handleSubmit` reads two attacker-controlled HTTP parameters directly off the request:

- `request.getParameter("requesterEmail")`
- `request.getParameter("subject")`

These are wrapped in a `TicketSubmission` with no validation, then passed to `TicketNotificationService.notifyAgent`, which builds a `MailEnvelope` where `replyTo = submission.getRequesterEmail()` and `subjectLine = "Ticket received: " + submission.getSubject()`. That envelope reaches `SmtpRelayClient.sendAcknowledgement`, which writes `replyTo` into the `MAIL FROM:<...>` command and `subjectLine` into the `DATA` block content - both without checking for embedded `\r`/`\n` sequences before they reach the socket.

## Fix

### File: SmtpRelayClient.java

```java
package com.example.support;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Minimal hand-rolled SMTP client used to relay ticket acknowledgements
 * through the internal mail gateway, without pulling in a full mail
 * client library.
 */
public class SmtpRelayClient {

    private final String relayHost;
    private final int relayPort;

    public SmtpRelayClient(String relayHost, int relayPort) {
        this.relayHost = relayHost;
        this.relayPort = relayPort;
    }

    public void sendAcknowledgement(MailEnvelope envelope) {
        String replyTo = requireNoSmtpControlChars(envelope.getReplyTo(), "replyTo");
        String recipient = requireNoSmtpControlChars(envelope.getRecipient(), "recipient");
        String subjectLine = requireNoSmtpControlChars(envelope.getSubjectLine(), "subjectLine");

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

    /**
     * Every command and the DATA content in this client are assembled by
     * concatenating raw strings onto the wire, so a CR, LF, or NUL byte
     * reaching this point would let a caller terminate the current
     * command (or the DATA block, via an injected line consisting only
     * of ".") and inject further SMTP commands into the same session.
     * Reject any such value outright instead of stripping it: stripping
     * would silently turn a chosen value into a different one rather
     * than refusing the request, and would not stop an attacker from
     * simply omitting the character they no longer need.
     */
    private static String requireNoSmtpControlChars(String value, String fieldName) {
        if (value == null) {
            throw new IllegalArgumentException(fieldName + " must not be null");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\r' || c == '\n' || c == '\0') {
                throw new IllegalArgumentException(
                        fieldName + " contains a disallowed control character");
            }
        }
        return value;
    }
}
```

## Explanation

The fix validates every field that ends up embedded in a raw SMTP command or in the `DATA` block - `replyTo`, `recipient`, and `subjectLine` - at the single point where they are all serialized onto the wire, `SmtpRelayClient.sendAcknowledgement`. This is the natural place to fix it: it is the only code that ever writes SMTP protocol bytes, so validating here closes the injection regardless of which caller supplies the envelope, without having to duplicate the check at every place a `MailEnvelope` might be constructed.

The check rejects (via `IllegalArgumentException`) any value containing `\r`, `\n`, or a NUL byte rather than stripping those characters out. Stripping would silently convert an attacker-supplied value into a different, still attacker-influenced value and give a false sense of safety; rejecting makes the malformed input a hard failure that surfaces during testing and cannot be quietly bypassed by re-encoding or omitting the character elsewhere in the payload. `recipient` is included even though today's only caller passes a fixed constant (`support-queue@example.com`), since the sink has no way to know that and this keeps the guard correct if a future caller threads a variable recipient through.

To verify: a submission where `requesterEmail` is a normal address and `subject` contains no control characters behaves exactly as before - `HELO`, `MAIL FROM`, `RCPT TO`, `DATA`, and the acknowledgement body are written as a single well-formed SMTP transaction. A submission where `requesterEmail` or `subject` contains an embedded `\r\n` (for example `subject` set to `test\r\n.\r\nMAIL FROM:<attacker@evil.com>`) now throws `IllegalArgumentException` before any bytes are written to the socket, instead of silently splitting into extra SMTP commands - confirming the injection path is closed rather than merely relocated.
