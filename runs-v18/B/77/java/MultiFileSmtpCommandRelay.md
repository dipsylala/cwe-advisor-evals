## Verdict

Exploitable. Untrusted email addresses reach SMTP protocol commands built via string concatenation, allowing injection of additional RCPT TO and other commands via embedded CRLF sequences.

## Source

`TicketController.handleSubmit()` receives `requesterEmail` from HTTP request parameter (`request.getParameter("requesterEmail")`), which flows untrusted through `TicketSubmission.getRequesterEmail()` into `MailEnvelope.replyTo`, and reaches the SMTP sink in `SmtpRelayClient.sendAcknowledgement()` at line 28.

## Fix

### File: SmtpRelayClient.java

```java
package com.example.support;

import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import java.util.Properties;

/**
 * SMTP client used to relay ticket acknowledgements through the internal mail
 * gateway using the Jakarta Mail library, which safely handles protocol command
 * construction and validates addresses to prevent command injection.
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
            // Validate addresses with strict=true to reject CR/LF in local parts,
            // preventing SMTP command injection (CWE-77)
            InternetAddress from = new InternetAddress(envelope.getReplyTo(), true);
            InternetAddress to = new InternetAddress(envelope.getRecipient(), true);

            // Strip line breaks from subject to prevent header injection
            String subject = stripLineBreaks(envelope.getSubjectLine());

            // Configure session to use the relay host
            Properties props = new Properties();
            props.put("mail.smtp.host", relayHost);
            props.put("mail.smtp.port", String.valueOf(relayPort));

            Session session = Session.getInstance(props);

            // Use MimeMessage to construct the message; Transport.send() will safely
            // build the SMTP protocol commands instead of concatenating strings
            MimeMessage message = new MimeMessage(session);
            message.setFrom(from);
            message.setRecipient(Message.RecipientType.TO, to);
            message.setSubject(subject);
            message.setText("Ticket acknowledgement");

            // Send the message using SMTP protocol
            Transport.send(message);
        } catch (AddressException e) {
            throw new RuntimeException("Invalid mail address in ticket acknowledgement", e);
        } catch (MessagingException e) {
            throw new RuntimeException("Failed to relay ticket acknowledgement", e);
        }
    }

    /**
     * Remove CR and LF characters from a string to prevent injection into
     * email headers, which are CRLF-terminated.
     */
    private String stripLineBreaks(String value) {
        if (value == null) {
            return null;
        }
        return value.replace("\r", "").replace("\n", "");
    }
}
```

## Explanation

The original code built SMTP protocol commands by concatenating untrusted email addresses and subject lines directly into strings sent over a socket. An attacker could submit an email address containing `\r\n` followed by additional SMTP commands to redirect mail to arbitrary recipients.

The fix replaces the raw socket-based SMTP command construction with Jakarta Mail's `Session`/`Transport`/`MimeMessage` API. Jakarta Mail constructs SMTP commands safely and includes validation of email addresses via `InternetAddress(string, true)`, which rejects CR/LF sequences in the local part of the address. Additionally, the fix strips CR/LF from subject lines to prevent header injection. Transport.send() then builds the complete protocol dialogue safely, preventing the injection sink.

The fix requires Jakarta Mail version 2.0.2 or later (or 1.6.8 for the 1.6 line), which includes a CR/LF scan in `SMTPTransport` for CVE-2025-7962. Earlier versions forward CR/LF that address parsing allows through (in particular, quoted strings with CRLF-space). Verify the resolved version is 2.0.2+ or 1.6.8+ via dependency checker before merging.

## Behaviour changes

1. **Dependency addition**: Now requires Jakarta Mail library as a compile-time dependency (was previously using only standard Java libraries)

2. **Address validation**: Untrusted addresses are now validated with `InternetAddress(string, true)`, which throws `AddressException` on invalid syntax including embedded CR/LF. This may reject edge-case but technically invalid email addresses that the original socket-based code accepted without validation.

3. **Subject line sanitization**: CR and LF characters are stripped from the subject line before sending, preventing header injection attacks. A subject containing literal `\r` or `\n` will have these characters removed rather than transmitted to the server.

4. **Protocol command construction**: SMTP commands are now built by Jakarta Mail's Transport class rather than hand-concatenated, ensuring proper escaping and encoding of all protocol elements.

5. **Exception handling**: Now catches both `AddressException` (from address validation) and `MessagingException` (from SMTP operations) separately, both wrapped in `RuntimeException`. The original code only caught `IOException`.

6. **Message body**: The original code transmitted the subject line as both a header and the message body in an unconventional SMTP format. The fixed code uses `MimeMessage.setText()` which constructs a proper MIME message body, and `setSubject()` which properly encodes the subject as a MIME header.

All behaviour changes are necessary to fix the command injection vulnerability or represent legitimate improvements in protocol handling. The API contract remains the same: accept a `MailEnvelope` with untrusted email addresses and subject, and send an acknowledgement.
