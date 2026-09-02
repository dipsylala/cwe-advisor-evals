## Verdict

Confirmed. `folderName` is attacker-controlled (`request.getParameter("folder")`) and is concatenated directly into a raw IMAP command line that is written to the socket without any quoting, escaping, or CRLF filtering. A value such as `INBOX"\r\na2 LOGOUT\r\na3 SELECT "x` (or one containing an unescaped `"` or `\`) breaks out of the intended `SELECT` argument, terminates the current IMAP command early, and injects one or more additional IMAP commands that the backend server will execute in the authenticated session (e.g. issuing arbitrary mailbox operations, exfiltrating other folders, or manipulating session state) - a classic special-element/protocol command injection.

## Source

`folderName` at `ImapRawSocketFolderInjection.java:13` — `String folderName = request.getParameter("folder");`. This is unvalidated, attacker-controlled HTTP request data that flows unmodified into the command string built at line 16 and written to the IMAP socket at line 18 (`out.write(command.getBytes("US-ASCII"))`).

## Fix

```java
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;

/**
 * Handles the "jump to folder" action in a lightweight webmail client that
 * talks to the backend IMAP server directly over a raw socket.
 */
public class ImapRawSocketFolderInjection {

    public void selectFolder(HttpServletRequest request, Socket imapSocket) throws Exception {
        // Mailbox name chosen by the signed-in user from the folder tree UI.
        String folderName = request.getParameter("folder");
        if (folderName == null) {
            throw new IllegalArgumentException("Missing folder parameter");
        }

        // Encode as an IMAP literal (RFC 3501 sec. 4.3) instead of a quoted
        // string. The server reads exactly the declared number of octets as
        // the argument, so embedded quotes, backslashes, or CRLF sequences
        // in folderName cannot terminate the command or inject a new one.
        byte[] mailboxBytes = folderName.getBytes(StandardCharsets.UTF_8);

        OutputStream out = imapSocket.getOutputStream();
        String commandHeader = "a1 SELECT {" + mailboxBytes.length + "}\r\n";
        out.write(commandHeader.getBytes("US-ASCII"));
        out.flush();

        // Per RFC 3501, the server replies "+ Ready for literal data" before
        // the literal octets are sent; a production client must read that
        // continuation response here before writing mailboxBytes. Omitted
        // in this snippet for brevity - see the general remediation notes.
        out.write(mailboxBytes);
        out.write("\r\n".getBytes("US-ASCII"));
        out.flush();
    }
}
```

If a synchronous continuation round-trip is impractical for this client, use a non-synchronizing literal (`{<n>+}`) instead, which the server accepts without a continuation reply, while still avoiding any quoting or escaping of the mailbox name. Either literal form is preferable to hand-rolled escaping of `"` and `\` in a quoted string, since it also structurally prevents CR/LF from being interpreted as a command terminator - the server reads the declared byte count regardless of its content. As a defense-in-depth measure, also reject `folderName` values containing NUL, CR, or LF before use, and prefer an existing, actively maintained IMAP client library (e.g. Jakarta Mail) over hand-built protocol commands where the application architecture allows it, since such libraries implement RFC 3501 framing (including literals and quoting) correctly.

## Explanation

Raw IMAP is a line-oriented text protocol where the server determines the end of a command argument either by a closing quote (for a quoted string) or CRLF (for an unquoted/atom-like token) or by a declared byte count (for a literal). The original code treats `folderName` as an unquoted, unescaped token concatenated into the command line, so any character with syntactic meaning to the IMAP parser - a double quote, backslash, or especially CRLF - is interpreted by the server rather than treated as literal mailbox-name data. An attacker who controls the `folder` request parameter can therefore terminate the `SELECT` command early and smuggle one or more additional IMAP commands into the same write, which the server will execute with the privileges of the already-authenticated session on that socket.

Switching to the IMAP literal syntax removes the injection surface at its root: instead of asking the server to parse where the argument ends, the client declares exactly how many bytes follow, and the server consumes precisely that many octets as opaque data regardless of their content. This is the same "length-prefixed, not delimiter-terminated" principle used to close injection in other text protocols (e.g. HTTP chunked bodies, SMTP `BDAT`) and it means no escaping function has to be written or kept in sync with the server's actual quoting grammar. The literal must still be paired with the protocol's expected round-trip (waiting for the server's `+` continuation reply before sending a synchronizing literal, or using a non-synchronizing `{n+}` literal if the server supports RFC 7888) so the fix is protocol-correct as well as safe.
