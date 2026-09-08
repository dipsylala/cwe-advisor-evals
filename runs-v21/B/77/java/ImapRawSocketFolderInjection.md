## Verdict

Command injection via IMAP protocol: untrusted folder name is concatenated into a raw IMAP command string and written to a socket, allowing an attacker to inject additional IMAP commands by embedding CRLF sequences.

## Source

`HttpServletRequest.getParameter("folder")` (line 13) - user-controlled HTTP request parameter, untrusted.

## Fix

Validate the folder name to reject CR and LF characters before it reaches the socket write operation. This prevents the attacker from injecting CRLF sequences that would terminate the SELECT command and inject additional IMAP commands.

### File: ImapRawSocketFolderInjection.java

```java
import java.io.OutputStream;
import java.net.Socket;
import javax.servlet.http.HttpServletRequest;

/**
 * Handles the "jump to folder" action in a lightweight webmail client that
 * talks to the backend IMAP server directly over a raw socket.
 */
public class ImapRawSocketFolderInjection {

    public void selectFolder(HttpServletRequest request, Socket imapSocket) throws Exception {
        // Mailbox name chosen by the signed-in user from the folder tree UI.
        String folderName = request.getParameter("folder");

        // CWE-77: Reject folder names containing line breaks to prevent IMAP command injection
        if (folderName.contains("\r") || folderName.contains("\n")) {
            throw new IllegalArgumentException("Invalid folder name: contains line breaks");
        }

        OutputStream out = imapSocket.getOutputStream();
        String command = "a1 SELECT " + folderName + "\r\n";
        out.write(command.getBytes("US-ASCII"));
        out.flush();
    }
}
```

## Explanation

The fix adds validation immediately after the untrusted input is received to reject any folder name containing CR (carriage return, `\r`) or LF (line feed, `\n`) characters. This prevents an attacker from embedding CRLF sequences that would break out of the current IMAP command and inject additional commands into the protocol stream. An `IllegalArgumentException` is thrown when validation fails, causing the request to be rejected before the malicious input reaches the socket. The validated folder name is then used as before, but is now guaranteed to be safe from CRLF injection.

This approach follows the guidance's principle: "rejecting CR and LF in the filename before the call is what closes the vector." It is defence-in-depth for this raw-socket implementation. The primary defence (recommended in the guidance) is to migrate to Jakarta Mail's `Store`/`Folder` API, which handles the protocol safely, but that would require broader refactoring of the calling code and method signatures.

## Behaviour changes

- Invalid folder names (those containing CR or LF) are now rejected with an `IllegalArgumentException` instead of being silently forwarded to the IMAP server.
- Legitimate folder names without line breaks are unaffected and work exactly as before.
- The exception is thrown at the application level before the command reaches the network, allowing for logging and user-friendly error handling at the call site.
