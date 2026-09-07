## Verdict
VULNERABLE - CWE-77 command injection in IMAP protocol

## Source
Line 16: User-supplied `folderName` from HTTP request parameter is concatenated directly into IMAP command without escaping.
Line 18: The unsanitized command is sent to the IMAP server, where special characters can alter the protocol structure.

An attacker controlling the `folder` parameter can inject IMAP protocol commands. For example, submitting `" LOGOUT "` as the folder name would result in the command `a1 SELECT " LOGOUT "\r\n`, causing unintended protocol flow.

## Fix

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

        // Validate and quote the mailbox name to prevent IMAP command injection.
        String quotedMailbox = quoteImapMailbox(folderName);
        
        OutputStream out = imapSocket.getOutputStream();
        String command = "a1 SELECT " + quotedMailbox + "\r\n";
        out.write(command.getBytes("US-ASCII"));
        out.flush();
    }

    /**
     * Quotes an IMAP mailbox name to prevent command injection.
     * In IMAP, mailbox names containing special characters must be quoted.
     * Within quotes, backslash and double-quote characters are escaped with a backslash.
     */
    private String quoteImapMailbox(String mailbox) {
        if (mailbox == null) {
            throw new IllegalArgumentException("Mailbox name cannot be null");
        }
        
        // Escape backslashes first, then double-quotes, then wrap in quotes.
        // This ensures proper IMAP protocol compliance and prevents injection.
        String escaped = mailbox.replace("\\", "\\\\").replace("\"", "\\\"");
        return "\"" + escaped + "\"";
    }
}
```

## Explanation
The fix introduces a `quoteImapMailbox()` helper method that properly escapes user-supplied mailbox names according to IMAP protocol rules. When a mailbox name is wrapped in double quotes, any backslashes and quotes within the name must be escaped with a preceding backslash. This ensures that special characters in the folder name cannot alter the IMAP command structure.

The escaping order is critical: backslashes must be escaped first (`\\` becomes `\\\\`), then double-quotes (`"` becomes `\"`), and finally the result is wrapped in quotes. This prevents the attacker-controlled input from breaking out of the quoted string or injecting additional commands. The IMAP server interprets the entire quoted string as a single mailbox name, preventing command injection regardless of the characters submitted.
