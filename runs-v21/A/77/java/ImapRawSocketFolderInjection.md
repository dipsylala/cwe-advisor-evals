## Verdict

**CONFIRMED** — CWE-77 command injection in IMAP protocol handling. User-supplied mailbox name is concatenated directly into IMAP SELECT command without escaping, allowing injection of newlines and IMAP metacharacters to alter command structure and inject arbitrary commands.

## Source

Line 13 sources untrusted input from HTTP request parameter:
```
String folderName = request.getParameter("folder");
```

Line 16-18 sink writes unsanitized input into IMAP command:
```
String command = "a1 SELECT " + folderName + "\r\n";
out.write(command.getBytes("US-ASCII"));
```

An attacker can inject `\r\n` into the folder name to terminate the SELECT command and inject subsequent commands (e.g., `EXPUNGE\r\nX LOGOUT`), or inject quote characters to break out of protocol context.

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

        if (folderName == null || folderName.isEmpty()) {
            throw new IllegalArgumentException("Mailbox name cannot be null or empty");
        }

        OutputStream out = imapSocket.getOutputStream();
        // Escape and quote the mailbox name to prevent IMAP command injection
        String escapedFolder = escapeImapString(folderName);
        String command = "a1 SELECT " + escapedFolder + "\r\n";
        out.write(command.getBytes("US-ASCII"));
        out.flush();
    }

    private String escapeImapString(String input) {
        // RFC 3501: quoted-string must escape backslash and quote characters
        String escaped = input.replace("\\", "\\\\").replace("\"", "\\\"");
        return "\"" + escaped + "\"";
    }
}
```

## Explanation

The fix applies RFC 3501 IMAP protocol-compliant quoting and escaping:

1. **Null/empty check**: Reject invalid input early to fail safely.

2. **Quote and escape the mailbox name**: The `escapeImapString()` method wraps the mailbox name in double quotes and escapes internal quote and backslash characters. This treats the folder name as a literal string value within the IMAP protocol, preventing interpretation of embedded control characters or protocol metacharacters.

   - Backslashes: `\` → `\\` (prevent escape-sequence injection)
   - Quotes: `"` → `\"` (prevent string delimiter injection)
   - Wrapped in `"..."` to form a valid IMAP quoted-string

3. **Result**: Any input, including inputs containing `\r\n`, quotes, or other IMAP metacharacters, is now treated as literal mailbox name data rather than protocol commands. For example:
   - Input: `Test\r\nX LOGOUT`
   - Escaped: `"Test\r\nX LOGOUT"` (literal newline characters inside quoted string, not protocol delimiters)
   - Sent command: `a1 SELECT "Test\r\nX LOGOUT"\r\n` (safe; the server interprets this as a single SELECT for a folder with that literal name)

This approach handles any valid IMAP mailbox name (including those with spaces, special characters, or international characters encoded in UTF-7 for IMAP) while preventing command injection.
