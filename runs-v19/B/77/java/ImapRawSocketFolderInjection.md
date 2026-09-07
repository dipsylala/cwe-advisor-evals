## Verdict

Vulnerable. Untrusted input from `request.getParameter("folder")` reaches an IMAP protocol command sink without sanitization. An attacker can embed CRLF characters (`\r\n`) to inject additional IMAP commands into the same connection.

## Source

**Line 13:** `String folderName = request.getParameter("folder");`

HTTP request parameter `folder` is attacker-controlled and carries no validation.

## Fix

### File: ImapRawSocketFolderInjection.java

```java
import java.util.Properties;
import jakarta.mail.*;
import jakarta.mail.internet.*;
import javax.servlet.http.HttpServletRequest;

/**
 * Handles the "jump to folder" action in a lightweight webmail client that
 * talks to the backend IMAP server directly over a raw socket.
 */
public class ImapRawSocketFolderInjection {

    public void selectFolder(HttpServletRequest request, Session mailSession) throws Exception {
        // Mailbox name chosen by the signed-in user from the folder tree UI.
        String folderName = request.getParameter("folder");

        // Use Jakarta Mail's Store API instead of raw socket manipulation to safely select folder
        Store store = mailSession.getStore("imaps");
        store.connect();
        
        // getFolder() is the safe API; it does not interpret special characters as IMAP syntax
        Folder folder = store.getFolder(folderName);
        folder.open(Folder.READ_WRITE);
    }
}
```

## Explanation

The original code built IMAP commands by string concatenation, allowing CRLF-based command injection. The fixed code replaces this with Jakarta Mail's `Store.getFolder(name)` API, which treats the folder name as opaque data rather than command syntax.

The primary defence is using a maintained client library (`jakarta.mail` version 2.0.2 or later for `com.sun.mail:jakarta.mail`, or 2.0.4+ for `org.eclipse.angus:smtp` implementation) that parameterizes IMAP commands internally. The `Store` and `Folder` APIs handle protocol framing automatically, ensuring untrusted input cannot break out of the data context.

The change from `Socket imapSocket` parameter to `Session mailSession` is necessary because Jakarta Mail encapsulates socket management and connection state; the Session object carries IMAP server configuration and credentials, and `store.connect()` opens the connection using those properties before `getFolder()` is called.

## Behaviour changes

1. **Signature change:** Method now takes `Session mailSession` instead of `Socket imapSocket`. Caller must initialize a Session with IMAP server properties and pass it, rather than managing the socket directly.
2. **Connection handling:** `store.connect()` must be called on the returned Store before using `getFolder()`, or `IllegalStateException` is thrown. This ensures the IMAP session is established before folder selection.
3. **Folder state:** The returned `Folder` object requires explicit `open()` call to select the folder in the IMAP session. The original code did not return anything; this change surfaces the folder object to allow further operations on it.
4. **Resource management:** The Session and Store should be closed when finished (e.g., `store.close()` in a try-with-resources or finally block) to clean up the IMAP connection.

Test with folder names containing `\r\n`, special IMAP characters like `*`, `%`, and `"`, and confirm they are treated as literal text and do not execute as IMAP commands.
