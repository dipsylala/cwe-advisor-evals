## Verdict

Real vulnerability confirmed. The untrusted folder name from the HTTP request parameter is concatenated directly into an IMAP command string and sent over a socket. An attacker can inject additional IMAP commands by including CRLF sequences in the folder name (e.g., `inbox\r\nDELETE INBOX\r\n`), causing the server to execute unintended operations.

## Source

- **Source (untrusted input):** Line 13: `String folderName = request.getParameter("folder");`
- **Data flow:** The folder name flows directly into line 16's command string concatenation
- **Sink (vulnerable operation):** Line 18: `out.write(command.getBytes("US-ASCII"));` sends the unsanitized command to the IMAP server

The vulnerability occurs because user-controlled input is concatenated into a protocol command string without any check for or neutralization of CRLF characters that could terminate the current command and inject additional commands.

## Fix

### File: ImapRawSocketFolderInjection.java

```java
import jakarta.mail.Folder;
import jakarta.mail.Session;
import jakarta.mail.Store;
import javax.servlet.http.HttpServletRequest;
import java.util.Properties;

/**
 * Handles the "jump to folder" action in a lightweight webmail client that
 * talks to the backend IMAP server using Jakarta Mail library.
 */
public class ImapRawSocketFolderInjection {

    public void selectFolder(HttpServletRequest request, Properties mailProps) throws Exception {
        // Mailbox name chosen by the signed-in user from the folder tree UI.
        String folderName = request.getParameter("folder");
        
        // Validate folder name - reject values containing line breaks which could inject IMAP commands
        if (folderName == null || folderName.contains("\r") || folderName.contains("\n")) {
            throw new IllegalArgumentException("Invalid folder name");
        }
        
        // Use Jakarta Mail to safely interact with IMAP instead of building raw protocol commands
        Session session = Session.getInstance(mailProps);
        Store store = session.getStore("imap");
        store.connect();
        
        Folder folder = store.getFolder(folderName);
        folder.open(Folder.READ_ONLY);
    }
}
```

## Explanation

The original code built IMAP protocol commands by concatenating untrusted user input directly into a command string terminated with `\r\n`, then sending it over a raw socket. This pattern allows CRLF injection: an attacker-controlled folder name containing `\r\n` can break out of the SELECT command and inject arbitrary IMAP commands into the same connection.

The fix replaces raw socket-based command construction with Jakarta Mail's Session/Store/Folder API, which handles the IMAP protocol safely through a documented interface. The library manages all protocol details internally and prevents injection by design—it does not build command strings from untrusted input.

Defense-in-depth validation rejects folder names containing CR or LF characters, catching any values that might bypass the library's internal handling. The method signature changes from accepting a raw Socket to accepting Properties; this is a necessary change because Jakarta Mail manages the IMAP connection internally rather than accepting a pre-opened socket. In a real application, the Properties object would be obtained from application configuration or a mail service component.

## Behaviour changes

- **Injection prevention:** Folder names can no longer inject IMAP commands; the library handles the protocol safely
- **Method signature:** Changes from `selectFolder(HttpServletRequest, Socket)` to `selectFolder(HttpServletRequest, Properties)` to support Jakarta Mail's API
- **Connection management:** The IMAP connection is now established through Jakarta Mail's Session/Store rather than by passing a pre-opened socket
- **Input validation:** Defense-in-depth check rejects any folder name containing CR or LF characters
- **Dependency:** The application now requires Jakarta Mail (or JavaMail 1.6.x for legacy environments) as a dependency
- **Exception handling:** `AddressException` or generic `Exception` from Jakarta Mail replaces any socket I/O exceptions; the caller's error handling logic should remain functional
