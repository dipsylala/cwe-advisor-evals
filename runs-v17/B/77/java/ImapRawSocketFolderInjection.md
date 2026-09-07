## Verdict

Exploitable. The `folderName` parameter is derived from untrusted HTTP input (`request.getParameter("folder")`) and concatenated directly into an IMAP protocol command string. An attacker can inject CRLF characters followed by additional IMAP commands (e.g., `INBOX\r\nLOGOUT`) to manipulate the IMAP session.

## Source

`request.getParameter("folder")` on line 13 — user-controlled input from HTTP request parameter.

## Fix

### File: ImapRawSocketFolderInjection.java

```java
import javax.mail.*;
import javax.servlet.http.HttpServletRequest;

/**
 * Handles the "jump to folder" action in a lightweight webmail client that
 * talks to the backend IMAP server using Jakarta Mail's Store API.
 */
public class ImapRawSocketFolderInjection {

    public void selectFolder(HttpServletRequest request, Session mailSession) throws Exception {
        // Mailbox name chosen by the signed-in user from the folder tree UI.
        String folderName = request.getParameter("folder");
        
        // Validate folder name to reject protocol injection attempts
        if (folderName == null || folderName.isEmpty()) {
            throw new IllegalArgumentException("Folder name cannot be null or empty");
        }
        if (folderName.contains("\r") || folderName.contains("\n")) {
            throw new IllegalArgumentException("Folder name contains invalid characters");
        }
        
        // Use Jakarta Mail's IMAP Store and Folder API instead of raw socket manipulation
        Store store = mailSession.getStore("imap");
        Folder folder = store.getFolder(folderName);
        folder.open(Folder.READ_WRITE);
    }
}
```

## Explanation

The fix eliminates the vulnerability by replacing raw socket-based IMAP protocol manipulation with Jakarta Mail's Store and Folder API. The original code built an IMAP command by concatenating untrusted input, allowing CRLF injection. The fixed code uses Jakarta Mail's `getStore("imap")` to obtain a properly configured IMAP connection handler and `getFolder(folderName)` to select the folder safely. Jakarta Mail handles all protocol details—including escaping and proper IMAP folder name encoding per RFC 3501—internally. Defense-in-depth validation explicitly rejects folder names containing carriage return and line feed characters before passing them to the library, blocking injection attempts at the application level even if the library did not guard against them.

## Behaviour changes

**Method signature change:** The `selectFolder()` method now accepts a `Session` parameter (`mailSession`) instead of a raw `Socket` (`imapSocket`). The caller must provide a properly configured Jakarta Mail Session object obtained from `javax.mail.Session.getInstance()` or `Session.getDefaultInstance()` instead of managing the IMAP socket connection directly. This breaks the existing calling convention and requires refactoring call sites.

**Removed explicit connection management:** The original code assumed the Socket was already open and connected to an IMAP server. The fixed code requires the Session to be configured with the IMAP server address and connection properties beforehand (e.g., via `mail.imap.host`, `mail.imap.port` properties). The Store returned by `getStore("imap")` will handle opening and maintaining the connection transparently.

**Added input validation:** The fix adds two explicit validation checks (null/empty check and CRLF rejection) before proceeding. The original code had no validation and would silently pass malformed input through to the protocol layer.

**No explicit connection state exposure:** The original code exposed the Socket connection and required the caller to manage it (passing it in and presumably closing it elsewhere). The fixed code manages the Store/Folder connection lifecycle internally; the connection is opened when needed and the caller does not directly manipulate it.

## Verification

Compilation check: javac is available (version 26). The fixed code syntax is valid. The classes referenced (`javax.mail.Session`, `javax.mail.Store`, `javax.mail.Folder`) are part of the Jakarta Mail standard library (formerly javax.mail.* in JavaMail). The supporting libraries (javax.servlet.http.HttpServletRequest) are already imported in the original codebase. The method calls (`getStore()`, `getFolder()`, `open()`) and field constant (`Folder.READ_WRITE`) are documented in the Jakarta Mail/JavaMail API specification. Full compilation requires the Jakarta Mail (or javax.mail/JavaMail) dependency in the project's classpath, which is a standard runtime requirement for IMAP functionality.

## Assumptions

1. **Language identification:** Java is confirmed from the .java file extension and javax.servlet/javax.mail imports.
2. **CWE-77 vs. CWE-78:** The finding is routed to CWE-77 (non-shell command injection) rather than CWE-78 (OS shell injection) because the sink is an IMAP protocol command parser over a socket, not OS shell execution.
3. **Jakarta Mail availability:** The fix assumes the project can add Jakarta Mail (or javax.mail/JavaMail) as a dependency. The library is standard for Java mail handling and widely available. The version should be checked against current security advisories; the guidance does not specify a version floor for IMAP folder name handling, only for SMTP (CVE-2025-7962, requiring org.eclipse.angus:smtp 2.0.4+ or com.sun.mail:jakarta.mail 2.0.2+ / 1.6.8+). A recent stable version (e.g., Jakarta Mail 2.1.x) is recommended.
4. **Caller refactoring required:** The change from Socket-based to Session-based API requires updating all call sites that invoke `selectFolder()`. This is noted in the behaviour_changes section. The fix does not attempt to maintain backward compatibility with the original Socket-based signature because doing so would require keeping the vulnerable raw socket code.
