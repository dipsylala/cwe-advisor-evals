## Verdict
The vulnerability is confirmed: untrusted input (folderName) is concatenated directly into an IMAP SELECT command string sent to a raw socket, enabling command injection via CRLF sequences. Line 18 is the sink where the injected command reaches the IMAP protocol interpreter.

## Source
**Input:** `folderName` from `request.getParameter("folder")` at line 13 is attacker-controlled.

**Data flow:** folderName → line 16 string concatenation → line 18 socket write (sink).

**Interpreter:** IMAP protocol parser on the remote server reading the socket output stream.

## Fix
Replace raw socket IMAP operations with a maintained IMAP client library. Jakarta Mail is the standard choice in Java. The remediated code:

```java
import java.util.Properties;
import javax.mail.Folder;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Store;
import javax.servlet.http.HttpServletRequest;

public class ImapRawSocketFolderInjection {

    public void selectFolder(HttpServletRequest request, Store imapStore) throws MessagingException {
        String folderName = request.getParameter("folder");
        
        // Validate folder name: allowlist alphanumeric, dots, hyphens, underscores.
        // Adjust the pattern to match your application's valid folder naming scheme.
        if (!folderName.matches("^[a-zA-Z0-9._-]+$")) {
            throw new IllegalArgumentException("Invalid folder name: contains invalid characters");
        }
        
        // Use the IMAP client library's structured API.
        // IMAPStore automatically handles command framing and parameter escaping.
        Folder folder = imapStore.getFolder(folderName);
        folder.open(Folder.READ_ONLY);
        // Process folder content
        folder.close(false);
    }
}
```

**Key changes:**
1. **Replace Socket with Store:** Use Jakarta Mail's `Store` API (obtained from a properly configured `Session`) instead of manually managing a `Socket`.
2. **Parameterized API:** `imapStore.getFolder(folderName)` is the structured, parameterized method. The library handles all IMAP protocol framing, escaping, and CRLF handling internally.
3. **Input validation:** Allowlist folder name characters to reject names containing CRLF, quotes, or other special characters that could manipulate the protocol.
4. **No manual command building:** Remove string concatenation of raw IMAP commands.

**Dependency:** Requires `jakarta.mail:jakarta.mail-api` and an implementation such as `org.eclipse.angus:smtp` (version 2.0.4+) or `com.sun.mail:jakarta.mail` (version 2.0.2+/1.6.8+) for full protection.

## Explanation
The original code concatenates user input directly into an IMAP command string terminated with `\r\n`. An attacker can inject a newline and carriage return (`\r\n`) followed by additional IMAP commands to manipulate folder selection, listing, or deletion.

**Attack example:**
- Input: `Inbox\r\nDELETE Trash\r\n`
- Result command: `a1 SELECT Inbox\r\nDELETE Trash\r\n\r\n`
- The IMAP server interprets this as two commands: SELECT Inbox, then DELETE Trash.

The fix uses Jakarta Mail's `Store.getFolder()` API, which:
- Accepts the folder name as a structured parameter, not a raw protocol token
- Internally handles all IMAP protocol framing and escaping
- Does not allow control characters to break out of the folder name parameter
- Follows the IMAP RFC 3501 specification for proper command construction

The allowlist validation adds defence-in-depth: even if the library did not properly escape (unlikely with a maintained library), the validation ensures only safe characters enter.

## Behaviour changes
- **Before:** Accepts any folder name, including those with embedded CRLF sequences, which can inject additional IMAP commands.
- **After:** 
  - Accepts only folder names matching the allowlist pattern (alphanumeric, dot, hyphen, underscore).
  - Rejects folder names with CRLF, quotes, or special characters.
  - All folder selection is delegated to the IMAP client library, which safely frames the command.
  - Command injection is prevented because the library constructs the command syntactically, not via string concatenation.
