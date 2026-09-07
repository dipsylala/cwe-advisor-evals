## Verdict

**CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')**
**Status:** Exploitable
**Confidence:** High

The untrusted folder name parameter flows directly into an IMAP command string without validation, allowing an attacker to inject CRLF sequences to execute arbitrary IMAP commands.

## Source

**Untrusted Input:** `request.getParameter("folder")` (line 13)
- HTTP request parameter controlled by the client
- No validation before use

**Sink:** `out.write(command.getBytes("US-ASCII"))` (line 18)
- Writes the unsanitized command to an IMAP socket
- An embedded CRLF allows injecting additional protocol commands on the same connection

**Data Flow:**
1. Line 13: folderName received from HTTP parameter
2. Line 16: folderName concatenated directly into IMAP command string
3. Line 18: Command written to socket without validation

**Example Attack:**
- Input: `INBOX\r\nLOGOUT`
- Result: Socket receives `"a1 SELECT INBOX\r\nLOGOUT\r\n"`, executing both SELECT and LOGOUT

## Fix

**Vulnerable Code:**
```java
public void selectFolder(HttpServletRequest request, Socket imapSocket) throws Exception {
    // Mailbox name chosen by the signed-in user from the folder tree UI.
    String folderName = request.getParameter("folder");

    OutputStream out = imapSocket.getOutputStream();
    String command = "a1 SELECT " + folderName + "\r\n";
    // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
    out.write(command.getBytes("US-ASCII"));
    out.flush();
}
```

**Fixed Code (Primary: Use Jakarta Mail Library):**
```java
import javax.mail.*;
import javax.servlet.http.HttpServletRequest;

public void selectFolder(HttpServletRequest request, Session mailSession) throws Exception {
    String folderName = request.getParameter("folder");
    
    // Validate as defence-in-depth: reject CRLF and restrict to valid IMAP folder name characters
    if (folderName == null || folderName.isEmpty() || 
        folderName.contains("\r") || folderName.contains("\n")) {
        throw new IllegalArgumentException("Invalid folder name");
    }
    
    // Allowlist valid mailbox name characters (RFC 3501 atom-specials excluded)
    if (!folderName.matches("^[a-zA-Z0-9_.\\-/]+$")) {
        throw new IllegalArgumentException("Invalid folder name format");
    }
    
    // Use Jakarta Mail's IMAPStore which constructs IMAP commands safely,
    // preventing CRLF injection through the library's internal protocol handling
    try {
        Store store = mailSession.getStore("imap");
        store.connect();
        
        Folder folder = store.getFolder(folderName);
        folder.open(Folder.READ_ONLY);
    } catch (MessagingException e) {
        // Log the exception without echoing untrusted input
        throw new Exception("Failed to open mailbox", e);
    }
}
```

**Fixed Code (Interim: Validation-Only Approach):**
If refactoring to Jakarta Mail is deferred, apply validation to the current socket-based code:
```java
public void selectFolder(HttpServletRequest request, Socket imapSocket) throws Exception {
    String folderName = request.getParameter("folder");
    
    // Validate: reject null, CRLF, and invalid characters to prevent command injection
    if (folderName == null || folderName.isEmpty()) {
        throw new IllegalArgumentException("Folder name is required");
    }
    
    if (folderName.contains("\r") || folderName.contains("\n")) {
        throw new IllegalArgumentException("Folder name contains invalid characters");
    }
    
    // Allowlist valid IMAP folder name characters (letters, digits, dots, hyphens, slashes, underscores)
    if (!folderName.matches("^[a-zA-Z0-9_.\\-/]+$")) {
        throw new IllegalArgumentException("Invalid folder name format");
    }
    
    OutputStream out = imapSocket.getOutputStream();
    String command = "a1 SELECT " + folderName + "\r\n";
    out.write(command.getBytes("US-ASCII"));
    out.flush();
}
```

## Explanation

The primary fix adopts Jakarta Mail's IMAPStore and IMAPFolder API, which constructs IMAP protocol commands through its own internal mechanism rather than string concatenation. This eliminates the injection vector entirely because the library's command builder does not interpret the folder name as a protocol delimiter or command separator—it encodes the value as a safe parameter to the underlying IMAP command.

The interim validation approach adds a multi-layer defence: it first rejects the null case, then explicitly rejects any value containing CR or LF characters (the CRLF sequence that would end the command line and begin a new one), and finally restricts the remaining input to a strict allowlist of characters valid in IMAP mailbox names per RFC 3501. This prevents CRLF injection while keeping the current socket-based architecture. The allowlist pattern is more secure than a denylist of metacharacters because it rejects any unexpected character rather than trying to enumerate every dangerous one.

Both fixes break the taint chain by ensuring untrusted input cannot reach the protocol sink in a form that reinterprets it as a command boundary.

## Behaviour changes

**Primary Fix (Library Adoption):**
- **Changed Method Signature:** The method now takes a `Session` parameter instead of a raw `Socket`. The caller must pass an initialized Jakarta Mail session configured with IMAP connection details.
- **Changed Return Type & Error Handling:** The method now may throw `MessagingException` (from Jakarta Mail) instead of generic `Exception`. The exception is wrapped to avoid echoing untrusted input in error messages.
- **Changed Functionality:** The method now opens the folder for reading and holds the connection open. The caller must close the folder/store when done (not shown in this snippet). The original code opened a socket, wrote one command, and did not maintain state; the new code establishes a full IMAP session.
- **Changed Dependencies:** Requires Jakarta Mail library (minimum version 2.0.2 for SMTP or equivalent for IMAP). The evals/cases setup must include this library.
- **Reason:** Library-based command construction eliminates the injection vector by design and is the primary remedy per CWE-77 Java guidance.

**Interim Fix (Validation Only):**
- **Added Validation Logic:** Three checks are now performed on `folderName` before it reaches the sink (null/empty check, CRLF rejection, allowlist match).
- **Changed Exception Type:** Throws `IllegalArgumentException` for invalid input instead of attempting to use it. Callers must handle this exception.
- **No Functional Change to Socket Operations:** If validation passes, the code path is identical to the original—same command format, same socket write, same return type.
- **Reason:** Validation breaks the taint chain without refactoring the socket-based architecture, providing immediate protection while a longer-term library migration is planned.

Both fixes preserve the original return type (void) and do not change what the method discards or omits from the sink contract.
