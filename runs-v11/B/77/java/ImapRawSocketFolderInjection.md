## Verdict

exploitable

## Source

`request.getParameter("folder")` receives untrusted user input at line 13.

## Fix

**Vulnerable Code (line 11-20):**

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

**Fixed Code:**

```java
public void selectFolder(HttpServletRequest request, Socket imapSocket) throws Exception {
    // Mailbox name chosen by the signed-in user from the folder tree UI.
    String folderName = request.getParameter("folder");

    // Validate folder name does not contain IMAP protocol injection characters (CR/LF)
    if (folderName == null || folderName.contains("\r") || folderName.contains("\n")) {
        throw new IllegalArgumentException("Invalid folder name: contains control characters");
    }

    OutputStream out = imapSocket.getOutputStream();
    String command = "a1 SELECT " + folderName + "\r\n";
    out.write(command.getBytes("US-ASCII"));
    out.flush();
}
```

**Library Recommendation:**

The ideal long-term fix is to replace the raw IMAP socket implementation with a maintained client library. Use `jakarta.mail` (formerly `javax.mail`) which provides `IMAPStore` and `IMAPFolder` APIs that handle protocol command construction safely. If using the SMTP or IMAP transport, require minimum version `com.sun.mail:jakarta.mail` 2.0.2, `1.6.8`, or `org.eclipse.angus:smtp` 2.0.4 for CR/LF command injection protection.

## Explanation

The vulnerability exists because `folderName` from untrusted user input is concatenated directly into an IMAP protocol command string without validation. IMAP commands are terminated with CRLF (`\r\n`), so an attacker can inject additional IMAP commands by embedding `\r\n` in the folder name (e.g., `INBOX\r\nLOGOUT\r\n` would terminate the SELECT command and inject a LOGOUT, disconnecting the session). The fix validates that the folder name does not contain CR or LF characters before concatenating it into the command. This prevents protocol-level injection by rejecting any input containing the IMAP command delimiter. The validation follows the guidance principle: "Allowlist the expected format rather than denylisting metacharacters" by explicitly rejecting the dangerous control characters. For maximum security, migrate to a maintained IMAP client library that handles command construction internally.

## Behaviour changes

The fix adds validation that throws `IllegalArgumentException` if the folder parameter is null or contains CR/LF characters. Legitimate folder names (those without control characters) are unaffected. The error is raised before the IMAP command is sent, preventing any injection attempt from reaching the server. This is the only behavioral change beyond closing the injection: the method now rejects invalid input rather than silently passing it through.
