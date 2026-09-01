## Verdict
Command injection vulnerability confirmed. The `folderName` parameter is obtained from untrusted user input and concatenated directly into an IMAP protocol command without validation or escaping, allowing an attacker to inject arbitrary IMAP commands.

## Source
Line 13: `String folderName = request.getParameter("folder");`

The user-controlled `folderName` is obtained from an HTTP request parameter without any validation.

## Fix
```java
public void selectFolder(HttpServletRequest request, Socket imapSocket) throws Exception {
    String folderName = request.getParameter("folder");
    
    // Validate that folder name contains only safe characters (alphanumeric, underscore, hyphen, dot)
    if (folderName == null || !folderName.matches("^[a-zA-Z0-9_.\\-]+$")) {
        throw new IllegalArgumentException("Invalid folder name");
    }
    
    OutputStream out = imapSocket.getOutputStream();
    String command = "a1 SELECT " + folderName + "\r\n";
    out.write(command.getBytes("US-ASCII"));
    out.flush();
}
```

Alternatively, if folder names may contain special characters, properly quote them according to IMAP RFC 3501:

```java
public void selectFolder(HttpServletRequest request, Socket imapSocket) throws Exception {
    String folderName = request.getParameter("folder");
    
    if (folderName == null || folderName.isEmpty()) {
        throw new IllegalArgumentException("Folder name cannot be empty");
    }
    
    // Escape backslashes and quotes, then wrap in quotes per IMAP RFC 3501
    String escapedName = folderName.replace("\\", "\\\\").replace("\"", "\\\"");
    String quotedName = "\"" + escapedName + "\"";
    
    OutputStream out = imapSocket.getOutputStream();
    String command = "a1 SELECT " + quotedName + "\r\n";
    out.write(command.getBytes("US-ASCII"));
    out.flush();
}
```

## Explanation
The vulnerability exists because `folderName` is directly interpolated into the IMAP SELECT command without validation. An attacker can inject IMAP protocol commands by including special characters like newlines or quotes in the folder parameter (e.g., `folder=INBOX"\r\na1 DELETE INBOX\r\n`), causing arbitrary commands to be executed on the IMAP server.

The fix validates the input by either:
1. **Allowlist approach**: Restricting folder names to known-safe characters (alphanumeric, underscore, hyphen, dot) that cannot be used for command injection.
2. **IMAP quoting approach**: Following RFC 3501 by escaping special characters and quoting the mailbox name, which prevents the IMAP parser from interpreting injected content as commands.

The allowlist approach is simpler and more secure if folder names don't need to contain special characters. The quoting approach provides more flexibility while maintaining security by properly escaping the input according to IMAP protocol specifications.
