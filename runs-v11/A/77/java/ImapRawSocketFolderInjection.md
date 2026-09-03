## Verdict

The code is vulnerable to command injection via the IMAP protocol. User-supplied input from `request.getParameter("folder")` is concatenated directly into an IMAP command string without validation or escaping, allowing an attacker to inject arbitrary IMAP protocol commands.

## Source

```java
public void selectFolder(HttpServletRequest request, Socket imapSocket) throws Exception {
    String folderName = request.getParameter("folder");
    OutputStream out = imapSocket.getOutputStream();
    String command = "a1 SELECT " + folderName + "\r\n";
    out.write(command.getBytes("US-ASCII"));
    out.flush();
}
```

The vulnerability exists at line 18 where the unsanitized `folderName` is sent to the IMAP server.

## Fix

```java
public void selectFolder(HttpServletRequest request, Socket imapSocket) throws Exception {
    String folderName = request.getParameter("folder");
    
    // Validate folder name: restrict to safe characters
    // IMAP allows alphanumerics, periods, hyphens, underscores, and spaces in mailbox names
    if (folderName == null || folderName.isEmpty() || 
        !folderName.matches("^[a-zA-Z0-9._\\- ]+$")) {
        throw new IllegalArgumentException("Invalid folder name: contains invalid characters");
    }
    
    OutputStream out = imapSocket.getOutputStream();
    // Use IMAP quoted string format with proper escaping
    String escapedName = folderName.replace("\\", "\\\\").replace("\"", "\\\"");
    String command = "a1 SELECT \"" + escapedName + "\"\r\n";
    out.write(command.getBytes("US-ASCII"));
    out.flush();
}
```

## Explanation

The fix applies two layers of defence. First, input validation rejects any folder name containing characters outside an allowlist of safe values (alphanumeric, period, hyphen, underscore, and space). This prevents injection of IMAP protocol metacharacters like `\r` and `\n`. Second, the folder name is wrapped in IMAP quoted strings, and any embedded backslashes or quotes are escaped according to IMAP's quoted-string escaping rules. This ensures that even if validation were bypassed, the folder name remains a single token within the IMAP command. The combination prevents an attacker from injecting new IMAP commands.
