## Verdict

The vulnerability exists. Untrusted user input (`folderName` from the HTTP request parameter) is concatenated directly into an IMAP protocol command without validation. The IMAP protocol uses `\r\n` as a command terminator, so an attacker can inject CRLF sequences in the folder name to break out of the current SELECT command and inject additional arbitrary IMAP commands into the same connection.

## Source

Line 13: `String folderName = request.getParameter("folder");`

The `folderName` comes directly from untrusted user input via the HTTP request and flows unchanged into the command string at line 16.

## Fix

**Primary recommendation:** Replace the hand-rolled IMAP socket communication with a maintained IMAP client library. Use Jakarta Mail's `IMAPStore` API to select folders safely, which handles protocol framing internally without risk of CRLF injection.

**Code-level remediation (if raw socket must be used):** Validate that `folderName` does not contain CR or LF characters before constructing the command, and additionally constrain it to a safe character set (mailbox names should be alphanumeric with optional dots, dashes, and underscores).

Original vulnerable code:
```java
public void selectFolder(HttpServletRequest request, Socket imapSocket) throws Exception {
    String folderName = request.getParameter("folder");
    
    OutputStream out = imapSocket.getOutputStream();
    String command = "a1 SELECT " + folderName + "\r\n";  // VULNERABLE: concatenation without validation
    out.write(command.getBytes("US-ASCII"));
    out.flush();
}
```

Fixed code (if raw socket pattern must continue):
```java
public void selectFolder(HttpServletRequest request, Socket imapSocket) throws Exception {
    String folderName = request.getParameter("folder");
    
    // Reject folder names containing CR or LF (IMAP command delimiters)
    if (folderName == null || folderName.isEmpty() || 
        folderName.contains("\r") || folderName.contains("\n")) {
        throw new IllegalArgumentException("Invalid folder name");
    }
    
    // Additional hardening: allowlist safe characters for mailbox names
    if (!folderName.matches("^[a-zA-Z0-9._-]+$")) {
        throw new IllegalArgumentException("Invalid folder name");
    }
    
    OutputStream out = imapSocket.getOutputStream();
    String command = "a1 SELECT " + folderName + "\r\n";
    out.write(command.getBytes("US-ASCII"));
    out.flush();
}
```

Better fix (using Jakarta Mail - requires `jakarta.mail:jakarta.mail-api` and implementation like `org.eclipse.angus:smtp`):
```java
public void selectFolder(HttpServletRequest request, Store store) throws Exception {
    String folderName = request.getParameter("folder");
    
    // Validate folder name format
    if (folderName == null || folderName.isEmpty() || 
        folderName.contains("\r") || folderName.contains("\n")) {
        throw new IllegalArgumentException("Invalid folder name");
    }
    
    // Use Jakarta Mail's Folder API instead of raw socket commands
    Folder folder = store.getFolder(folderName);
    folder.open(Folder.READ_ONLY);
}
```

## Explanation

The vulnerability arises because the application constructs IMAP protocol commands by string concatenation without validating or encoding the folder name parameter. Since IMAP uses CR/LF (`\r\n`) as a protocol delimiter, an attacker can inject these characters in the folder name to inject additional arbitrary commands into the same socket connection. For example, requesting `folder=INBOX\r\nLIST "" "*"` would cause the server to execute an additional LIST command, potentially allowing the attacker to enumerate all mailboxes or execute other IMAP operations without authorization.

The fix takes two approaches:

1. **Code-level validation** (if raw socket must be used): Reject any folder name containing CR or LF characters, and validate against a strict allowlist of safe characters. This prevents CRLF injection but does not address other potential protocol parsing issues.

2. **Library-based fix** (recommended): Use Jakarta Mail's `IMAPStore.getFolder()` and `Folder` API, which handles all IMAP protocol framing internally and is resistant to command injection. This is the primary defence recommended by the guidance because it shifts responsibility for protocol safety from the application code to a maintained, audited library.

## Behaviour changes

**With the code-level validation:** Folder names are now restricted to alphanumeric characters, dots, dashes, and underscores. Any folder name containing CR, LF, or other special characters is rejected with an `IllegalArgumentException`. This may break legitimate use cases if folder names in the IMAP server contain other special characters (e.g., spaces, brackets, accented characters encoded in modified UTF-7). The allowlist pattern should be adjusted based on the actual IMAP server's naming requirements.

**With the Jakarta Mail library fix:** The application no longer directly constructs and sends IMAP protocol commands. Instead, it uses the standardized Jakarta Mail Folder API. This changes the caller's interface from a raw Socket to a Store object (obtained via `Session`/`Transport`), but the folder selection logic is otherwise equivalent. No behaviour change from the user's perspective - the correct folder is selected - but the application is now protected against command injection, redirection, and other protocol-level attacks that raw socket handling would expose.
