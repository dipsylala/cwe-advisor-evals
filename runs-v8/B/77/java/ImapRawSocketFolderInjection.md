## Verdict

Exploitable.

## Source

Untrusted input: `request.getParameter("folder")` (line 13) — user-controlled folder name from HTTP request parameter.

Sink: `out.write(command.getBytes("US-ASCII"))` (line 18) — writes concatenated IMAP command to the backend IMAP server via raw socket.

Data flow: The folder name is concatenated directly into an IMAP protocol command string on line 16 without any validation or parameterization, then sent to the IMAP server on line 18.

## Fix

**Vulnerable code:**
```java
public void selectFolder(HttpServletRequest request, Socket imapSocket) throws Exception {
    String folderName = request.getParameter("folder");
    OutputStream out = imapSocket.getOutputStream();
    String command = "a1 SELECT " + folderName + "\r\n";
    out.write(command.getBytes("US-ASCII"));
    out.flush();
}
```

**Fixed code:**
```java
import javax.mail.*;

public void selectFolder(HttpServletRequest request, Session mailSession) throws Exception {
    String folderName = request.getParameter("folder");
    
    // Validate folder name against allowlist as defence-in-depth
    if (!folderName.matches("^[\\w\\-./\\[\\]]+$")) {
        throw new IllegalArgumentException("Invalid folder name");
    }
    
    Store store = mailSession.getStore("imap");
    store.connect();
    try {
        Folder folder = store.getFolder(folderName);
        if (!folder.exists()) {
            throw new FolderNotFoundException(folder);
        }
        folder.open(Folder.READ_WRITE);
        // Folder selection complete; use folder...
        folder.close(false);
    } finally {
        store.close();
    }
}
```

## Explanation

The fix replaces the vulnerable raw socket approach with JavaMail's (now Jakarta Mail) parameterized IMAP API. Instead of concatenating the folder name into a raw protocol command string, the code now uses the `Store.getFolder(name)` method, which safely handles the protocol internally without allowing command injection. The folder name is validated against an allowlist of safe characters as defence-in-depth, rejecting any input containing unexpected patterns that might indicate an injection attempt. This eliminates the CRLF injection vector because the folder name is now treated purely as data, not as part of a command string being constructed for the protocol interpreter.

## Behaviour changes

- **Method signature**: Changed parameter from `Socket imapSocket` to `Session mailSession`. This is necessary because the fix replaces the raw socket approach with a proper IMAP client library. The Session object encapsulates all connection and configuration details that were previously managed manually via the raw socket.
- **Error handling**: Added explicit validation with `IllegalArgumentException` for invalid folder names. The fixed code also checks `folder.exists()` before attempting to open, adding a safety gate the original lacked.
- **Resource management**: Added try-finally to ensure `store.close()` is always called, preventing connection leaks. The original code did not close the socket, leaving resource cleanup to the caller.
- **Connection lifecycle**: The fixed code manages the connection through the Store/Folder API rather than via explicit OutputStream writes. This allows the IMAP client library to apply protocol-level safeguards automatically.

