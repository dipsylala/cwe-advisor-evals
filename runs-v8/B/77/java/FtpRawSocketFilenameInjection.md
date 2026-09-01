## Verdict

Real issue confirmed. The filename parameter reaches the FTP command string without validation, allowing CRLF injection.

## Source

`requestedFileName` parameter at line 12, sourced from export request payload (untrusted).

## Fix

Replace hand-rolled FTP socket operations with Apache Commons Net's `FTPClient` library, which safely handles filenames as structured parameters rather than raw command strings.

Vulnerable code:
```java
String command = "RETR " + requestedFileName + "\r\n";
out.write(command.getBytes(StandardCharsets.US_ASCII));
```

Fixed code (requires dependency: `commons-net:commons-net`):
```java
import org.apache.commons.net.ftp.FTPClient;
import java.io.ByteArrayOutputStream;

public void fetchReportFile(String requestedFileName) throws IOException {
    FTPClient ftpClient = new FTPClient();
    try {
        ftpClient.connect("ftp.internal.example.com", 21);
        ftpClient.login("reportsvc", ftp_password); // inject password from secure source
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (!ftpClient.retrieveFile(requestedFileName, out)) {
            throw new IOException("Failed to retrieve file from FTP server");
        }
    } finally {
        if (ftpClient.isConnected()) {
            ftpClient.disconnect();
        }
    }
}
```

## Explanation

The original code builds FTP protocol commands by concatenating untrusted input directly into a string terminated with `\r\n`. This allows an attacker to inject additional FTP commands through CRLF sequences in the filename (e.g., `"file.txt\r\nDELE target.txt"` executes two commands). The fix delegates to `FTPClient`, a maintained library that frames commands through its own API and does not allow filenames to break the protocol structure. `retrieveFile()` takes the filename as a structured parameter, not a concatenated string, eliminating the injection vector. The method returns success/failure as a boolean, allowing the caller to detect and respond to command failures.

## Behaviour changes

- Error handling: `retrieveFile()` returns a boolean instead of throwing on transport-level failure; I/O exceptions still throw. The fixed code checks the return value and throws on retrieval failure rather than silently continuing.
- Credentials: The password is no longer embedded as a literal in the command string; it should be injected from a secure source (environment variable, vault, etc.) instead of the placeholder shown.
- Connection lifecycle: FTPClient manages connection state internally; `disconnect()` is called explicitly in the finally block to ensure cleanup even on error.
