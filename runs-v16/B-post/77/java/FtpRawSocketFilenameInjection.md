## Verdict

Exploitable. The `requestedFileName` parameter arrives from untrusted input (the export request payload) and is concatenated directly into an FTP protocol command on line 19 without validation. An attacker can inject FTP commands by including `\r\n` in the filename (e.g., `file.txt\r\nDELE critical.txt\r\n`), causing arbitrary FTP operations to execute against the server.

## Source

`requestedFileName` parameter (line 12) - passed from the HTTP export request payload, documented as untrusted in the comment on line 13.

## Fix

**Vulnerable code (lines 12-24):**
```java
public void fetchReportFile(String requestedFileName) throws IOException {
    // requestedFileName comes straight from the export request payload
    try (Socket ftpSocket = new Socket("ftp.internal.example.com", 21)) {
        OutputStream out = ftpSocket.getOutputStream();
        out.write("USER reportsvc\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write("PASS ${FTP_REPORTSVC_PASS}\r\n".getBytes(StandardCharsets.US_ASCII));

        String command = "RETR " + requestedFileName + "\r\n";
        // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
        out.write(command.getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }
}
```

**Fixed code (recommended with validation while migrating to Apache Commons Net):**
```java
public void fetchReportFile(String requestedFileName) throws IOException {
    // Validate filename to reject FTP command injection attempts
    if (requestedFileName == null || requestedFileName.isEmpty()) {
        throw new IllegalArgumentException("Filename cannot be null or empty");
    }
    if (requestedFileName.contains("\r") || requestedFileName.contains("\n")) {
        throw new IllegalArgumentException("Filename contains invalid control characters");
    }
    // Allowlist: restrict to safe filename characters
    if (!requestedFileName.matches("^[a-zA-Z0-9._\\-]+$")) {
        throw new IllegalArgumentException("Filename contains invalid characters");
    }
    
    try (Socket ftpSocket = new Socket("ftp.internal.example.com", 21)) {
        OutputStream out = ftpSocket.getOutputStream();
        out.write("USER reportsvc\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write("PASS ${FTP_REPORTSVC_PASS}\r\n".getBytes(StandardCharsets.US_ASCII));

        String command = "RETR " + requestedFileName + "\r\n";
        out.write(command.getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }
}
```

**Long-term fix (primary recommendation):**

Replace the raw socket implementation with Apache Commons Net `FTPClient`. This eliminates the vulnerability by delegating command construction to a maintained library:

```java
import org.apache.commons.net.ftp.FTPClient;

public void fetchReportFile(String requestedFileName) throws IOException {
    FTPClient ftpClient = new FTPClient();
    try {
        ftpClient.connect("ftp.internal.example.com", 21);
        ftpClient.login("reportsvc", System.getenv("FTP_REPORTSVC_PASS"));
        ftpClient.setFileType(org.apache.commons.net.ftp.FTP.BINARY_FILE_TYPE);
        
        // Validate filename as defence-in-depth
        if (requestedFileName == null || requestedFileName.isEmpty() ||
            requestedFileName.contains("\r") || requestedFileName.contains("\n") ||
            !requestedFileName.matches("^[a-zA-Z0-9._\\-]+$")) {
            throw new IllegalArgumentException("Invalid filename");
        }
        
        // Use library API instead of raw protocol commands
        ftpClient.retrieveFile(requestedFileName, new java.io.FileOutputStream(requestedFileName));
    } finally {
        if (ftpClient.isConnected()) {
            ftpClient.disconnect();
        }
    }
}
```

## Explanation

The vulnerability occurs because user-supplied `requestedFileName` is concatenated directly into an FTP command string (`RETR filename\r\n`) without validation. FTP uses `\r\n` as a command terminator, so an attacker can break out of the RETR command and inject additional FTP operations. The fix adds three layers: (1) immediate input validation to reject CR/LF characters and restrict to a safe character allowlist, rejecting the malicious input before it reaches the sink; (2) recommended migration to Apache Commons Net's `FTPClient` library, which encapsulates FTP protocol handling and does not concatenate user input into raw command strings; (3) defence-in-depth validation retained even with the library to catch edge cases.

## Behaviour changes

**For the validation-based fix:** The method now throws `IllegalArgumentException` when the filename is null, empty, contains control characters, or contains characters outside the safe set `[a-zA-Z0-9._\-]`. This is a stricter precondition than before - filenames with embedded spaces or special characters will now be rejected rather than sent to the server. This is appropriate for a file retrieval operation where filenames are expected to follow a predictable format.

**For the library-based fix:** The method signature and exception contract change - `FTPClient.retrieveFile()` throws `IOException` on protocol errors (same as the socket approach), but the output now writes to a local file instead of the OutputStream. The caller will need to adapt to receive file data from the destination file rather than from the `OutputStream`. Additionally, connection management is now explicit (`connect()` and `disconnect()`), providing better resource cleanup than the try-with-resources on the socket alone. The primary behaviour change is that the FTP implementation is now delegated to a maintained library and is no longer vulnerable to command injection.
