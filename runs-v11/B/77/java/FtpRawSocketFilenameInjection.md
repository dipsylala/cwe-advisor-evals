## Verdict

The finding is confirmed. The code concatenates the untrusted `requestedFileName` parameter directly into an FTP protocol command string terminated with `\r\n`. This allows command injection: an attacker can include `\r\n` followed by additional FTP commands (e.g., `file.txt\r\nDELE other.txt\r\n`) to manipulate server-side operations.

## Source

**Parameter:** `requestedFileName` (line 12) — originates from report-export request payload, untrusted user input.

**Taint flow:**
1. `fetchReportFile(String requestedFileName)` receives untrusted input
2. Line 19: concatenated into `String command = "RETR " + requestedFileName + "\r\n"`
3. Line 21: assembled bytes written to FTP server via socket: `out.write(command.getBytes(StandardCharsets.US_ASCII))`

**Sink:** `Socket.getOutputStream().write(byte[])` — writes the raw FTP command bytes to the server without validation or parameterization.

## Fix

**Library:** Replace raw `Socket` I/O with Apache Commons Net's `FTPClient`. Use version **3.11.0** or later (or current stable if the project's existing Commons Net dependency is newer).

**Manifest change (Maven pom.xml example):**
```xml
<dependency>
    <groupId>commons-net</groupId>
    <artifactId>commons-net</artifactId>
    <version>3.11.0</version>
</dependency>
```

**Vulnerable code (lines 12–24):**
```java
public void fetchReportFile(String requestedFileName) throws IOException {
    // requestedFileName comes straight from the export request payload
    try (Socket ftpSocket = new Socket("ftp.internal.example.com", 21)) {
        OutputStream out = ftpSocket.getOutputStream();
        out.write("USER reportsvc\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write("PASS ${FTP_REPORTSVC_PASS}\r\n".getBytes(StandardCharsets.US_ASCII));

        String command = "RETR " + requestedFileName + "\r\n";
        // SAST FINDING: CWE-77 - command injection via untrusted filename
        out.write(command.getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }
}
```

**Fixed code:**
```java
import java.io.IOException;
import java.io.InputStream;
import java.util.regex.Pattern;
import org.apache.commons.net.ftp.FTPClient;

public void fetchReportFile(String requestedFileName) throws IOException {
    // Allowlist: only alphanumerics, dots, underscores, hyphens
    if (requestedFileName == null || requestedFileName.isEmpty() ||
        !Pattern.matches("^[a-zA-Z0-9._-]+$", requestedFileName)) {
        throw new IllegalArgumentException("Invalid filename format");
    }

    FTPClient ftpClient = new FTPClient();
    try {
        ftpClient.connect("ftp.internal.example.com", 21);
        String password = System.getenv("FTP_REPORTSVC_PASS");
        if (password == null) {
            throw new IOException("FTP credentials not configured");
        }
        ftpClient.login("reportsvc", password);
        
        // Use parameterized API instead of building command strings
        try (InputStream inputStream = ftpClient.retrieveFileStream(requestedFileName)) {
            if (inputStream == null) {
                throw new IOException("Failed to retrieve file: " + ftpClient.getReplyString());
            }
            // Process the file stream (caller's logic goes here)
        }
        
        ftpClient.completePendingCommand();
    } finally {
        if (ftpClient.isConnected()) {
            try {
                ftpClient.logout();
            } catch (IOException e) {
                // Suppress logout errors on cleanup
            }
            ftpClient.disconnect();
        }
    }
}
```

## Explanation

The fixed code replaces the unsafe raw-socket protocol construction with `FTPClient.retrieveFileStream(filename)`, which encapsulates FTP command building and sanitization. The filename is validated against an allowlist pattern (`^[a-zA-Z0-9._-]+$`) that rejects `\r`, `\n`, and other control characters that could inject protocol commands. The validated filename is passed to the parameterized method, not the original untrusted string. `FTPClient` internally constructs the `RETR` command safely without exposing the protocol format to user input.

The fix preserves the original method signature and error handling contract: it still takes a filename and throws `IOException` on connection or authentication failure. The allowlist validation throws `IllegalArgumentException` early for malformed names, preventing invalid input from reaching the protocol layer.

## Behaviour changes

- **Argument validation:** filenames not matching `^[a-zA-Z0-9._-]+$` now raise `IllegalArgumentException` instead of reaching the server. This may reject legitimate filenames containing spaces, special characters, or Unicode. The allowlist can be broadened if those are valid in your deployment (e.g., to `^[a-zA-Z0-9._\-\s]+$` for spaces), but must remain restrictive to guard against CRLF injection.
- **Error reporting:** the code now reports FTP server errors via `ftpClient.getReplyString()` instead of relying on implicit protocol flow. Callers see clearer error messages.
- **Connection lifecycle:** `FTPClient` manages socket I/O internally, so the raw `try-with-resources` on `Socket` is replaced with explicit `login()`, file retrieval, and `logout()` steps. The `completePendingCommand()` call ensures pipelined commands are flushed before disconnection.
- **Credentials handling:** the password is read from the environment variable once and validated; it is not embedded in a command string written to the socket, eliminating a secondary injection risk if the password contains special characters.
