## Verdict
The vulnerability is confirmed. The `requestedFileName` parameter is used directly in an FTP protocol command without validation, allowing an attacker to inject additional FTP commands by including carriage return and line feed characters.

## Source
The vulnerability exists at line 21 where an untrusted filename is concatenated into an FTP RETR command:
```java
String command = "RETR " + requestedFileName + "\r\n";
out.write(command.getBytes(StandardCharsets.US_ASCII));
```

If `requestedFileName` contains `\r\n`, it will terminate the current command and allow injection of a new command. For example, a filename like `report.txt\r\nDELE admin.txt` would execute both RETR and DELETE commands.

## Fix
### File: FtpRawSocketFilenameInjection.java
```java
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Downloads a report file from the archive FTP server on behalf of a
 * report-export request.
 */
public class FtpRawSocketFilenameInjection {

    public void fetchReportFile(String requestedFileName) throws IOException {
        // Validate filename to prevent FTP command injection
        if (requestedFileName == null || requestedFileName.isEmpty()) {
            throw new IllegalArgumentException("Filename cannot be null or empty");
        }
        
        // Reject filenames containing CRLF (FTP command terminators) or path traversal
        if (requestedFileName.contains("\r") || requestedFileName.contains("\n") || requestedFileName.contains("..")) {
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
}
```

## Explanation
The fix validates the `requestedFileName` parameter before using it in the FTP command:

1. **Null and empty check:** Rejects null or empty filenames to prevent edge cases.
2. **CRLF validation:** Rejects any filename containing carriage return (`\r`) or line feed (`\n`) characters, which are FTP protocol command separators. This prevents an attacker from injecting additional FTP commands.
3. **Path traversal prevention:** Rejects filenames containing `..` to prevent directory traversal attacks that could access files outside the intended directory.
4. **Exception handling:** Throws `IllegalArgumentException` for invalid input, preventing the vulnerable code path from executing.

This approach treats the filename as an untrusted input and applies input validation to constrain its format, which is the primary defense against command injection vulnerabilities in non-shell command interpreters.
