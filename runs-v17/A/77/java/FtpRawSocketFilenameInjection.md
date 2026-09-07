## Verdict
CONFIRMED - The code constructs an FTP RETR command by directly concatenating user-supplied input without validation, allowing injection of arbitrary FTP commands via CRLF sequences in the filename parameter.

## Source
The vulnerability exists at line 21 in `FtpRawSocketFilenameInjection.java`. The `requestedFileName` parameter is user-controlled (derived from an export request payload) and is concatenated directly into the FTP command string without any sanitization. An attacker can inject CRLF characters to break out of the intended RETR command and execute additional FTP commands on the server.

Example attack: A filename of `report.txt\r\nDELE sensitive.txt` would execute both RETR and DELETE commands.

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
        
        // Reject filenames containing CR or LF characters (FTP command separators)
        if (requestedFileName.contains("\r") || requestedFileName.contains("\n")) {
            throw new IllegalArgumentException("Filename contains invalid characters");
        }
        
        // requestedFileName comes straight from the export request payload
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
The fix adds input validation before using the `requestedFileName` in the FTP command. It rejects any filename that contains carriage return (`\r`) or line feed (`\n`) characters, which are the command separators in the FTP protocol. This prevents an attacker from injecting additional FTP commands.

The validation occurs before any FTP communication, failing fast with an `IllegalArgumentException` if malicious input is detected. This maintains the original functionality for legitimate filenames while blocking the injection vector that would allow an attacker to execute arbitrary FTP commands on the server.
