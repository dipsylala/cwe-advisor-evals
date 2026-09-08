## Verdict

Exploitable. The `requestedFileName` parameter is concatenated directly into an FTP RETR command without validation, allowing CRLF injection. An attacker can inject arbitrary FTP commands by including `\r\n` in the filename.

## Source

Parameter `requestedFileName` in method `fetchReportFile(String requestedFileName)`. The parameter comment states it "comes straight from the export request payload", making it untrusted input.

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
        // Validate filename to prevent FTP command injection via CRLF
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

The vulnerability arises from concatenating untrusted input directly into an FTP protocol command. The original code at line 19 builds `String command = "RETR " + requestedFileName + "\r\n"` and sends it to the FTP server without validation. An attacker can inject additional FTP commands by including CRLF sequences in the filename. For example, a filename like `"report.txt\r\nDELE victim.txt\r\n"` would cause the FTP server to execute both a RETR and a DELETE command in the same connection.

The fix adds validation before the filename is used in the command string. It rejects any filename containing carriage return (`\r`) or line feed (`\n`) characters by throwing an `IllegalArgumentException`. This prevents the injection of additional protocol commands. Per CWE-77 Java guidance, validating input to reject the protocol's delimiter characters (CRLF) is the primary defence when using raw protocol sockets; the validation closes the vector by ensuring the filename cannot break out of the RETR command it is embedded in.

## Behaviour changes

**Added validation:** The method now rejects filenames containing CR or LF characters by throwing `IllegalArgumentException`. This is a breaking change for legitimate calls that pass filenames with embedded newlines (if any such calls exist), but such filenames are invalid in FTP and would have failed on the server anyway. The caller must handle the exception and respond with an error to the user. This is the intended behavior: invalid filenames are rejected at the application boundary, not forwarded to the server.

**No other changes:** The FTP command format, socket connection, authentication, and write operations remain unchanged. The method still sends the same sequence of commands to the FTP server for valid filenames.
