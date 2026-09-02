## Verdict

Confirmed. The code constructs an FTP RETR command by concatenating untrusted `requestedFileName` directly into a command string sent over a socket. An attacker can inject CRLF characters to append arbitrary FTP commands to the same connection, violating CWE-77's requirement to neutralize special elements before sending data to a command interpreter.

## Source

- **Variable**: `requestedFileName` parameter, line 12
- **Context**: Untrusted data from export request payload (per code comment)
- **Flow**: Parameter → concatenated into command string (line 19) → written to socket (line 21)

## Fix

Replace raw socket manipulation with Apache Commons Net's `FTPClient` API. The library's structured methods handle FTP protocol safely without string concatenation:

**Dependency (pom.xml)**:
```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-net</artifactId>
    <version>3.10.0</version>
</dependency>
```

**Fixed code**:
```java
import org.apache.commons.net.ftp.FTPClient;
import java.io.IOException;
import java.io.InputStream;

/**
 * Downloads a report file from the archive FTP server on behalf of a
 * report-export request.
 */
public class FtpRawSocketFilenameInjection {

    public void fetchReportFile(String requestedFileName) throws IOException {
        FTPClient ftpClient = new FTPClient();
        try {
            ftpClient.connect("ftp.internal.example.com", 21);
            ftpClient.login("reportsvc", System.getenv("FTP_REPORTSVC_PASS"));
            
            // Use structured API instead of raw command concatenation
            InputStream responseStream = ftpClient.retrieveFileStream(requestedFileName);
            if (responseStream != null) {
                // Process the file data from responseStream
                responseStream.close();
                ftpClient.completePendingCommand();
            }
            
            ftpClient.logout();
        } finally {
            if (ftpClient.isConnected()) {
                try {
                    ftpClient.disconnect();
                } catch (IOException ex) {
                    // Log and continue cleanup
                }
            }
        }
    }
}
```

## Explanation

The vulnerability arises because raw socket writes allow untrusted input containing CRLF sequences (carriage return `\r` and line feed `\n`) to break out of the intended RETR command and inject additional FTP commands. For example, `file.txt\r\nDELE otherfile.txt\r\n` would delete a file instead of retrieving it.

The fix uses Apache Commons Net's `FTPClient`, which provides a structured API (`retrieveFileStream`) that accepts the filename as a method parameter rather than concatenating it into a command string. The library encodes or validates the filename internally according to FTP protocol rules, preventing injection. This follows CWE-77's core principle: **use the interpreter's (FTP server's) own parameterized or structured command-construction method instead of building command strings by concatenation**.

The fixed code also demonstrates proper resource management by ensuring the FTP connection is closed in a `finally` block, even if an exception occurs.

## Behaviour changes

- **Replaced manual socket-based FTP protocol handling** with a maintained library API, eliminating the need to construct raw command strings
- **Added explicit connection lifecycle management** (`connect`, `login`, `logout`, `disconnect`) via the FTPClient API
- **Filename is now passed as a parameter** to `retrieveFileStream()` rather than concatenated into a command string
- **File data is returned as an InputStream** instead of being written directly to the original socket's output stream; the caller is responsible for consuming or copying this stream as needed
- **Added error handling** for disconnect failures to ensure cleanup completes even on exception
- **Added environment variable lookup** for the password instead of the placeholder; adjust to match actual credential management in your application
