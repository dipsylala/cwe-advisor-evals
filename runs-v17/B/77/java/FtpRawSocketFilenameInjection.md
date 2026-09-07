## Verdict

Exploitable. Untrusted filename parameter reaches the FTP command string without neutralization of CRLF delimiters. An attacker can inject additional FTP commands via embedded `\r\n` sequences.

## Source

File: `FtpRawSocketFilenameInjection.java`
Line: 19-21
Parameter: `requestedFileName` (line 12)

The `requestedFileName` parameter originates from an export request payload (attacker-controlled) and flows directly into the FTP RETR command via string concatenation at line 19. The concatenated command is written to the FTP control connection at line 21 without validation.

## Fix

**Library Recommendation**: Replace raw socket FTP with Apache Commons Net's `FTPClient` class. Apache Commons Net is actively maintained and handles FTP command construction safely. No specific version floor is required; use the latest stable version from the project's build tool.

For Maven, update `pom.xml`:
```xml
<dependency>
    <groupId>commons-net</groupId>
    <artifactId>commons-net</artifactId>
    <version>3.10.0</version>
</dependency>
```

For Gradle, update `build.gradle`:
```gradle
dependencies {
    implementation 'commons-net:commons-net:3.10.0'
}
```

**Fixed Code**:

```java
import java.io.IOException;
import java.io.OutputStream;
import java.util.regex.Pattern;
import org.apache.commons.net.ftp.FTPClient;

/**
 * Downloads a report file from the archive FTP server on behalf of a
 * report-export request.
 */
public class FtpRawSocketFilenameInjection {

    // Allowlist: only permit simple filenames without path traversal or control characters
    private static final Pattern SAFE_FILENAME = Pattern.compile("^[a-zA-Z0-9._-]+$");

    public void fetchReportFile(String requestedFileName) throws IOException {
        // Validate filename to reject path traversal and injection attempts
        if (requestedFileName == null || !SAFE_FILENAME.matcher(requestedFileName).matches()) {
            throw new IllegalArgumentException("Invalid filename: contains disallowed characters");
        }

        FTPClient ftpClient = new FTPClient();
        try {
            ftpClient.connect("ftp.internal.example.com", 21);
            ftpClient.login("reportsvc", System.getenv("FTP_REPORTSVC_PASS"));
            
            // Use FTPClient's retrieveFile() which safely constructs FTP commands internally
            // The library prevents command injection by handling CRLF encoding internally
            OutputStream out = System.out;
            boolean success = ftpClient.retrieveFile(requestedFileName, out);
            if (!success) {
                throw new IOException("Failed to retrieve file: " + ftpClient.getReplyString());
            }
        } finally {
            if (ftpClient.isConnected()) {
                ftpClient.disconnect();
            }
        }
    }
}
```

## Explanation

This fix eliminates the vulnerability in two ways. **Primary defence**: Apache Commons Net's `FTPClient.retrieveFile()` method safely constructs and transmits FTP commands internally using the library's parameterized API. The method takes the filename as a parameter to an internal command builder, not as a string interpolated into a raw command. This prevents CRLF injection because the library handles all special character escaping according to the FTP protocol. **Defence-in-depth**: The `SAFE_FILENAME` allowlist pattern (`^[a-zA-Z0-9._-]+$`) rejects filenames containing path traversal characters (`/`, `\`), control characters, and delimiters before they reach any sink. The validation throws `IllegalArgumentException` on mismatch, failing safely. The password is moved to `System.getenv()` to avoid hardcoding credentials, matching the environment-variable placeholder in the original code.

## Behaviour changes

- **Library initialization**: The code now creates an `FTPClient` instance and manages its lifecycle (`connect`, `login`, `disconnect`) instead of opening a raw `Socket`.
- **Authentication**: Password is sourced from the `FTP_REPORTSVC_PASS` environment variable (set at deployment) instead of a hardcoded placeholder.
- **Error handling**: The method now explicitly checks `FTPClient.retrieveFile()`'s boolean return value and raises `IOException` with the server's reply on failure. The original code did not check for successful file transmission.
- **File retrieval**: Data flows through `FTPClient`'s data connection (separate from the control channel) rather than the socket's output stream. Callers writing to `System.out` will receive the same file content.
- **Validation**: Filenames that do not match the allowlist pattern are rejected before connecting to the server, reducing server load and logging opportunities for malformed requests.

