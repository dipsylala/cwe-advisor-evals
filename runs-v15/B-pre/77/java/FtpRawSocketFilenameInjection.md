## Verdict

**VULNERABLE** — Improper Neutralization of Special Elements used in a Command (CWE-77). The `requestedFileName` parameter is directly concatenated into an FTP protocol command without validation, allowing an attacker to inject CRLF characters and execute arbitrary FTP commands on the server. For example, a filename like `report.txt\r\nDELE secret.txt\r\n` would execute a DELETE command in addition to the RETR command.

## Source

**Parameter**: `requestedFileName` at line 12, passed directly from external request
**Sink**: Line 21, where the unsanitized filename is written into the FTP command stream via `out.write(command.getBytes(StandardCharsets.US_ASCII))`
**Intermediate taint**: Line 19, where the command is built by string concatenation: `String command = "RETR " + requestedFileName + "\r\n";`

The FTP protocol uses `\r\n` (CRLF) as command delimiters. An attacker controlling `requestedFileName` can embed CRLF sequences to inject additional protocol commands that execute with the privileges of the application's FTP connection.

## Fix

**Library dependency**: Add Apache Commons Net 3.10.0 or later to your project dependencies. This library provides a robust FTPClient that handles protocol framing and escaping internally.

For Maven, add to `pom.xml`:
```xml
<dependency>
    <groupId>commons-net</groupId>
    <artifactId>commons-net</artifactId>
    <version>3.10.0</version>
</dependency>
```

**Vulnerable code** (original, line 12–23):
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

**Fixed code**:
```java
public void fetchReportFile(String requestedFileName) throws IOException {
    // requestedFileName comes straight from the export request payload
    FTPClient ftpClient = new FTPClient();
    try {
        ftpClient.connect("ftp.internal.example.com", 21);
        ftpClient.login("reportsvc", "${FTP_REPORTSVC_PASS}");
        
        // Retrieve the file using the library API instead of raw protocol commands
        InputStream input = ftpClient.retrieveFileStream(requestedFileName);
        if (input != null) {
            // Process the file input stream here
            input.close();
        }
        
        if (!ftpClient.completePendingCommand()) {
            throw new IOException("Failed to retrieve file: " + ftpClient.getReplyString());
        }
    } finally {
        if (ftpClient.isConnected()) {
            ftpClient.logout();
            ftpClient.disconnect();
        }
    }
}
```

## Explanation

The original code constructs FTP protocol commands by concatenating untrusted input directly into command strings and writing them to the socket. FTP is a line-oriented protocol where commands are terminated with CRLF (`\r\n`), so embedding CRLF sequences in the filename parameter allows an attacker to inject additional commands.

The fix replaces raw socket manipulation with Apache Commons Net's `FTPClient`, which provides a structured API for FTP operations. The `retrieveFileStream(String)` method handles all protocol framing and escaping internally, ensuring that the filename parameter is treated strictly as data rather than executable command syntax. The filename cannot be interpreted as a protocol delimiter or command boundary, regardless of its content.

This follows the guidance for CWE-77 in Java: "prefer a maintained client library over raw socket text" for non-OS-shell protocol clients like FTP. The library also handles connection state, error conditions, and protocol compliance more robustly than manual socket manipulation.

## Behaviour changes

- **Primary**: The application now delegates FTP command construction and execution to the library rather than writing raw protocol strings. Filenames are transmitted as data only, never as command syntax.
- **Authentication**: Credentials are now passed to the library's `login()` method rather than embedded in raw commands; this also allows the library to handle authentication state and failures consistently.
- **Error handling**: FTP errors are now surfaced through the library's reply code and string (`getReplyString()`), providing more structured access to server responses.
- **Resource lifecycle**: The library manages the socket connection lifecycle and ensures proper cleanup via `logout()` and `disconnect()`, even if the retrieval fails partway through.
- **Protocol compliance**: The library ensures that all FTP commands follow protocol rules (line termination, command ordering, state transitions) automatically, reducing the risk of other protocol-level vulnerabilities.
