## Verdict

CWE-77 Command Injection confirmed. The `requestedFileName` parameter flows directly into an FTP protocol command without validation, allowing an attacker to inject FTP commands by including protocol delimiters (e.g., `\r\n`) in the filename.

## Source

Line 19-21: The filename is concatenated directly into the FTP `RETR` command:

```java
String command = "RETR " + requestedFileName + "\r\n";
out.write(command.getBytes(StandardCharsets.US_ASCII));
```

An attacker supplying `requestedFileName = "file.txt\r\nDELE sensitive.txt\r\n"` would inject commands that delete other files on the FTP server.

## Fix

Validate that `requestedFileName` contains only safe characters (alphanumerics, dots, hyphens, underscores) and reject any input containing FTP protocol control characters:

```java
public void fetchReportFile(String requestedFileName) throws IOException {
    // Validate filename to prevent FTP command injection
    if (!requestedFileName.matches("^[a-zA-Z0-9._-]+$")) {
        throw new IllegalArgumentException("Invalid filename: contains disallowed characters");
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

## Explanation

The vulnerability exists because FTP commands use `\r\n` as delimiters. Without validation, an attacker can embed newlines in the filename to inject arbitrary FTP commands. The fix adds a regex-based allowlist that restricts filenames to safe characters, preventing injection of control characters. This validation runs before any interaction with the FTP server, blocking the attack at the boundary.

For production systems, consider replacing raw socket communication with a vetted FTP client library (such as Apache Commons Net) which handles protocol details safely and provides built-in command validation.
