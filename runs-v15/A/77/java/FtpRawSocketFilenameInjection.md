## Verdict

**Confirmed:** CWE-77 command injection vulnerability. The `requestedFileName` parameter is concatenated directly into an FTP RETR command without validation, allowing an attacker to inject FTP commands by including control characters like `\r\n` in the filename.

## Source

Line 19-21 in `FtpRawSocketFilenameInjection.java`:

```java
String command = "RETR " + requestedFileName + "\r\n";
// SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
out.write(command.getBytes(StandardCharsets.US_ASCII));
```

The vulnerability exists because `requestedFileName` (from user input on line 12) is used to construct an FTP command string without any validation or sanitization. An attacker can inject additional FTP commands by including `\r\n` sequences in the filename.

## Fix

Add validation to reject filenames containing special characters before constructing the FTP command:

```java
public void fetchReportFile(String requestedFileName) throws IOException {
    // Validate filename to prevent command injection
    if (requestedFileName == null || requestedFileName.isEmpty() ||
        requestedFileName.contains("\r") || requestedFileName.contains("\n") ||
        requestedFileName.contains("\0")) {
        throw new IllegalArgumentException("Invalid filename");
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

Alternatively, restrict filenames to alphanumeric characters, hyphens, underscores, and dots:

```java
if (!requestedFileName.matches("^[a-zA-Z0-9._-]+$")) {
    throw new IllegalArgumentException("Invalid filename");
}
```

## Explanation

The FTP RETR command is sent as raw text over a socket. If an attacker supplies a filename like `report.pdf\r\nDELE sensitive.pdf`, the concatenated command becomes two separate FTP commands, allowing the attacker to execute arbitrary FTP operations (delete files, rename files, etc.).

The fix validates that the filename does not contain control characters (`\r`, `\n`, `\0`) that would break out of the command context. Filenames should never legitimately contain these characters. The validation occurs before the filename is incorporated into the command string, preventing the injection.

A stronger fix would be to use a dedicated FTP client library (such as Apache Commons Net) that handles escaping and parameterization correctly, rather than constructing raw FTP commands.
