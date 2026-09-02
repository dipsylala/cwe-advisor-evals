## Verdict

Real - the code is vulnerable to FTP command injection.

## Source

Line 19-21 constructs an FTP RETR command by directly concatenating `requestedFileName` (user-controlled input from the export request payload) without validation.

```java
String command = "RETR " + requestedFileName + "\r\n";
out.write(command.getBytes(StandardCharsets.US_ASCII));
```

An attacker can inject arbitrary FTP commands by embedding newline sequences or control characters in the filename.

## Fix

Validate the filename against a strict allowlist of safe characters before constructing the FTP command:

```java
public void fetchReportFile(String requestedFileName) throws IOException {
    // Validate filename against allowlist: only alphanumeric, dots, dashes, underscores, forward slashes
    if (!requestedFileName.matches("^[a-zA-Z0-9._/-]+$")) {
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

FTP commands are delimited by `\r\n` sequences. A malicious filename containing `\r\n` can break out of the RETR command and inject additional FTP operations. For example, a filename like `file.txt\r\nDELE sensitive.dat\r\n` would execute a DELETE command after RETR completes.

The fix validates the filename using a regex pattern that only permits safe characters: alphanumeric characters, dots (for file extensions), dashes, underscores, and forward slashes (for directory paths). Any filename containing control characters, newlines, or other metacharacters is rejected before being incorporated into the FTP command. This whitelist approach prevents command injection because the filename can no longer break the protocol structure.
