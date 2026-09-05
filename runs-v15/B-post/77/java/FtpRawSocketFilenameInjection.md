## Verdict
exploitable

## Source
Untrusted input: `requestedFileName` parameter (from export request payload) flows into FTP RETR command.

Sink: Line 21, `out.write(command.getBytes(StandardCharsets.US_ASCII))` writes the FTP command to the socket.

## Fix

**Vulnerable code:**
```java
public void fetchReportFile(String requestedFileName) throws IOException {
    try (Socket ftpSocket = new Socket("ftp.internal.example.com", 21)) {
        OutputStream out = ftpSocket.getOutputStream();
        out.write("USER reportsvc\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write("PASS ${FTP_REPORTSVC_PASS}\r\n".getBytes(StandardCharsets.US_ASCII));

        String command = "RETR " + requestedFileName + "\r\n";
        // VULNERABLE: requestedFileName is not validated; \r\n injection possible
        out.write(command.getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }
}
```

**Fixed code:**
```java
public void fetchReportFile(String requestedFileName) throws IOException {
    // Validate filename: allowlist safe characters only (alphanumeric, dots, dashes, underscores)
    // Rejects CRLF and control sequences; prevents leading/trailing hyphens (CWE-88)
    if (requestedFileName == null || !requestedFileName.matches("^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$")) {
        throw new IllegalArgumentException("Invalid filename: contains special characters or control sequences");
    }
    
    try (Socket ftpSocket = new Socket("ftp.internal.example.com", 21)) {
        OutputStream out = ftpSocket.getOutputStream();
        out.write("USER reportsvc\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write("PASS ${FTP_REPORTSVC_PASS}\r\n".getBytes(StandardCharsets.US_ASCII));

        // requestedFileName is now validated; safe to use in FTP command
        String command = "RETR " + requestedFileName + "\r\n";
        out.write(command.getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }
}
```

## Explanation
The fix adds strict allowlisting before the filename reaches the FTP command builder. The regex pattern `^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$` restricts filenames to safe characters only: alphanumeric, dots, dashes, and underscores. This rejects any attempt to inject CRLF (`\r\n`) or other control characters that could inject additional FTP commands. The pattern also rejects leading and trailing hyphens to prevent option/flag injection (CWE-88 defense-in-depth). The validation throws an `IllegalArgumentException` on mismatch, breaking the data flow before untrusted input reaches the sink. Only the validated filename is used to build the command string.

## Behaviour changes
- Added a null check and validation step before building the command string, which rejects filenames with special characters. Callers passing invalid filenames will now receive an `IllegalArgumentException` instead of sending malformed FTP commands.
- The exception thrown has a descriptive message but does not echo the untrusted input, preventing potential information leaks. Legitimate filenames matching the allowlist (e.g., `report-2026.txt`, `data_final.csv`) will pass without any change in behavior.
