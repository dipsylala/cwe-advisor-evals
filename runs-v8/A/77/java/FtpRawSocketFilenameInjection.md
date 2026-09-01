## Verdict

The code is vulnerable to command injection through the FTP RETR command. An attacker can inject arbitrary FTP commands by embedding protocol delimiters (CR/LF) in the `requestedFileName` parameter, allowing commands beyond the intended file retrieval to execute on the FTP server.

## Source

Line 19-21 concatenate user-controlled `requestedFileName` directly into an FTP command string without validation:

```java
String command = "RETR " + requestedFileName + "\r\n";
out.write(command.getBytes(StandardCharsets.US_ASCII));
```

An attacker controlling `requestedFileName` can inject `\r\n` sequences to terminate the current command and inject new ones.

## Fix

Validate `requestedFileName` to reject any value containing CR, LF, or null bytes before using it in the FTP command. Use an allowlist of safe characters:

```java
public void fetchReportFile(String requestedFileName) throws IOException {
    // Validate filename: allow only alphanumerics, dots, hyphens, underscores, and forward slashes
    if (!requestedFileName.matches("[a-zA-Z0-9._\\-/]+")) {
        throw new IllegalArgumentException("Invalid filename format");
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

FTP protocol commands are delimited by `\r\n` sequences. Injecting these characters into the filename allows an attacker to inject complete FTP commands. The fix uses a strict allowlist regex to permit only characters safe in FTP filenames (alphanumerics, dots, hyphens, underscores, and forward slashes for paths), rejecting any filename containing control characters or special characters that could be interpreted as command delimiters. This prevents command injection by ensuring user input cannot alter the command structure.
