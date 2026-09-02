## Verdict
Confirmed. `requestedFileName` is attacker-controlled input that is concatenated directly into a raw FTP protocol command with no validation or encoding, allowing injection of arbitrary FTP control-channel commands.

## Source
`requestedFileName`, the parameter to `fetchReportFile(String requestedFileName)` on line 12. The method comment states it "comes straight from the export request payload," i.e. external, attacker-influenced input with no prior validation.

## Fix

```java
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * Downloads a report file from the archive FTP server on behalf of a
 * report-export request.
 */
public class FtpRawSocketFilenameInjection {

    // Allow only a plain filename: letters, digits, dot, dash, underscore.
    // No CR/LF, no slashes, no spaces, no shell/FTP metacharacters.
    private static final Pattern SAFE_FILENAME = Pattern.compile("^[A-Za-z0-9._-]{1,255}$");

    public void fetchReportFile(String requestedFileName) throws IOException {
        // requestedFileName comes straight from the export request payload
        if (requestedFileName == null || !SAFE_FILENAME.matcher(requestedFileName).matches()
                || requestedFileName.contains("..")) {
            throw new IllegalArgumentException("Invalid report file name: " + requestedFileName);
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
}
```

## Explanation
The FTP control protocol is a plaintext, CRLF-delimited command stream: each `\r\n`-terminated line is parsed by the server as one complete command. Because `command` is built by string concatenation and written to the socket verbatim, any `\r\n` sequence embedded in `requestedFileName` terminates the intended `RETR` command early and starts a new one that the FTP server will execute with the same authenticated session (for example, injecting a `\r\nDELE otherfile\r\n` or `\r\nRETR ../../etc/passwd\r\n` sequence smuggles in arbitrary additional commands). This is the raw-socket-protocol equivalent of OS command injection: the sink is any write of unneutralized external data into a line-oriented control channel, not just a shell exec call.

The fix closes this by validating `requestedFileName` against a strict allowlist before it is ever placed into the command string, rather than trying to blacklist or strip dangerous sequences. Allowing only `[A-Za-z0-9._-]` structurally excludes CR, LF, and every other FTP/shell metacharacter, so no encoding step is needed and no injected line can ever be constructed. The explicit `..` check blocks path traversal within the allowed charset (e.g. `..`, `...`, `.-.` style names) that the character class alone would not catch. Invalid names are rejected outright (fail closed) rather than sanitized, since stripping characters could still produce a different, unintended-but-valid filename. This also implicitly caps the length and prevents null-byte or non-ASCII payloads that `US_ASCII` encoding would otherwise mangle unpredictably.

To verify: send a filename containing a CRLF-delimited second command (e.g. `"report.csv\r\nDELE other.csv"`) and confirm the call now throws `IllegalArgumentException` instead of writing two FTP commands to the socket; also confirm a legitimate filename like `"report_2026-09-01.csv"` still succeeds.
