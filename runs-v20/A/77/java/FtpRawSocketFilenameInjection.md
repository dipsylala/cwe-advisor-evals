## Verdict

Confirmed. `fetchReportFile` builds an FTP `RETR` command by concatenating attacker-influenced `requestedFileName` directly into the command string with no neutralization, then writes it to the raw control-channel socket.

## Source

`requestedFileName`, the parameter to `fetchReportFile(String requestedFileName)` — per the comment, it comes straight from the export request payload, i.e. externally controlled.

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
        // requestedFileName comes straight from the export request payload
        if (requestedFileName == null || requestedFileName.isEmpty()) {
            throw new IllegalArgumentException("requestedFileName must not be empty");
        }
        // The FTP control channel is a line-oriented text protocol: a CR or LF
        // embedded in the filename terminates the RETR command and starts a new
        // one, letting an attacker splice in arbitrary FTP commands (e.g. DELE,
        // STOR, another RETR). Reject rather than strip, since stripping would
        // silently turn a malicious filename into a different, valid-looking one.
        for (int i = 0; i < requestedFileName.length(); i++) {
            char c = requestedFileName.charAt(i);
            if (c == '\r' || c == '\n' || c == '\0') {
                throw new IllegalArgumentException("requestedFileName contains illegal control character");
            }
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

The FTP control channel is a line-oriented text protocol: each command ends at `\r\n`, and the server processes whatever text precedes that terminator as the next command. Because `requestedFileName` is concatenated straight into the `RETR` command with no filtering, a value containing `\r\n` terminates the intended `RETR` command early and injects one or more additional FTP commands (for example `\r\nDELE somefile.txt\r\n` or a second `RETR`/`STOR` targeting a different path) that the server will execute with the session's already-authenticated `reportsvc` credentials.

The fix rejects any `requestedFileName` containing a carriage return, line feed, or NUL byte before it is ever placed into the command string, throwing `IllegalArgumentException` instead of proceeding. Rejection is used rather than stripping the characters: stripping would silently turn an attacker-supplied multi-command payload into a single, differently-named but still attacker-chosen filename, whereas rejection surfaces the malformed input and lets the caller decide how to handle it (e.g. return a 400 to the export request). No third-party FTP client library is introduced, since the surrounding code intentionally speaks the protocol directly over a raw socket; the same validation approach applies regardless of the transport used to send the command.
