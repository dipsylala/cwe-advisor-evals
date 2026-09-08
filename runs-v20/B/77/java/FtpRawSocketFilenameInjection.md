## Verdict

Confirmed. `fetchReportFile` builds a raw FTP `RETR` command by concatenating an untrusted filename directly into a CRLF-terminated command string, then writes it straight to the control-channel socket. A filename containing `\r\n` terminates the `RETR` command early and injects an arbitrary second FTP command into the same session (e.g. `RETR a.txt\r\nDELE b.txt\r\n`).

## Source

`requestedFileName`, the parameter of `fetchReportFile(String requestedFileName)`. The class comment states it "comes straight from the export request payload," i.e. it is attacker/client-controlled and reaches the sink with no validation or encoding applied anywhere in the method.

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
        if (requestedFileName.indexOf('\r') >= 0 || requestedFileName.indexOf('\n') >= 0) {
            throw new IllegalArgumentException("requestedFileName must not contain CR or LF characters");
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

The sink is `Socket.getOutputStream().write()` sending a hand-built FTP command line. The knowledge base's Java guidance for this CWE notes that even a maintained FTP client library (Apache Commons Net's `FTPClient`) does not neutralize this on its own: its command-framing helper appends the command, a space, the argument, and CRLF with no check, so a filename containing `\r\n` still injects a second command through the library. The fix is what actually closes the vector regardless of transport: rejecting any embedded CR or LF in the filename before it is assembled into the command string, rather than silently stripping the characters (stripping would splice the payload's trailing bytes onto the legitimate filename and change its meaning rather than remove the injection). The check runs before the socket is opened, so a malicious request never reaches the network at all. Only the added validation guard was introduced; the `USER`/`PASS` handshake, the command format, the socket lifecycle (try-with-resources), and the ASCII encoding are unchanged from the original, since none of those are the source of the weakness. Rewriting the class onto Apache Commons Net's `FTPClient` was considered per the guidance's stated primary defense, but was not applied: it would require redesigning the login/credential handling (the `USER`/`PASS` raw-socket dialogue used elsewhere in this method) beyond the reported line, and per the guidance itself that library swap does not remove the need for this same CR/LF rejection - so the rejection is the change that closes the finding, and the library swap would be an unrelated, separately-scoped architecture change.

Verification: the fixed file was copied to a scratch location and compiled with `javac` (JDK 26) with no errors or warnings. No new imports were required; `IllegalArgumentException` is `java.lang` and needs no import. By hand: the only call whose signature could have changed, `fetchReportFile`, keeps its original signature (`String requestedFileName`, `throws IOException`) and its only caller-visible behavior change (throwing `IllegalArgumentException` on a crafted filename) is documented below.

## Behaviour changes

- A `requestedFileName` containing `\r` or `\n` now causes `fetchReportFile` to throw `IllegalArgumentException` immediately, before any socket is opened, instead of silently sending the attacker's injected FTP command to the server. Legitimate filenames (no CR/LF) are unaffected and still produce the identical `RETR <name>\r\n` command as before.
