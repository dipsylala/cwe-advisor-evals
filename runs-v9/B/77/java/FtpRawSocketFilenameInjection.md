## Verdict

CWE-77 (Improper Neutralization of Special Elements used in a Command) - **exploitable**. Confidence: high.

## Source

- **Source:** the `requestedFileName` parameter of `fetchReportFile(String requestedFileName)` (line 12). The method's own comment states it "comes straight from the export request payload," i.e. it is attacker-influenced, external input.
- **Data flow:** `requestedFileName` flows unchanged and unvalidated from the method parameter directly into the string concatenation on line 19 (`String command = "RETR " + requestedFileName + "\r\n";`). There is no intermediate validation, encoding, or transformation anywhere in the method.
- **Sink:** line 21, `out.write(command.getBytes(StandardCharsets.US_ASCII))`, which writes the assembled command directly to the FTP control-channel socket (`Socket.getOutputStream()`), matching the `Socket.getOutputStream().write()` taint sink for hand-built FTP command lines.
- **Why exploitable:** FTP is a line-oriented control protocol - each `\r\n`-terminated line the server reads off the socket is interpreted as one command. Because `requestedFileName` is concatenated into the command line with no restriction on its contents, a value containing an embedded `\r\n` (e.g. `report.csv\r\nDELE other-report.csv\r\n.`) terminates the intended `RETR` line early and injects one or more additional FTP commands into the same authenticated session (`reportsvc`), which the server will execute as if the application had sent them.

## Fix

**Library recommendation:** the knowledge base's primary defence for hand-rolled protocol clients in Java is to replace raw `Socket` command-line construction with a maintained FTP client library (e.g. Apache Commons Net's `FTPClient`) rather than writing protocol text by hand. No minimum safe version is recorded in the loaded guidance for that library, so any version adopted must be checked against SCA/dependency-check tooling before merging - "use the latest version" is not by itself a sufficient instruction. Because a library swap here would also change the method's connection-handling and file-transfer semantics (the original code never opens a data connection or reads a server reply, so it is not a complete FTP session), the code fix below applies the knowledge base's fallback for when no parameterized command API is in use at the point of change: allowlist-validate the untrusted value before it is ever assembled into the command line, closing the injection without altering the surrounding control flow.

Vulnerable code (line 19-21):

```java
String command = "RETR " + requestedFileName + "\r\n";
// SAST FINDING: CWE-77 reported here. Sink is the next statement.
out.write(command.getBytes(StandardCharsets.US_ASCII));
```

Fixed code:

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

    private static final Pattern SAFE_REPORT_FILENAME = Pattern.compile("[A-Za-z0-9._-]+");

    public void fetchReportFile(String requestedFileName) throws IOException {
        // requestedFileName comes straight from the export request payload;
        // reject anything that is not a plain filename before it reaches the FTP command channel
        if (!SAFE_REPORT_FILENAME.matcher(requestedFileName).matches()) {
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

The fix adds an allowlist check - `Pattern.compile("[A-Za-z0-9._-]+")` matched with `Matcher.matches()`, which is anchored to the whole string in Java (unlike `Pattern.matches` pitfalls seen in some other languages) - and rejects any `requestedFileName` that is not composed solely of ordinary filename characters. Because `\r`, `\n`, and any other protocol-significant byte fall outside that character class, a filename carrying an embedded CRLF sequence is rejected with `IllegalArgumentException` before it ever reaches the string concatenation that builds the `RETR` command, so it can never terminate the intended command line or introduce a second one. The validation runs at the earliest point the raw input is available (the top of `fetchReportFile`), which is also the only trust boundary in this call chain, and the rest of the method - including the existing `USER`/`PASS` handshake and the `RETR` command construction - is left as-is, since those lines are not the reported sink and do not depend on `requestedFileName`.

## Behaviour changes

- **New rejection path:** filenames that are not purely `[A-Za-z0-9._-]` (this includes legitimate names containing spaces, path separators, or non-ASCII characters, which the original code would previously have forwarded to the server without restriction) are now rejected with `IllegalArgumentException` instead of being sent. This is the intended effect of the fix, not a side effect - reason: it is the mechanism that closes the CRLF-based command injection, per the knowledge base's guidance to allowlist parameter structure when no parameterized command API is available.
- No other difference from the original: the socket lifecycle, the `USER`/`PASS` command bytes, the `RETR` command format, the character encoding (`US_ASCII`), and the method's return type, signature, and thrown-exception type (`IOException`) are unchanged. `IllegalArgumentException` is additionally possible on invalid input, which is a new but expected failure mode for an allowlist check, not a regression in the sink's existing contract.

**Assumption:** legitimate report filenames are plain names (letters, digits, `.`, `_`, `-`) with no path separators or whitespace, consistent with `Doc`-style export filenames; if the real system legitimately needs a broader character set (e.g. spaces), the allowlist pattern should be widened accordingly, but it must continue to exclude `\r` and `\n` in all cases.
