## Verdict

Confirmed. `folderName` comes from `request.getParameter("folder")` (untrusted, user-controlled) and is concatenated directly into a raw IMAP command string that is written to the socket. IMAP is a CRLF-delimited text protocol, so a value such as `INBOX\r\na2 LOGOUT` (or any other tagged command) lets the attacker terminate the intended `SELECT` and inject an arbitrary, fully-authenticated follow-on IMAP command on the same connection — classic CRLF/argument command injection (CWE-77 / CWE-93).

## Source

`E:/Github/cwe-advisor/evals/cases/77/java/ImapRawSocketFolderInjection/ImapRawSocketFolderInjection.java`, line 13:

```java
String folderName = request.getParameter("folder");
```

This flows unmodified into the command built at line 16 and written to the raw socket at line 18.

## Fix

### File: ImapRawSocketFolderInjection.java
```java
import java.io.OutputStream;
import java.net.Socket;
import javax.servlet.http.HttpServletRequest;

/**
 * Handles the "jump to folder" action in a lightweight webmail client that
 * talks to the backend IMAP server directly over a raw socket.
 */
public class ImapRawSocketFolderInjection {

    public void selectFolder(HttpServletRequest request, Socket imapSocket) throws Exception {
        // Mailbox name chosen by the signed-in user from the folder tree UI.
        String folderName = request.getParameter("folder");

        OutputStream out = imapSocket.getOutputStream();
        String command = "a1 SELECT " + quoteMailbox(folderName) + "\r\n";
        out.write(command.getBytes("US-ASCII"));
        out.flush();
    }

    /**
     * Encodes a mailbox name as an RFC 3501 quoted string so the server can
     * only interpret it as the single SELECT argument, never as additional
     * IMAP command syntax.
     */
    private static String quoteMailbox(String folderName) {
        if (folderName == null) {
            throw new IllegalArgumentException("folder is required");
        }
        // CR, LF and NUL cannot appear inside an IMAP quoted string (RFC 3501
        // excludes them from TEXT-CHAR) and have no valid escape sequence
        // there; letting one through would let the attacker close this
        // command early and inject additional IMAP commands on the same
        // connection, so these values are rejected outright rather than
        // stripped.
        for (int i = 0; i < folderName.length(); i++) {
            char c = folderName.charAt(i);
            if (c == '\r' || c == '\n' || c == '\0') {
                throw new IllegalArgumentException("folder contains an illegal control character");
            }
        }
        // Backslash and double-quote are the only characters an IMAP quoted
        // string requires escaping; escaping them keeps the value literal
        // instead of letting it close the quoted string or alter the
        // argument boundary.
        String escaped = folderName.replace("\\", "\\\\").replace("\"", "\\\"");
        return "\"" + escaped + "\"";
    }
}
```

## Explanation

The vulnerability is not the socket write itself but the unvalidated string concatenation that builds the IMAP command line: any user-controlled value reaching that concatenation can inject protocol control sequences, so the fix is applied at the point where the value is assembled into the command, before it reaches `out.write(...)`.

`quoteMailbox` neutralizes both attack surfaces the IMAP quoted-string grammar exposes:

- **CRLF/command injection (the reported finding):** `\r` or `\n` in the mailbox name would let the attacker end the current tagged command and start a new one that the server treats as fully authenticated. IMAP's quoted-string production explicitly excludes these characters from `TEXT-CHAR`, and there is no escape sequence for them inside a quoted string, so the only sound response is to reject the input rather than strip or re-encode it — stripping would silently turn a malicious value into a different, valid one instead of surfacing the bad request.
- **Quote/backslash breakout:** an unescaped `"` in the mailbox name would let the attacker close the quoted string early and append further arguments or flags to the same `SELECT` command; an unescaped `\` could similarly corrupt the intended parsing. Escaping both (`\` -> `\\`, `"` -> `\"`) is exactly what RFC 3501's quoted-string grammar requires, so the value round-trips as the literal mailbox name the server should select.

Wrapping the result in `"` characters is what makes it a syntactic quoted-string argument to `SELECT` rather than an unquoted atom, which is what the original code implicitly (and unsafely) relied on.

To verify: a request with `folder=INBOX%0d%0aa2%20LOGOUT` (or any other tagged command) now throws `IllegalArgumentException` from `quoteMailbox` instead of reaching the socket; a request with `folder=INBOX` still produces `a1 SELECT "INBOX"\r\n`, which every IMAP server accepts identically to the unquoted form; and a folder literally named `Weird"Name` or containing a backslash is sent as `a1 SELECT "Weird\"Name"\r\n`, selecting the correct mailbox rather than corrupting the command.
