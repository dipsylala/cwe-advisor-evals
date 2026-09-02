## Verdict

CWE-77 (Improper Neutralization of Special Elements used in a Command). Verdict: **exploitable**. Confidence: high.

`selectFolder` builds a raw IMAP protocol command by string-concatenating a user-supplied mailbox name and writes it directly to the socket. The value is never checked for the protocol's own delimiter (CRLF), so a mailbox name containing `\r\n` terminates the `SELECT` command early and injects an arbitrary follow-on IMAP command into the same authenticated session (for example issuing an additional `LOGIN`, `LIST`, or `DELETE` command, or a `LOGOUT`/re-`LOGIN` to hijack the connection state).

## Source

- **Source:** `request.getParameter("folder")` (line 13) - an `HttpServletRequest` parameter, directly attacker-controlled and unvalidated.
- **Flow:** `folderName` is concatenated with no neutralization into `command = "a1 SELECT " + folderName + "\r\n"` (line 16).
- **Sink:** `out.write(command.getBytes("US-ASCII"))` on `imapSocket.getOutputStream()` (line 18) - a hand-built IMAP command written straight to the raw protocol socket, per `cwe/77/java/INDEX.md`'s taint-sink pattern (`Socket.getOutputStream().write()` with hand-built SMTP/IMAP/FTP command lines).
- **Sink contract:** the call returns `void`; the method deliberately discards any server response (no read of `imapSocket.getInputStream()` follows), so success/failure of the `SELECT` is not currently checked by this code either before or after remediation. The only implicit argument is the encoding (`US-ASCII`), which is not security-relevant here. Failure mode is whatever `OutputStream.write`/`flush` throw (`IOException`), propagated via the method's `throws Exception`.
- No validation, allowlisting, or CRLF stripping occurs between source and sink - the path is fully exploitable as reported.

## Fix

**Library recommendation:** switch off the hand-rolled socket protocol to a maintained mail client - Jakarta Mail (artifact `com.sun.mail:jakarta.mail`, or its successor `org.eclipse.angus:jakarta.mail`) - and use its `Store`/`Folder` API for IMAP, per `cwe/77/java/INDEX.md`'s primary defense ("Apply the same principle to any other hand-rolled protocol client (IMAP, FTP): prefer a maintained client library over raw socket text"). The knowledge base's version floor (2.0.2 / 1.6.8) is documented specifically for `SMTPTransport`'s CVE-2025-7962 CR/LF scan on outgoing `MAIL FROM:` commands; it is not established as covering the IMAP `Folder` code path used here, so no minimum version is asserted for this fix - confirm the resolved version against SCA/dependency-check tooling before merging, rather than treating any specific release as an IMAP-injection floor.

**Vulnerable code:**
```java
import java.io.OutputStream;
import java.net.Socket;
import javax.servlet.http.HttpServletRequest;

public class ImapRawSocketFolderInjection {

    public void selectFolder(HttpServletRequest request, Socket imapSocket) throws Exception {
        // Mailbox name chosen by the signed-in user from the folder tree UI.
        String folderName = request.getParameter("folder");

        OutputStream out = imapSocket.getOutputStream();
        String command = "a1 SELECT " + folderName + "\r\n";
        // Vulnerable: folderName is concatenated raw into the IMAP command line.
        out.write(command.getBytes("US-ASCII"));
        out.flush();
    }
}
```

**Fixed code:**
```java
import jakarta.mail.Folder;
import jakarta.mail.Store;
import javax.servlet.http.HttpServletRequest;

/**
 * Handles the "jump to folder" action in a lightweight webmail client that
 * talks to the backend IMAP server through Jakarta Mail's Store/Folder API.
 */
public class ImapRawSocketFolderInjection {

    public void selectFolder(HttpServletRequest request, Store imapStore) throws Exception {
        // Mailbox name chosen by the signed-in user from the folder tree UI.
        String folderName = request.getParameter("folder");

        Folder folder = imapStore.getFolder(folderName);
        folder.open(Folder.READ_WRITE);
    }
}
```

## Explanation

The fix removes the hand-built `"a1 SELECT " + folderName + "\r\n"` string and the raw socket write entirely, replacing them with Jakarta Mail's `Store.getFolder(String)` / `Folder.open(int)`. The library owns the IMAP wire protocol: it frames the mailbox name as an IMAP quoted-string or literal (RFC 3501) rather than splicing it into a bare command line, so an embedded CRLF or other IMAP delimiter in `folderName` is transmitted as literal mailbox-name data instead of terminating the command and starting a new one. This closes the CWE-77 injection at its source - the interpreter (the IMAP server) - by using its own structured command-construction API, per the root and Java-specific guidance's primary defense, rather than attempting to denylist or hand-escape CR/LF in the command string.

## Behaviour changes

- **Method signature changed from `Socket imapSocket` to `Store imapStore`.** Required because Jakarta Mail's `Store`/`Folder` API owns the connection and frames every command itself; it cannot be layered on top of a caller-supplied raw `Socket` that has already been used for hand-written protocol text. The caller must instead obtain the `Store` via `Session.getInstance(props).getStore("imap")` and `store.connect(host, port, user, password)` before invoking this method.
- **The server's response to `SELECT` is now observed via exceptions instead of being silently ignored.** `Folder.open()` throws `MessagingException` (a subtype of the already-declared `Exception`) if the mailbox does not exist or cannot be opened, whereas the original code wrote the command and returned without reading any response. This is a behavioral improvement inherent to using the library's structured API, not an intentional scope addition, and callers that relied on `selectFolder` never failing will now see an exception on an invalid/inaccessible mailbox.
- **`OutputStream`/`Socket` imports removed; `jakarta.mail.Folder`/`jakarta.mail.Store` imports added.** Follows directly from replacing the raw-socket sink with the library API; no longer used otherwise.
- No change to the encoding, response-discarding behavior for successful selections, or the method's `throws Exception` signature.
