## Verdict

Exploitable (confidence: high). Single-file, single-hop flow from an HTTP request parameter to a raw IMAP command write, with no validation or neutralization anywhere on the path.

## Source

`request.getParameter("folder")` (`HttpServletRequest`) - the mailbox name chosen by the signed-in user in the folder-tree UI, but not constrained server-side to what the UI offers; an attacker can submit any string in the `folder` request parameter. It flows unmodified into `String command = "a1 SELECT " + folderName + "\r\n";` and reaches the sink at line 18, `out.write(command.getBytes("US-ASCII"))`, which writes the raw command straight onto the already-authenticated IMAP `Socket`. A `folder` value containing `\r\n` terminates the `SELECT` command early and smuggles an attacker-chosen IMAP command onto the same connection, running with the victim's authenticated session (IMAP control-channel/command injection).

## Fix

Per the loaded CWE-77 Java guidance, the primary defence for a hand-rolled IMAP/SMTP/FTP protocol client is a maintained client library rather than raw socket text. Jakarta Mail's `Store`/`Folder` API replaces the raw `Socket` write: `Store.getFolder(String)` plus `Folder.open(int)` issue the `SELECT` command through the library's own IMAP protocol layer instead of building it by string concatenation. Dependency: `jakarta.mail:jakarta.mail-api` (interfaces) plus an implementation provider such as `org.eclipse.angus:jakarta.mail` (the IMAP protocol handler lives in the provider, not the API jar). The loaded guidance gives a version floor for `SMTPTransport`'s address-command concatenation (CVE-2025-7962, fixed in `jakarta.mail` 2.0.2/1.6.8 and `angus-mail` 2.0.4); it records no separate floor for IMAP literal encoding, so no version number is asserted here - confirm the resolved provider version against SCA/dependency-check tooling before merging.

### File: ImapRawSocketFolderInjection.java

```java
import jakarta.mail.Folder;
import jakarta.mail.Store;
import javax.servlet.http.HttpServletRequest;

/**
 * Handles the "jump to folder" action in a lightweight webmail client that
 * talks to the backend IMAP server through the Jakarta Mail client library.
 */
public class ImapRawSocketFolderInjection {

    public Folder selectFolder(HttpServletRequest request, Store imapStore) throws Exception {
        // Mailbox name chosen by the signed-in user from the folder tree UI.
        String folderName = request.getParameter("folder");

        Folder folder = imapStore.getFolder(folderName);
        folder.open(Folder.READ_WRITE);
        return folder;
    }
}
```

## Explanation

The raw `"a1 SELECT " + folderName + "\r\n"` concatenation is replaced with `imapStore.getFolder(folderName)` followed by `folder.open(Folder.READ_WRITE)`. Jakarta Mail's IMAP provider frames its own protocol commands: when an argument contains a character outside the IMAP atom/quoted-string safe set - including CR or LF - it encodes the argument as an IMAP literal (`{n}` followed by CRLF and exactly `n` raw octets) instead of splicing it into the command line as text. A literal is read by the server as a fixed-length byte count regardless of its content, so an embedded CRLF can no longer terminate the `SELECT` command early and inject a second IMAP command. `Folder.open(Folder.READ_WRITE)` preserves the original command's semantics: Jakarta Mail issues `SELECT` (not `EXAMINE`) exactly when a folder is opened in `READ_WRITE` mode, matching the original hand-written `SELECT`.

Verification: the fixed file was compiled with `javac` (JDK 26) against real dependency jars - `jakarta.mail-api-2.1.3.jar`, `org.eclipse.angus:jakarta.mail-2.0.4.jar`, and `javax.servlet-api-4.0.1.jar` - and built cleanly, confirming `jakarta.mail.Store.getFolder(String)`, `jakarta.mail.Folder.open(int)`, and the `Folder.READ_WRITE` constant all resolve exactly as used.

## Behaviour changes

- Parameter type changed from `Socket imapSocket` to `Store imapStore`: the safe API has no form that keeps a raw `Socket` parameter, since the whole point of the fix is to stop driving the protocol over a bare socket. The caller must supply an already-connected `jakarta.mail.Store` (e.g. via `session.getStore("imaps")` then `.connect(host, user, password)`) in place of an already-connected `Socket` - the "connection already established by the caller" contract is preserved, only the connection object's type changes. This is an assumption inherent to adopting the guidance's named fix, since the finding's call chain does not show the caller.
- Return type changed from `void` to `Folder`: the original left the "selected mailbox" state implicit in the shared, caller-owned `Socket`. With the library API that state lives in the returned `Folder` object, so the caller now needs this reference to do anything with the selected mailbox afterward (list messages, read flags, etc.) or to close it later. Returning `void` here would make the opened folder unreachable and pointless to open.
- The explicit `US-ASCII` charset encoding (`command.getBytes("US-ASCII")`) is gone: command-line encoding is now owned by the Jakarta Mail provider, which is precisely what removes the injection point.
- `throws Exception` is kept as-is (rather than narrowed to `MessagingException`, which is what the new calls actually throw) so the exception contract stays at least as broad as the original and no caller-side catch clause needs to change.
- No other behaviour differs: the folder name is not otherwise transformed, validated, or logged differently than before.
