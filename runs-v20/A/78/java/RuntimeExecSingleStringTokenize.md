## Verdict

Confirmed. `runPing` builds a shell command line by concatenating the attacker-controlled `host` request parameter directly into a string, then passes that string to `Runtime.getRuntime().exec(String)`. That overload tokenizes the string with a `StringTokenizer` and hands it to the OS's shell-less exec, but a single token can still smuggle a `;`, `|`, `&&`, backtick, or `$()` sequence that the OS shell (or, on some platforms, `exec`'s own handling) will interpret if the value ever reaches a shell, and more directly the value can inject extra ping flags or arguments (e.g. `-c 100`, or a value starting with `-` interpreted as an option) since there is no validation of `host` at all before it reaches the command line.

## Source

`request.getParameter("host")` in `PingDiagnosticServlet.doGet`, passed unmodified into `runPing(host)`.

## Fix

### File: PingDiagnosticServlet.java

```java
package com.example.netops.web;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Network diagnostics endpoint used by the ops dashboard to let on-call
 * engineers check reachability of a host from the app server's network
 * segment without needing shell access to the box.
 */
public class PingDiagnosticServlet extends HttpServlet {

    private static final int PING_COUNT = 4;

    // Matches a syntactically valid DNS hostname (RFC 1123, label-wise) or an
    // IPv4/IPv6 literal. Requires the value to start and end with an
    // alphanumeric character so it can never begin with '-' (which would let
    // it be parsed as a ping option) and excludes every shell metacharacter.
    private static final Pattern VALID_HOST =
            Pattern.compile("^[A-Za-z0-9]([A-Za-z0-9.:-]*[A-Za-z0-9])?$");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String host = request.getParameter("host");
        if (host == null || host.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing 'host' parameter");
            return;
        }
        if (host.length() > 253 || !VALID_HOST.matcher(host).matches()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid 'host' parameter");
            return;
        }

        StringBuilder output = new StringBuilder();
        try {
            output.append(runPing(host));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Ping interrupted");
            return;
        }

        response.setContentType("text/plain");
        response.getWriter().write(output.toString());
    }

    /**
     * Runs the platform ping utility against the requested host and returns
     * its captured stdout. The command is built as an argument array, with
     * ping's executable name, flag, and host passed as separate elements, so
     * no shell ever parses the host value and it cannot be split into extra
     * arguments.
     */
    private String runPing(String host) throws IOException, InterruptedException {
        ProcessBuilder builder =
                new ProcessBuilder("ping", "-c", String.valueOf(PING_COUNT), host);
        builder.redirectErrorStream(true);
        Process process = builder.start();

        StringBuilder result = new StringBuilder();
        try (BufferedReader reader =
                new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append(System.lineSeparator());
            }
        }
        process.waitFor();
        return result.toString();
    }
}
```

## Explanation

Two independent changes close the finding, and each closes a different exploitation path:

1. **`ProcessBuilder` with an argument array replaces `Runtime.exec(String)`.** `Runtime.getRuntime().exec(command)` tokenizes the single string on whitespace with a `StringTokenizer` and treats the pieces as `argv`, but that tokenization is naive - it does not distinguish an attacker's embedded metacharacters from ordinary delimiters, and any downstream code or platform path that ever re-interprets the value through a shell restores classic shell-metacharacter injection (`;`, `|`, `&&`, backticks). Passing `"ping"`, `"-c"`, the count, and `host` as separate `ProcessBuilder` array elements means the host string is delivered to the OS as a single, literal argument - no shell parses it, so `;`, `|`, backticks, and `$()` in the value have no special meaning.
2. **The hostname allowlist closes the remaining option-injection gap.** An argument array alone does not stop `host` from being read as a flag by the `ping` binary itself if it starts with `-` (e.g. `-c100` or a platform-specific flag), which an array-based fix does not address on its own. Here the application defines the value's format - it is documented as a network host to ping, which is exactly a DNS hostname or IP literal - so a strict allowlist is not a security-only regression: `VALID_HOST` requires the string to start and end with an alphanumeric character and permits only letters, digits, `.`, `:`, and `-` in between, which covers RFC 1123 hostnames and IPv4/IPv6 literals, rejects anything starting with `-`, and rejects every shell metacharacter and space. The length cap (253) matches the DNS hostname limit and rejects pathological inputs before they reach `exec`.

Rejected inputs return `400 Bad Request` rather than being silently stripped or truncated, so a malformed value is refused instead of being coerced into a different, unintended valid host.
