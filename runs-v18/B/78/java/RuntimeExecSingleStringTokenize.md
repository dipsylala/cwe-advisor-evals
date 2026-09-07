## Verdict

Exploitable

## Source

Line 23: `String host = request.getParameter("host")`

Untrusted HTTP request parameter flows directly into command construction without validation.

## Fix

### File: PingDiagnosticServlet.java

```java
package com.example.netops.web;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
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

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String host = request.getParameter("host");
        if (host == null || host.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing 'host' parameter");
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
     * its captured stdout. Uses ProcessBuilder with separate arguments to
     * prevent command injection and validates the host to prevent argument injection.
     */
    private String runPing(String host) throws IOException, InterruptedException {
        // Validate that host doesn't start with a dash to prevent argument injection (CWE-88)
        if (host.startsWith("-")) {
            throw new IllegalArgumentException("Host must not start with a dash");
        }
        
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", String.valueOf(PING_COUNT), host);
        Process process = pb.start();

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

The original code constructed a command string by concatenating the untrusted `host` parameter directly into the command. `Runtime.exec(String)` tokenizes this concatenated string using `StringTokenizer` on whitespace, making it vulnerable to argument injection: a host value like `"example.com -X"` would result in additional flags being passed to ping. The fix replaces `Runtime.exec(String)` with `ProcessBuilder` initialized with separate arguments as an array. This prevents both shell-metacharacter injection and the tokenization issue, since the arguments are passed directly to the OS without string parsing. Additionally, the fix validates the host parameter to reject values starting with a dash, which prevents CWE-88 argument-injection attacks where the attacker could inject ping flags. The validation uses a simple prefix check appropriate to the usage pattern - hostnames and IP addresses never start with a dash, so rejecting these values has no impact on legitimate inputs.

## Behaviour changes

**Validation addition**: The method now throws `IllegalArgumentException` if the host parameter starts with a dash. This is a security-necessary change: the original code would silently allow such values and pass them to ping as flags. The exception is thrown before process creation, so it provides fail-fast feedback. This is an expected and necessary change to close CWE-88 argument injection.

**No functional regression**: The return value, error handling, and output collection remain identical. The method still returns the captured stdout as a String, and `process.waitFor()` ensures proper process synchronization.

