## Verdict

Confirmed. The finding is exploitable. Line 50 calls `Runtime.getRuntime().exec(command)` with a single concatenated string incorporating the untrusted `host` parameter. The single-string overload of `Runtime.exec()` is tokenized via StringTokenizer (whitespace splitting) and is unreliable for command construction.

## Source

The `host` parameter originates from the HTTP request at line 23: `String host = request.getParameter("host")`. Although basic null/empty validation occurs at lines 24-27, this does not prevent OS command injection. The validated host is directly concatenated into a command string at line 48:

```java
String command = "ping -c " + PING_COUNT + " " + host;
```

This concatenated string is then passed to the single-string overload of Runtime.exec() at line 50, enabling command injection if the host contains shell metacharacters or flags.

## Fix

Replace the single-string Runtime.exec() call with ProcessBuilder, passing arguments as a separate list. Insert the `--` literal before the host argument to prevent it from being interpreted as a flag by ping.

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
     * its captured stdout. Arguments are passed as a list to ProcessBuilder,
     * preventing shell injection and argument injection (via the -- marker).
     */
    private String runPing(String host) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", String.valueOf(PING_COUNT), "--", host);
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

The original code used `Runtime.getRuntime().exec(String)`, which tokenizes its single argument using StringTokenizer and is unreliable and deprecated as of Java 18. This approach creates an exploitable injection point.

The fix replaces it with ProcessBuilder, passing the command and its arguments as separate list elements. This prevents shell metacharacter injection because the arguments are not re-parsed by a shell. The `--` literal inserted before the host argument serves as an end-of-options marker (supported by standard ping implementations), preventing any value—including one beginning with `-`—from being interpreted as a command-line flag, thereby closing CWE-88 argument injection as well.

The fix preserves the original behavior: capturing and returning the stdout output from the ping command to the response.

## Behaviour changes

The fix adds the `--` flag before the host argument in the ping command line. This is a standard end-of-options marker recognized by modern ping implementations and has no impact on the command's output when the host is a legitimate hostname or IP address. If a host value begins with `-` (which was previously a command injection vector), it will now be treated as a literal hostname instead of being interpreted as a flag.
