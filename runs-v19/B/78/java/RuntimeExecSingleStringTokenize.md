## Verdict

OS Command Injection confirmed. The `host` parameter from the HTTP request is directly concatenated into a command string passed to `Runtime.exec()`, allowing arbitrary command execution.

## Source

`host` parameter from HTTP request (line 23: `request.getParameter("host")`)

## Fix

Replace the vulnerable `Runtime.exec(String)` call with `ProcessBuilder` using separate argument array elements:

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
     * its captured stdout. The command is executed as a separate argument array
     * to prevent shell injection, with the host as its own argument element.
     */
    private String runPing(String host) throws IOException, InterruptedException {
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

The vulnerability stems from constructing a shell command as a single concatenated string. While `Runtime.exec(String)` does tokenize the input using `StringTokenizer`, this approach is deprecated and problematic because: (1) the tokenizer splits on whitespace, which does not protect against shell metacharacters like `;`, `|`, or backticks in the host value; (2) more importantly, the original concatenated string approach remains exploitable even with tokenization.

The fix replaces the vulnerable pattern with `ProcessBuilder`, passing the command and its arguments as separate list elements. This prevents the host value from being interpreted by the shell. The command `ProcessBuilder("ping", "-c", "4", host)` passes each element as its own argument to the `ping` process, preventing injection of additional commands or flags. The `String.valueOf(PING_COUNT)` ensures the integer count is properly converted to a string argument.

The fix preserves the original functionality: the ping command executes identically, stdout is captured and returned, and error handling remains the same.

## Behaviour changes

None. The process output, return value, and error handling remain unchanged. The only change is the mechanism of command invocation, which closes the injection without altering the observable behavior.
