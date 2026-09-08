## Verdict
Confirmed. The vulnerability is OS command injection through unsanitized concatenation of user input into a command string passed to `Runtime.getRuntime().exec(String)`.

## Source
Line 48–50 in PingDiagnosticServlet.java. The `host` parameter from `request.getParameter("host")` is concatenated directly into a single command string, which is then passed to `Runtime.getRuntime().exec(command)`. The string-based overload of `exec()` uses an internal string tokenizer that does not properly isolate arguments, allowing shell metacharacters in the `host` parameter to break out and execute arbitrary OS commands.

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
     * its captured stdout. The command is passed as an array of separate
     * arguments to bypass shell interpretation and prevent command injection.
     */
    private String runPing(String host) throws IOException, InterruptedException {
        String[] command = {"ping", "-c", String.valueOf(PING_COUNT), host};
        Process process = Runtime.getRuntime().exec(command);

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
The vulnerability is fixed by replacing the single string command with a string array passed to `Runtime.getRuntime().exec(String[])`. When `exec()` receives an array, each element is passed as a separate argument directly to the process without shell interpretation. This prevents shell metacharacters in the `host` parameter from being interpreted as command operators or terminators. The `PING_COUNT` integer is converted to a string using `String.valueOf()` to match the array element type. The comment is updated to reflect the change in approach.
