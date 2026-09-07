## Verdict
VULNERABLE - CWE-78 confirmed on line 50. Concatenating unsanitized user input into a command string passed to `Runtime.getRuntime().exec(String)` allows command injection through shell metacharacters and tokenization artifacts.

## Source
`host` parameter from `request.getParameter("host")` on line 23 is concatenated into the command string on line 48 without validation, then executed on line 50.

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

        // Validate host to prevent command injection
        if (!host.matches("^[a-zA-Z0-9\\-._:]+$")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid host format");
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
     * its captured stdout. Command arguments are passed as an array to prevent
     * shell interpretation of special characters.
     */
    private String runPing(String host) throws IOException, InterruptedException {
        // Use array form of exec() to avoid shell interpretation
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
The fix eliminates the vulnerability through two complementary defences:

1. **Input Validation (line 29-32)**: The `host` parameter is validated against a whitelist pattern `^[a-zA-Z0-9\\-._:]+$` that accepts only characters valid in hostnames and IPv6 addresses (alphanumerics, hyphens, dots, underscores, colons). This rejects shell metacharacters and spaces that could alter command structure.

2. **Array-Based Command Execution (line 54)**: The `exec(String[])` method is used instead of `exec(String)`. Each argument is passed as a separate array element, preventing the `StringTokenizer` from parsing special characters and eliminating shell interpretation. The command becomes `["ping", "-c", "4", host]` where `host` is treated as a literal argument value regardless of its content.

Combined, these changes ensure that even if validation were bypassed, the array form would treat attacker-supplied characters as literal argument text, not command syntax.
