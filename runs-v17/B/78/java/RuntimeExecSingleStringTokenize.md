## Verdict

Exploitable. The `host` parameter from the HTTP request is concatenated directly into a command string and passed to `Runtime.getRuntime().exec(String)`, which tokenizes the string using `StringTokenizer`. An attacker can inject OS command separators or arguments by providing a specially crafted host value.

## Source

Untrusted input from HTTP request parameter `host` at line 23:
```
String host = request.getParameter("host");
```

This value is concatenated into the command string at line 48 without validation or escaping:
```
String command = "ping -c " + PING_COUNT + " " + host;
```

## Fix

Replace the vulnerable `Runtime.exec(String)` call with `ProcessBuilder` using separate argument array, and add input validation:

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
        } catch (IllegalArgumentException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
            return;
        }

        response.setContentType("text/plain");
        response.getWriter().write(output.toString());
    }

    /**
     * Runs the platform ping utility against the requested host and returns
     * its captured stdout.
     */
    private String runPing(String host) throws IOException, InterruptedException {
        // Validate host input to prevent injection attacks
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("Host cannot be empty");
        }
        
        // Allow only alphanumeric characters, dots, hyphens, and colons (for IPv6)
        if (!host.matches("[a-zA-Z0-9.:-]+")) {
            throw new IllegalArgumentException("Invalid host format");
        }
        
        // Reject if starts with dash to prevent argument injection (CWE-88)
        if (host.startsWith("-")) {
            throw new IllegalArgumentException("Host cannot start with a dash");
        }
        
        // Use ProcessBuilder with separate arguments instead of concatenated string
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

The fix eliminates the command injection vulnerability by replacing `Runtime.getRuntime().exec(String)` with `ProcessBuilder` using separate string array arguments. Key changes:

1. **ProcessBuilder with argument array**: Instead of concatenating the host into a single command string, each component (`"ping"`, `"-c"`, the count, and the host) is passed as a separate element in the argument array. This prevents shell interpretation of special characters in the host value.

2. **Input validation**: Added strict validation that rejects any host value containing characters other than alphanumeric, dots, hyphens, and colons (necessary for IPv6 addresses and domain names). Additionally, rejects any host starting with a dash to prevent argument injection attacks (CWE-88).

3. **Error handling in servlet**: Updated the servlet's `doGet` method to catch `IllegalArgumentException` and return a 400 Bad Request response, providing feedback to the caller without exposing internal details.

4. **Updated documentation**: Removed the outdated comment claiming the single string was necessary, as `ProcessBuilder` naturally handles multiple arguments.

The `ProcessBuilder` API with separate arguments prevents shell interpretation while maintaining the original functionality of returning the ping command's output to the caller.

## Behaviour changes

- Invalid host parameters (containing special characters or starting with dash) now result in an HTTP 400 Bad Request response instead of being passed to the ping command.
- The command is no longer subject to shell metacharacter interpretation.
- All other behaviour (ping count, output capture, timing) remains identical to the original implementation.
