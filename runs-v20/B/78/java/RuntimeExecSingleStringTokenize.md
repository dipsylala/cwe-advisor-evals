## Verdict

exploitable

- cwe_id: CWE-78
- location: `PingDiagnosticServlet.java`, line 50 (sink); command built at line 48
- confidence: high

## Source

`request.getParameter("host")` in `doGet` (line 23). The value is attacker-controlled (any HTTP GET query parameter), has no validation applied before use, and flows unchanged into `runPing(host)` (line 31), which concatenates it directly into a single command string (line 48) passed to `Runtime.getRuntime().exec(command)` (line 50).

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
    private static final String PING_EXECUTABLE = "/bin/ping";

    // Hostnames (RFC 1123), IPv4 literals, and IPv6 literals only: letters,
    // digits, '.', ':' and '-', and never starting with '-' so the value
    // cannot be read as a flag by ping even without the "--" guard below.
    private static final Pattern HOST_PATTERN =
            Pattern.compile("^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String host = request.getParameter("host");
        if (host == null || host.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing 'host' parameter");
            return;
        }
        if (!HOST_PATTERN.matcher(host).matches()) {
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
     * its captured stdout. The command is built as an argument list, with a
     * literal "--" marking the end of options, so the host value is always
     * taken as ping's destination operand and never as a flag or as input to
     * a shell.
     */
    private String runPing(String host) throws IOException, InterruptedException {
        ProcessBuilder builder = new ProcessBuilder(
                PING_EXECUTABLE, "-c", String.valueOf(PING_COUNT), "--", host);
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

Ping is the feature this endpoint exists to provide, and no Java standard library API performs an ICMP echo the way `ping` does (`InetAddress.isReachable()` falls back to a TCP connect that misreports hosts with the relevant port closed), so the remediation keeps command execution and makes it safe rather than replacing it. `Runtime.exec(String)` tokenized the concatenated string with `StringTokenizer` and, being a single-string overload, offered no boundary between the fixed flags and the attacker-controlled host - a value like `x; rm -rf /` or `x $(reboot)` became additional shell-style tokens once handed to `exec`. The fix replaces it with `ProcessBuilder` given a fixed argument list (`/bin/ping`, `-c`, `4`, `--`, host), so the host value is always a single argv element and is never re-parsed by a shell; the executable is invoked by its absolute path so a writable `PATH` entry cannot substitute a different binary. A literal `--` precedes the host argument so a value starting with `-` (e.g. `-c1000000`) is taken by `ping` as the end of options rather than as an additional flag, closing the argument-injection gap (CWE-88) that an argument array alone does not close. A hostname/IP-literal allowlist (`HOST_PATTERN`, matched with `Matcher.matches()` so a trailing newline cannot slip past the anchors) is applied as a secondary, defense-in-depth layer before the value ever reaches the sink, since the application owns "a value that names a host" as its expected format.

## Behaviour changes

- Requests whose `host` value does not match the hostname/IPv4/IPv6 character set (`[A-Za-z0-9][A-Za-z0-9.:-]*`) now receive `400 Bad Request` instead of being passed to `ping`. Previously such a value (e.g. one containing an underscore, which is common in some internal DNS names but is not a valid RFC 1123 hostname character) would have reached `ping` and produced whatever output/error `ping` itself returned. This is an intentional narrowing of accepted input to the format the application actually needs (a ping target), and it also rejects the injection payloads the finding is about; it does not change behaviour for any well-formed hostname or IP literal.
- `ping` is now invoked by absolute path `/bin/ping` instead of via `PATH` lookup. On a host where `ping` is not present at `/bin/ping` (some systems only ship `/usr/bin/ping`, though on most modern Linux distributions `/bin` is a symlink to `/usr/bin`), the servlet would now fail to start the process where it previously would have found it via `PATH`. This is called out explicitly under Assumptions below.
- All other aspects of the sink contract are unchanged: the method still returns stdout as a `String` (stderr is still not captured/merged, matching the original - no new information leak), `PING_COUNT` is still hard-coded to 4, `InterruptedException`/`IOException` propagate the same way, and `process.waitFor()` is still called before returning.

## Assumptions

- The deployment target is Linux (the original code's `-c` count flag is POSIX/GNU `ping` syntax, not Windows `ping -n`, so this was already implicit in the unfixed code).
- `/bin/ping` is the correct absolute path for the target system's `ping` binary. If the actual deployment places it elsewhere (e.g. only `/usr/bin/ping` on a non-usrmerge system), `PING_EXECUTABLE` needs to be adjusted to match; this could not be verified without knowing the target OS/distribution.
- The system `ping` implementation honors a literal `--` as an end-of-options marker (true for GNU/iputils and BSD `ping`, which use standard `getopt`-style parsing). If the deployment uses a `ping` built on a non-standard argument parser that does not recognize `--`, that specific guard would not apply, though the hostname allowlist and the fixed argument list still prevent shell injection.
- Verification: the fixed file was copied to a scratch directory (outside the repository and outside the case directory) alongside a `javax.servlet-api` jar and compiled with `javac -cp javax.servlet-api-4.0.1.jar`. It compiled cleanly with no errors or warnings. Every new name used (`ProcessBuilder`, `java.util.regex.Pattern`, `Pattern.compile`, `Matcher.matches`, `String.valueOf`) is `java.lang`/`java.util.regex` standard library, confirmed present by successful compilation.
