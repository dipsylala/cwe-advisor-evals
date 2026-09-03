## Verdict

Exploitable. The `host` parameter from the HTTP request is concatenated directly into a command string and passed to `Runtime.exec()` without validation. An attacker can inject shell metacharacters or additional commands (e.g., `host=8.8.8.8; rm -rf /` or `host=8.8.8.8 && malicious-command`) to execute arbitrary OS commands on the server.

## Source

`request.getParameter("host")` at line 23 in `doGet()`, assigned to the `host` variable.

## Fix

**Vulnerable code (lines 21-50):**

```java
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

private String runPing(String host) throws IOException, InterruptedException {
    String command = "ping -c " + PING_COUNT + " " + host;
    // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
    Process process = Runtime.getRuntime().exec(command);
    // ... rest of method
}
```

**Fixed code:**

```java
@Override
protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    String host = request.getParameter("host");
    if (host == null || host.isEmpty()) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing 'host' parameter");
        return;
    }

    // Validate host parameter - only allow alphanumeric characters, dots, and hyphens (valid in hostnames and IPv4 addresses)
    if (!host.matches("[a-zA-Z0-9.-]+")) {
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

private String runPing(String host) throws IOException, InterruptedException {
    // Use array form with separate arguments instead of a concatenated string to prevent shell interpretation
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
```

## Explanation

The fix eliminates CWE-78 OS Command Injection through two complementary defenses. First, input validation at the entry point (line 31-34) rejects any `host` value containing characters outside the set `[a-zA-Z0-9.-]`, which covers all valid characters in hostnames and IPv4 addresses while preventing shell metacharacters, command separators, and leading dashes that could be interpreted as flags. Second, the `runPing()` method is changed from `Runtime.exec(String)` (which tokenizes the input using `StringTokenizer`, making shell interpretation possible) to `Runtime.exec(String[])` with an array of separate arguments. Array-form execution does not invoke a shell parser, so even if validation were bypassed, shell metacharacters in the arguments would be treated as literal characters, not operators. The validated `host` value is passed as a trusted argument after validation confirms it matches the allowlist pattern.

## Behaviour changes

The response now returns HTTP 400 Bad Request if the `host` parameter contains any character outside `[a-zA-Z0-9.-]`. This rejects malformed input (e.g., hostnames with spaces, wildcards, or shell metacharacters) but does not alter the behavior for valid hostnames and IPv4 addresses. The ping process execution is unchanged in its output and return values - the same stdout is captured, buffered, and returned to the caller. No implicit arguments or defaults are altered.
