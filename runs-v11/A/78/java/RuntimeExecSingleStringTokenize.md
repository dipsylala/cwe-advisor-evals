## Verdict

Real vulnerability. The code passes a command as a single string to `Runtime.getRuntime().exec()`, and the `host` parameter is concatenated directly from untrusted user input without validation. When a single string is passed to `exec()`, Java's tokenization logic can be exploited by shell metacharacters in the `host` value to inject additional commands.

## Source

**File:** `evals/cases/78/java/RuntimeExecSingleStringTokenize/PingDiagnosticServlet.java`  
**Lines:** 48-50

```java
String command = "ping -c " + PING_COUNT + " " + host;
// SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
Process process = Runtime.getRuntime().exec(command);
```

The `host` parameter originates from `request.getParameter("host")` (line 23), flows directly into the command string at line 48, and is passed as a single string to `exec()` at line 50. An attacker can inject shell metacharacters to break out of the intended command.

## Fix

Replace the single-string invocation with an argument array, and validate the `host` parameter to a safe format:

```java
private String runPing(String host) throws IOException, InterruptedException {
    // Validate host is a valid hostname or IPv4/IPv6 address
    if (!host.matches("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$|^\\d{1,3}(\\.\\d{1,3}){3}$|^\\[?[0-9a-f:]+\\]?$")) {
        throw new IllegalArgumentException("Invalid host format");
    }
    
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

The validation regex accepts:
- Hostnames with alphanumeric characters and hyphens (not starting or ending with hyphen)
- IPv4 addresses (four dot-separated octets)
- IPv6 addresses in bracket notation

Reject any host value that doesn't match one of these patterns. Alternatively, use a library like `java.net.InetAddress.getByName()` to resolve the host first, which validates format and rejects injection attempts.

## Explanation

`Runtime.getRuntime().exec(String)` tokenizes the single command string using a simplistic parser that splits on whitespace. This parser does not handle or escape shell metacharacters, making it vulnerable to injection when user-controlled data is concatenated into the string.

The correct defense is to pass arguments as a separate array: `exec(String[])`. This avoids tokenization of user input and ensures each argument is passed to the target process exactly as provided—the `ping` binary receives `host` as a literal string, not as a shell-parsed operand.

Input validation on the `host` parameter adds a secondary defence: it ensures only valid hostnames and IP addresses reach the command, preventing any attempt to inject semicolons, pipes, or other shell constructs. The regex pattern is permissive enough to accept both bare hostnames (e.g., `example.com`, `10.0.0.1`) and IPv6 addresses in bracket form (e.g., `[::1]`), covering the diagnostic use case while rejecting attacker-supplied payloads like `8.8.8.8; rm -rf /`.

Also update the caller (line 31) to handle the `IllegalArgumentException`:

```java
try {
    output.append(runPing(host));
} catch (IllegalArgumentException e) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid host format");
    return;
} catch (InterruptedException e) {
    Thread.currentThread().interrupt();
    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Ping interrupted");
    return;
}
```
