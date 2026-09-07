## Verdict

exploitable

## Source

`request.getParameter("host")` (line 23) — untrusted HTTP parameter, attacker-controlled

## Fix

**Vulnerable code (line 47-50):**

```java
private String runPing(String host) throws IOException, InterruptedException {
    String command = "ping -c " + PING_COUNT + " " + host;
    // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
    Process process = Runtime.getRuntime().exec(command);
```

**Fixed code:**

```java
private String runPing(String host) throws IOException, InterruptedException {
    // Validate host to prevent argument injection and command injection
    if (host == null || host.isEmpty() || host.startsWith("-") || !host.matches("[a-zA-Z0-9.-]+")) {
        throw new IllegalArgumentException("Invalid hostname");
    }
    
    // Use ProcessBuilder with separate arguments instead of string concatenation
    ProcessBuilder pb = new ProcessBuilder("ping", "-c", String.valueOf(PING_COUNT), host);
    Process process = pb.start();
```

## Explanation

The original code concatenates the untrusted `host` parameter directly into a command string, then passes it to `Runtime.exec(String)`. This is vulnerable to argument injection: an attacker can supply input like `"example.com -l 999"` to inject additional flags, or `"example.com; id"` to attempt command chaining. The single-string overload of `Runtime.exec()` tokenizes its argument with `StringTokenizer`, which cannot distinguish between separate intended arguments and injected ones.

The fix uses `ProcessBuilder` with separate argument array elements (`ping`, `-c`, count, hostname), which prevents the shell and the runtime from re-interpreting the hostname as containing options or commands. Validation rejects hostnames starting with `-` (preventing flag injection) and permits only alphanumeric characters, dots, and hyphens—the valid characters in a hostname. This allowlist validation as a secondary defense ensures that even if the hostname somehow reaches a sink that re-interprets strings, it cannot contain shell metacharacters or option markers.

## Behaviour changes

1. **New exception on invalid input**: Invalid hostnames (null, empty, starting with `-`, or containing characters outside `[a-zA-Z0-9.-]`) now throw `IllegalArgumentException` before process execution. The original code would have passed these to ping, where they would fail at the OS level with no validation feedback. This is a refinement that fails fast and provides clearer error handling.

2. **ProcessBuilder instead of Runtime.exec(String)**: No functional difference; the output, return value, and exception behavior remain the same. `ProcessBuilder` is the recommended modern API and handles argument separation correctly. The deprecated single-string overload is replaced.

3. **Explicit argument list**: Arguments are passed as separate array elements (`ping`, `-c`, count as string, hostname) rather than a single concatenated string. This is a safer API boundary but produces identical ping invocation and output.
