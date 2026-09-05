## Verdict

**Exploitable**

The `host` parameter is directly concatenated into a command string and passed to `Runtime.getRuntime().exec(String)`. Although `exec(String)` tokenizes the string into arguments using `StringTokenizer`, shell metacharacters and pipes in the input allow arbitrary OS command execution. For example, a host value of `127.0.0.1; rm -rf /` would execute both the ping command and the destructive command.

## Source

User-supplied input: `request.getParameter("host")` at line 23, passed directly into the command string at line 48 via string concatenation without validation or escaping.

## Fix

Replace the single-string command invocation with `Runtime.exec(String[])` using separate arguments, and add input validation to prevent option injection.

**Original vulnerable code (line 48-50):**
```java
String command = "ping -c " + PING_COUNT + " " + host;
Process process = Runtime.getRuntime().exec(command);
```

**Fixed code:**
```java
// Validate host to prevent option injection (values starting with -)
if (host.startsWith("-")) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Host parameter must not start with '-'");
    return;
}

String[] command = {"ping", "-c", String.valueOf(PING_COUNT), host};
Process process = Runtime.getRuntime().exec(command);
```

## Explanation

`Runtime.exec(String)` with a concatenated command string is vulnerable to OS command injection because the shell interprets metacharacters in the input. The fix uses `Runtime.exec(String[])` (or equivalently, `ProcessBuilder` with a list) to pass the command and its arguments separately, preventing the shell from interpreting special characters in the `host` parameter as command separators or redirects.

The input validation rejects values starting with `-` to prevent argument injection, where a malicious host value like `-e /bin/sh` could be misinterpreted as a flag by the `ping` command itself. This is a secondary defence layer that complements the parameterized execution.

## Behaviour changes

- Command execution now uses an argument array instead of shell string parsing, eliminating shell metacharacter interpretation
- Input validation adds a check that rejects host values starting with `-`, preventing option/flag injection into the ping command
- Return value and output handling remain unchanged: stdout is still captured and returned to the client
- Error handling remains unchanged: `InterruptedException` and `IOException` propagate as before
