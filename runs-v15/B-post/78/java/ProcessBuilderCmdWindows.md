## Verdict

**Vulnerable.** The code is exploitable; a fix is provided.

## Source

The `host` and `count` request parameters enter the endpoint without validation and are directly incorporated into the diagnostic command:

```java
@RequestParam("host") String host
@RequestParam("count") String count
```

An attacker can supply malicious values such as `host=8.8.8.8 & del /s /q C:\` to inject additional commands.

## Fix

```java
@GetMapping("/support/diagnostics/ping")
public String runPingDiagnostic(@RequestParam("host") String host, @RequestParam("count") String count)
        throws IOException, InterruptedException {

    // Validate and parse count as integer
    int pingCount;
    try {
        pingCount = Integer.parseInt(count);
        if (pingCount < 1 || pingCount > 4) {
            throw new IllegalArgumentException("Count must be between 1 and 4");
        }
    } catch (NumberFormatException e) {
        throw new IllegalArgumentException("Count must be a valid integer", e);
    }

    // Validate host - reject empty or dash-prefixed values to prevent argument injection
    if (host == null || host.trim().isEmpty() || host.startsWith("-")) {
        throw new IllegalArgumentException("Invalid host parameter");
    }

    // Call ping.exe directly with separate arguments, avoiding cmd.exe shell injection vector
    Process process = new ProcessBuilder("ping.exe", "-n", String.valueOf(pingCount), host).start();

    StringBuilder output = new StringBuilder();
    try (BufferedReader reader =
            new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append(System.lineSeparator());
        }
    }

    int exitCode = process.waitFor();
    if (exitCode != 0) {
        output.append("ping exited with code ").append(exitCode);
    }

    return output.toString();
}
```

## Explanation

The original code passed user-supplied parameters to `ProcessBuilder` in a concatenated command string that was then executed through `cmd.exe /c`. Although `ProcessBuilder` is used (which is safer than `Runtime.exec(String)`), the Windows shell (`cmd.exe`) re-parses the entire command line passed as its third argument, allowing shell metacharacters like `&`, `|`, and `>` to be interpreted as command separators and redirects.

This fix eliminates the shell invocation by calling `ping.exe` directly with separate argument array elements. `ProcessBuilder` with a list argument prevents both shell metacharacter injection and provides clear separation between the command and its arguments. The fix also adds input validation:

- `pingCount` is parsed and constrained to a valid range (1-4), preventing malformed or excessive pings
- `host` is validated to reject empty values and values starting with `-` (which could be interpreted as flags, introducing CWE-88 argument injection)

The code preserves the original behavior: it still runs the ping command and returns its output and exit code to the caller.

## Behaviour changes

- **Input validation:** The endpoint now rejects invalid `count` values (non-integer or out of range) and invalid `host` values (empty or flag-like), returning HTTP 400 errors instead of attempting execution
- **Command execution:** The endpoint no longer invokes `cmd.exe`, eliminating the shell re-parsing step that enabled command injection
- **Output:** Unchanged - the endpoint still returns ping output and exit codes
- **Error handling:** Validation errors now throw `IllegalArgumentException`, which will produce HTTP 500 responses unless a Spring exception handler is configured; consider adding a `@ExceptionHandler` method to return HTTP 400 for these validation failures
