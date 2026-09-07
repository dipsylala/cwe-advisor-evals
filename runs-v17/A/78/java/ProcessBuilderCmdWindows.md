## Verdict
VULNERABLE. Line 28 constructs a shell command by concatenating untrusted user input (`host` and `count` parameters), then executes it via `ProcessBuilder` with `/c`. An attacker can inject shell metacharacters (e.g., `&`, `|`, `&&`) or commands into either parameter to execute arbitrary Windows commands.

## Source
**File:** `DiagnosticController.java`  
**Vulnerable Code (lines 25-28):**
```java
String diagnosticCommand = "ping -n " + count + " " + host;
Process process = new ProcessBuilder("cmd.exe", "/c", diagnosticCommand).start();
```

**Attack Example:**
- Request: `GET /support/diagnostics/ping?host=google.com%20%26%20dir%20C:%5C&count=4`
- Interpreted as: `ping -n 4 google.com & dir C:\`
- Result: Both `ping` and `dir C:\` execute

## Fix
### File: DiagnosticController.java
```java
package com.example.support.diagnostics;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Support-desk diagnostic endpoint. Lets a helpdesk operator kick off a
 * network reachability check against a customer-reported host without
 * needing shell access to the Windows app server.
 */
@RestController
public class DiagnosticController {

    @GetMapping("/support/diagnostics/ping")
    public String runPingDiagnostic(@RequestParam("host") String host, @RequestParam("count") String count)
            throws IOException, InterruptedException {

        // Pass arguments directly to the ping executable without shell interpretation.
        // This prevents command injection via shell metacharacters in the host or count parameters.
        Process process = new ProcessBuilder("ping.exe", "-n", count, host).start();

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
}
```

## Explanation
The fix eliminates OS command injection by passing arguments directly to `ProcessBuilder` as a list instead of constructing a shell command string. The key changes are:

1. **Removed shell invocation:** Changed from `ProcessBuilder("cmd.exe", "/c", concatenatedString)` to `ProcessBuilder("ping.exe", "-n", count, host)`. This calls the `ping.exe` executable directly without invoking a shell interpreter.

2. **Argument array prevents metacharacter interpretation:** When arguments are passed as array elements rather than as part of a single command string, the OS does not interpret shell metacharacters like `&`, `|`, `&&`, or `>` as operators. Each element is treated as a literal argument value.

3. **No string concatenation:** User input (`host` and `count`) is no longer concatenated into a command string. They are passed as individual arguments that cannot be used to inject additional commands or shell syntax.

The attack example from the Source section would now fail: the `count` value `"4"` would be treated as a literal string argument, and the `host` value `"google.com & dir C:\"` would be treated as a single hostname argument (which ping would reject as invalid, but without executing the injected `dir` command).
