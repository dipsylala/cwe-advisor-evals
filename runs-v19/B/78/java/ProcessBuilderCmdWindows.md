# DiagnosticController - CWE-78 Remediation

## Verdict

Exploitable. The vulnerability allows OS command injection through untrusted request parameters (`host` and `count`) that are concatenated into a shell command and executed via `cmd.exe /c`, which re-parses the command line as shell syntax.

## Source

`@RequestParam("host") String host` and `@RequestParam("count") String count` at line 20-21 are untrusted HTTP request parameters with no validation.

## Fix

### File: DiagnosticController.java

```java
package com.example.support.diagnostics;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
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

    // Pattern to validate count as a positive integer
    private static final Pattern VALID_COUNT = Pattern.compile("^[0-9]+$");

    @GetMapping("/support/diagnostics/ping")
    public String runPingDiagnostic(@RequestParam("host") String host, @RequestParam("count") String count)
            throws IOException, InterruptedException {

        // Validate count parameter - must be a positive integer
        if (!VALID_COUNT.matcher(count).matches()) {
            throw new IllegalArgumentException("Invalid count parameter");
        }

        // Use ProcessBuilder with separate arguments to avoid shell injection
        // On Windows, invoke ping directly instead of through cmd.exe
        Process process = new ProcessBuilder("ping", "-n", count, host).start();

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

The vulnerability existed at line 28 where `ProcessBuilder("cmd.exe", "/c", diagnosticCommand).start()` executed a shell-parsed command string built from untrusted request parameters. On Windows, `cmd.exe /c` causes the shell to re-parse the command line regardless of how ProcessBuilder passes it, enabling shell metacharacter injection through either the `host` or `count` parameters.

The fix eliminates this by invoking `ping` directly as a separate executable with ProcessBuilder argument list: `new ProcessBuilder("ping", "-n", count, host).start()`. Each argument is passed to the `ping` process without shell parsing, preventing shell metacharacter interpretation. The `count` parameter is validated against `^[0-9]+$` to ensure it is a numeric value, preventing argument injection where a malicious count like `"-h"` could be misinterpreted as a flag. The fix preserves the original behavior: same output stream handling, same exit code reporting, same exception propagation.

## Behaviour changes

- **Added validation**: The `count` parameter is now validated to match `^[0-9]+$` (one or more digits). Invalid values throw `IllegalArgumentException`. This prevents argument injection but rejects non-numeric count values that the original code would have passed to ping (e.g., `"abc"` or `"-10"`). 
- **Removed shell invocation**: The command invocation changed from `ProcessBuilder("cmd.exe", "/c", diagnosticCommand)` to `ProcessBuilder("ping", "-n", count, host)`. This eliminates shell parsing and changes the execution path, but preserves the same ping command and output behavior. Process output and exit code handling remain identical.
- **Added import**: `java.util.regex.Pattern` was imported to support the validation pattern.
