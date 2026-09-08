## Verdict
Confirmed CWE-78 (OS Command Injection). User-supplied `count` and `host` parameters are concatenated into a shell command string and passed to `cmd.exe /c`, allowing shell metacharacter injection.

## Source
- **File**: DiagnosticController.java
- **Line**: 25–28
- **Issue**: Parameters are concatenated into `diagnosticCommand` and passed as a shell string to `ProcessBuilder("cmd.exe", "/c", diagnosticCommand)`, where `cmd.exe` parses the string for shell metacharacters.
- **Attack vector**: An attacker can inject commands through the `host` parameter (e.g., `example.com & del /s /q C:\`).

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

        // Validate count is a positive integer to prevent option injection
        int countValue;
        try {
            countValue = Integer.parseInt(count);
            if (countValue <= 0 || countValue > 100) {
                return "Error: count must be between 1 and 100";
            }
        } catch (NumberFormatException e) {
            return "Error: count must be a valid integer";
        }

        // Pass arguments separately to ProcessBuilder to avoid shell metacharacter
        // interpretation. Calling ping.exe directly (not through cmd.exe) eliminates
        // the shell interpreter and closes the command injection sink.
        Process process = new ProcessBuilder("ping.exe", "-n", String.valueOf(countValue), host).start();

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
The fix addresses CWE-78 through two key changes:

1. **Input validation**: Validate `count` as a positive integer and constrain it to a safe range (1–100). This prevents option injection through the count parameter (e.g., passing `-l 65500` to cause a packet flood).

2. **Argument array instead of shell string**: Replace `ProcessBuilder("cmd.exe", "/c", diagnosticCommand)` with `ProcessBuilder("ping.exe", "-n", countValue, host)`. Passing arguments as separate array elements to `ProcessBuilder` avoids shell parsing. Calling `ping.exe` directly (not through `cmd.exe` with `/c`) eliminates the shell interpreter altogether, so shell metacharacters in the `host` parameter (like `&`, `|`, `>`) are passed as literal arguments to ping.exe, which ignores them.

The remediated code prevents an attacker from injecting commands through the `host` or `count` parameters.
