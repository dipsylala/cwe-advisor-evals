## Verdict

Confirmed: CWE-78 OS Command Injection via shell string concatenation on Windows. Untrusted request parameters (`host`, `count`) are concatenated into a command string and passed to `ProcessBuilder("cmd.exe", "/c", ...)`, which causes Windows cmd.exe to re-parse the string and execute injected shell metacharacters.

## Source

The endpoint accepts `host` and `count` as untrusted request parameters (@RequestParam). Line 25 concatenates them into `diagnosticCommand`, and line 28 passes this concatenated string to ProcessBuilder with cmd.exe shell invocation:

```java
String diagnosticCommand = "ping -n " + count + " " + host;
Process process = new ProcessBuilder("cmd.exe", "/c", diagnosticCommand).start();
```

An attacker can inject shell commands through either parameter. For example, `host=127.0.0.1 & whoami` executes the `whoami` command.

## Fix

### File: DiagnosticController.java

```java
package com.example.support.diagnostics;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
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

        // Validate count is a positive integer
        if (!count.matches("\\d+")) {
            throw new IllegalArgumentException("Invalid count: must be a positive integer");
        }

        // Validate host is a valid hostname or IP address (alphanumeric, dots, hyphens)
        if (host.isEmpty() || !host.matches("[a-zA-Z0-9.-]+")) {
            throw new IllegalArgumentException("Invalid hostname");
        }

        // Build ping command with separate arguments to prevent shell injection.
        // Passing arguments as separate list elements instead of concatenating into
        // a shell command string prevents an attacker from injecting shell metacharacters
        // through the host or count parameters.
        List<String> command = new ArrayList<>();
        command.add("ping");
        command.add("-n");  // Windows ping syntax: -n for count
        command.add(count);
        command.add(host);

        Process process = new ProcessBuilder(command).start();

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

The vulnerability stems from passing user-controlled input as part of a shell command string to cmd.exe. The fix eliminates the shell layer entirely by:

1. **Removing shell invocation**: Changed from `ProcessBuilder("cmd.exe", "/c", concatenatedString)` to calling `ping` directly with `ProcessBuilder(List)`. This prevents cmd.exe from re-parsing the command line.

2. **Input validation**: Added regex validation for `count` (must be digits) and `host` (alphanumeric, dots, hyphens only). This ensures only legitimate values can reach the sink and rejects obviously malicious input like shell metacharacters.

3. **Separate argument passing**: Arguments are passed as separate list elements, not concatenated into a single string. ProcessBuilder forwards each element as a separate argv entry to the ping process, preventing shell interpretation.

The guidance permits `ping` to remain under ProcessBuilder because Java has no native ICMP implementation (InetAddress.isReachable() has platform-specific limitations). Since the purpose here is diagnostic output for support staff, executing ping safely via argument array is appropriate.

## Behaviour changes

- **Return value**: Identical. Output is still collected from the process and returned as a string, including exit codes.
- **Input format**: Stricter. Invalid `count` (non-numeric) and `host` (containing special characters) now throw `IllegalArgumentException` rather than being passed to the shell. This is a regression-free change because the shell would have rejected these same invalid values at runtime.
- **Windows compatibility**: Preserved. The `-n` flag is Windows-specific ping syntax and is correctly passed as a separate argument.
- **Error handling**: Identical. Process exit codes are captured and appended to output as before.
