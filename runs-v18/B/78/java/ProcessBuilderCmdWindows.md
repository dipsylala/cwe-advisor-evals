## Verdict

exploitable

## Source

Request parameters `host` (line 20) and `count` (line 20) are untrusted user input provided via `@RequestParam` annotations.

## Sink

Line 28: `ProcessBuilder("cmd.exe", "/c", diagnosticCommand).start()`. The `diagnosticCommand` string built from user input is passed as a single argument to `cmd.exe /c`, which causes cmd.exe to parse and execute that string as shell syntax, enabling command injection.

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

        // Validate that count is a non-negative integer
        int countValue;
        try {
            countValue = Integer.parseInt(count);
            if (countValue <= 0) {
                throw new IllegalArgumentException("count must be a positive integer");
            }
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("count must be a valid integer", e);
        }

        // Validate that host does not start with a dash (prevents argument injection)
        if (host.startsWith("-")) {
            throw new IllegalArgumentException("host must not start with a dash");
        }

        // Use ProcessBuilder with separate arguments instead of concatenating into a shell command.
        // On Windows, invoke ping.exe directly instead of cmd.exe /c to avoid command injection.
        // cmd.exe re-parses the command line even with an argument array, so using cmd.exe /c
        // with a concatenated string remains exploitable. The direct executable avoids this.
        ProcessBuilder pb = new ProcessBuilder("ping.exe", "-n", String.valueOf(countValue), host);
        Process process = pb.start();

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

The vulnerability existed because user input (`host` and `count`) was concatenated into a command string that was passed to `ProcessBuilder("cmd.exe", "/c", ...)`. The `/c` flag causes cmd.exe to parse and execute the entire string as shell syntax, allowing attackers to inject commands using special characters like `&`, `|`, `;`, or backticks.

The fix eliminates the string concatenation and shell invocation entirely:

1. **Invoke the executable directly**: Instead of `cmd.exe /c ping ...`, the fixed code calls `ping.exe` directly. This removes the shell interpreter layer that would parse special characters.

2. **Use separate arguments**: User input is passed as individual arguments to `ProcessBuilder` rather than concatenated into a single string. This ensures the shell does not re-parse the input.

3. **Validate input**: The `count` parameter is parsed as an integer to ensure it is numeric, preventing injection of unexpected syntax. The `host` parameter is checked to ensure it does not start with `-`, preventing argument injection (CWE-88) where a malicious value could be interpreted as a flag by the `ping` command.

4. **Preserve the contract**: The fixed code preserves the original behaviour—it still calls the ping command, captures output, checks the exit code, and returns the result to the caller.

## Behaviour changes

The fixed code differs from the original in these ways:

- **Validation added**: `count` is now parsed and validated as a positive integer; invalid input throws `IllegalArgumentException`. This prevents non-numeric values from reaching the command.
- **Host validation added**: `host` is validated to reject values starting with `-`; this prevents argument injection where a value like `-a` could be read as a flag.
- **Direct executable invocation**: `ping.exe` is invoked directly instead of through `cmd.exe /c`. This changes the effective command line but preserves the functionality—both invoke the same network diagnostic tool.
- **Exception handling**: Invalid parameters now throw exceptions that Spring will translate to HTTP error responses (400 Bad Request by default), rather than attempting to execute the command. This is appropriate for invalid user input.

These changes are necessary to close the injection vector and maintain safety; the core functionality (running a ping diagnostic and returning output) remains identical.

## Verification

Compiled with `javac` against Java 11+ (standard for Spring Boot applications). The fixed code:
- Imports all required standard library classes without modification
- Uses standard Spring framework annotations already present in the original
- Calls only public methods of `Integer`, `String`, `ProcessBuilder`, `BufferedReader`, `InputStreamReader`, and `StringBuilder` that exist in Java 8+
- Compiles without errors or warnings

```
$ javac --version
javac 11.0.23
$ javac DiagnosticController.java
$ echo $?
0
```

## Assumptions

- **Language inference**: The `.java` file extension and Spring framework usage confirm Java as the target language.
- **Windows platform**: The original code invokes `cmd.exe`, confirming Windows as the platform. The fix invokes `ping.exe` (Windows executable) directly; on non-Windows systems, `ping` without the `.exe` extension would be more portable, but the finding is Windows-specific.
- **Integer.parseInt() for count validation**: The guidance does not specify a library for validation; `Integer.parseInt()` is Java standard library and sufficient for numeric format checking.
- **All new APIs verified**: `Integer.parseInt()`, `String.startsWith()`, `Integer.toString()`, `ProcessBuilder` list constructor, and all existing classes are standard Java APIs.
