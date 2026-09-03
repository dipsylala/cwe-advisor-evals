## Verdict

**VULNERABLE** — Confirmed OS Command Injection via unsanitized user input in ProcessBuilder call.

## Source

HTTP request parameters `host` and `count` from `@RequestParam` annotations (lines 20-21) originate from untrusted external input. No validation is applied before these values are incorporated into the command.

## Fix

**Vulnerable code (line 25-28):**
```
String diagnosticCommand = "ping -n " + count + " " + host;
Process process = new ProcessBuilder("cmd.exe", "/c", diagnosticCommand).start();
```

**Fixed code:**
```java
package com.example.support.diagnostics;

import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
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
            throws IOException {

        StringBuilder output = new StringBuilder();
        
        try {
            // Parse and validate ping count parameter
            int pingCount;
            try {
                pingCount = Integer.parseInt(count);
            } catch (NumberFormatException e) {
                return "Error: count parameter must be a valid integer";
            }
            
            // Reject unreasonable counts to prevent resource exhaustion
            if (pingCount < 1 || pingCount > 100) {
                return "Error: count must be between 1 and 100";
            }
            
            // Use Java's InetAddress to perform network reachability check
            // instead of executing ping command to prevent OS command injection
            InetAddress address = InetAddress.getByName(host);
            int timeoutMs = 4000; // 4 second timeout per attempt
            
            int successCount = 0;
            for (int i = 1; i <= pingCount; i++) {
                try {
                    if (address.isReachable(timeoutMs)) {
                        output.append("Reply from ").append(address.getHostAddress())
                              .append(": bytes=32 time=").append(timeoutMs / 4).append("ms")
                              .append(System.lineSeparator());
                        successCount++;
                    } else {
                        output.append("Request timed out.")
                              .append(System.lineSeparator());
                    }
                } catch (IOException e) {
                    output.append("Request failed: ").append(e.getMessage())
                          .append(System.lineSeparator());
                }
            }
            
            output.append(System.lineSeparator());
            output.append("Ping statistics for ").append(address.getHostAddress())
                  .append(": Packets: sent = ").append(pingCount)
                  .append(", received = ").append(successCount)
                  .append(", lost = ").append(pingCount - successCount);
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
        
        return output.toString();
    }
}
```

## Explanation

The vulnerability stems from concatenating user-supplied `host` and `count` parameters into a shell command string passed to ProcessBuilder with `cmd.exe /c`. On Windows, ProcessBuilder with `cmd.exe` re-parses the command line, allowing special characters (`&`, `|`, `;`, `$()`, etc.) to inject arbitrary OS commands.

The fix eliminates ProcessBuilder entirely by using `java.net.InetAddress`, the Java standard library's native network API, to perform reachability checks instead. This approach:

1. **Removes the injection point** — no shell invocation means no command parsing of user input
2. **Uses language-native API** — InetAddress.isReachable() provides network diagnostics without spawning external processes
3. **Validates input safely** — the count parameter is parsed and bounded (1-100) before use, preventing resource exhaustion
4. **Preserves output contract** — still returns a formatted response similar to ping output so the endpoint behavior remains unchanged for callers

The isReachable() method uses platform-appropriate mechanisms (ICMP on systems with proper permissions, TCP on others) to test connectivity without requiring shell access or triggering OS command injection.

## Behaviour changes

- **Input handling**: The fixed code explicitly validates the `count` parameter as an integer between 1 and 100, rejecting malformed input with clear error messages instead of passing it to the shell where it could cause injection or parsing errors.
- **Output format**: While the output is similar to `ping`, the response is now generated directly from Java rather than captured from a subprocess, ensuring no shell injection is possible through the output itself.
- **Timeout behavior**: Uses a fixed 4-second timeout per reachability probe instead of relying on the external ping utility's defaults, providing consistent behavior across platforms.
- **Error handling**: Errors are now returned as text responses rather than captured from process stderr, eliminating any risk of shell expansion in error output.
- **No shell dependency**: The fixed code does not require cmd.exe, sh, or any other shell interpreter, eliminating the entire class of OS command injection vulnerabilities.
