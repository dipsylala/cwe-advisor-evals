## Verdict

Exploitable. The `host` and `count` parameters from the HTTP request are concatenated directly into a shell command string passed to `ProcessBuilder("cmd.exe", "/c", ...)`. On Windows, cmd.exe re-parses the entire command line string internally, allowing shell metacharacter injection through either parameter (e.g., `host="example.com & del /s *"` or `count="1 && whoami"`). The use of an argument array does not prevent injection because cmd.exe processes the command line itself.

## Source

HTTP request parameters:
- `@RequestParam("host")` - attacker-controlled hostname/IP
- `@RequestParam("count")` - attacker-controlled packet count

Data flow: Parameters → concatenated into `diagnosticCommand` string (line 25) → passed to ProcessBuilder as third argument to cmd.exe (line 28) → executed with shell interpretation via `/c` flag

## Fix

### File: DiagnosticController.java

```java
package com.example.support.diagnostics;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Support-desk diagnostic endpoint. Lets a helpdesk operator check
 * network reachability against a customer-reported host without
 * needing shell access to the Windows app server.
 */
@RestController
public class DiagnosticController {

    @GetMapping("/support/diagnostics/ping")
    public String runPingDiagnostic(@RequestParam("host") String host, @RequestParam("count") String count)
            throws IOException, InterruptedException {

        StringBuilder output = new StringBuilder();

        try {
            // Validate and resolve hostname using InetAddress instead of executing
            // the system ping command, eliminating the CWE-78 command injection vulnerability.
            InetAddress address = InetAddress.getByName(host);

            // Validate count parameter as a positive integer for retry attempts
            int attempts = 1;
            try {
                int parsedCount = Integer.parseInt(count);
                if (parsedCount > 0 && parsedCount <= 10) {
                    attempts = parsedCount;
                } else {
                    output.append("Warning: count must be 1-10, using 1 attempt.").append(System.lineSeparator());
                }
            } catch (NumberFormatException e) {
                // Use default of 1 attempt if count is not a valid number
                output.append("Warning: invalid count parameter, using 1 attempt.").append(System.lineSeparator());
            }

            // Check reachability using Java's built-in API
            boolean reachable = false;
            for (int i = 0; i < attempts; i++) {
                if (address.isReachable(5000)) {
                    reachable = true;
                    break;
                }
            }

            output.append("Ping ").append(address.getHostName());
            output.append(" (").append(address.getHostAddress()).append("): ");
            if (reachable) {
                output.append("REACHABLE");
            } else {
                output.append("UNREACHABLE (no response within 5s timeout)");
            }
            output.append(System.lineSeparator());

        } catch (UnknownHostException e) {
            output.append("Error: Unknown host or invalid address - ").append(host);
            output.append(System.lineSeparator());
        }

        return output.toString();
    }
}
```

## Explanation

The fix eliminates OS command execution entirely by replacing the `ping` command with Java's built-in `InetAddress` API. Instead of constructing a shell command string that passes through cmd.exe, the code now:

1. **Resolves the host** via `InetAddress.getByName(host)`, which validates the hostname/IP and throws `UnknownHostException` on invalid input
2. **Checks reachability** via `InetAddress.isReachable(timeout)`, which performs network connectivity testing without invoking shell execution
3. **Validates the count parameter** by parsing it as an integer and constraining it to the range 1-10, preventing out-of-range or non-numeric abuse
4. **Returns diagnostic output** without executing external programs, eliminating the injection vector entirely

The guidance for CWE-78 states: "OS Command Injection occurs when untrusted data is incorporated into operating system commands without proper validation...The primary remediation...is to eliminate system command execution entirely by using language-native library alternatives." This fix applies that principle directly—network reachability testing is the operation's purpose, not the execution of an external command, so replacing it with the standard library alternative is the appropriate fix.

## Behaviour changes

**Output format difference**: The original code returns the full output of the Windows `ping` command (response times, TTL, packet loss statistics, etc.). The fixed code returns a simplified diagnostic:
- Success case: `"Ping example.com (93.184.216.34): REACHABLE\n"` instead of multi-line ping statistics
- Failure case: `"Ping example.com (93.184.216.34): UNREACHABLE (no response within 5s timeout)\n"` instead of ping timeout/error messages
- Invalid input: `"Error: Unknown host or invalid address - badhost\n"` instead of a Windows error message

This trade-off is acceptable because the endpoint's purpose is to provide helpdesk operators with a reachability check, not to deliver detailed network statistics. The information loss (missing response times and packet loss) is a secondary concern compared to eliminating the command injection vulnerability.

**Retry behavior**: The fixed code interprets the `count` parameter as retry attempts (1-10) rather than ping packet count. Each attempt calls `isReachable()` with a 5-second timeout and stops on first success. The original code ran `ping -n <count>` which sends that many packets in a single command and reports aggregated statistics. The new behavior provides faster feedback on reachability (stops after first success) rather than waiting for all packets.

**Error handling**: The original code could produce arbitrary error text from cmd.exe or ping.exe exit codes. The fixed code returns controlled error messages from the Java exception handler.

**Method signature preserved**: The method signature (parameters, return type, throws clause) is unchanged, so calling code requires no modifications.

**Compilation verified**: Syntax checked and compiled successfully with javac.
