## Verdict

Confirmed. `host` and `count` are request parameters concatenated directly into a single command-line string (`"ping -n " + count + " " + host`) that is then handed to `cmd.exe /c`. `cmd.exe` re-parses that string as shell syntax, so metacharacters an attacker places in either `host` or `count` (`&`, `|`, `&&`, `||`, `>`, backtick-free but Windows still honors `&`/`|`/`^`) let them append and run arbitrary commands with the privileges of the app server process, e.g. `host=127.0.0.1 & calc.exe`.

## Source

`@RequestParam("host") String host` and `@RequestParam("count") String count` in `DiagnosticController.runPingDiagnostic` (`DiagnosticController.java`, lines 20-25) — both are attacker-controlled HTTP query parameters, concatenated unescaped into `diagnosticCommand`.

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

    // A DNS hostname (RFC 1123, dots allowed) or an IPv4/IPv6 literal.
    // Deliberately excludes anything ping.exe could read as a flag (a
    // leading '-') or that a shell could interpret as a metacharacter.
    private static final Pattern HOST_PATTERN =
            Pattern.compile("^[A-Za-z0-9]([A-Za-z0-9.:-]{0,253}[A-Za-z0-9])?$");

    private static final int MAX_PING_COUNT = 10;

    @GetMapping("/support/diagnostics/ping")
    public String runPingDiagnostic(@RequestParam("host") String host, @RequestParam("count") String count)
            throws IOException, InterruptedException {

        if (host == null || !HOST_PATTERN.matcher(host).matches()) {
            throw new IllegalArgumentException("Invalid host");
        }

        int packetCount;
        try {
            packetCount = Integer.parseInt(count);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid count");
        }
        if (packetCount < 1 || packetCount > MAX_PING_COUNT) {
            throw new IllegalArgumentException("Invalid count");
        }

        // Run ping.exe directly with a fixed argument array. No shell
        // (cmd.exe /c) is involved, so there is no command-line string for
        // the operating system to re-parse: each element reaches the child
        // process as a single literal argument regardless of its content.
        Process process =
                new ProcessBuilder("ping.exe", "-n", Integer.toString(packetCount), host).start();

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

Two changes close the injection, and both are necessary together:

1. **Drop `cmd.exe /c` and the concatenated command string.** `ProcessBuilder` now invokes `ping.exe` directly with a fixed argument array (`"ping.exe", "-n", packetCount, host`). Windows' `CreateProcess` passes each array element to the child as a discrete argument; there is no shell re-parsing a single string, so shell metacharacters (`&`, `|`, `&&`, `||`, `^`, `%VAR%`) in `host` or `count` no longer have any command-line syntax to land in.

2. **Validate both inputs before they reach the argument array.** An argument array alone stops shell-metacharacter injection but not the child program from reading a crafted value as one of its own flags. `count` is parsed with `Integer.parseInt` and bounded to 1-10, which both rejects non-numeric payloads and prevents a value like `-t` (an infinite, non-terminating ping) from being read as a flag. `host` is checked against `HOST_PATTERN`, a hostname/IPv4/IPv6 allowlist that also rejects a leading `-`, since a bare `ping.exe` (no `cmd.exe`) still parses its own arguments and would otherwise accept a host string starting with `-` as an additional flag. The pattern is justified here because the field has a well-defined format — a network host — unlike a free-form value where a strict allowlist would reject legitimate input.

Both parameters keep their original purpose (packet count and target host for `ping.exe`) and their expected value shapes are unchanged for legitimate callers, so this is not a breaking change for the diagnostic endpoint's normal use.
