## Verdict

CWE-78, exploitable, confidence: high.

## Source

- **Source**: `host` and `count`, both `@RequestParam` values on the `GET /support/diagnostics/ping` endpoint (`DiagnosticController.runPingDiagnostic`, lines 20-25) - unauthenticated, attacker-controlled query parameters.
- **Data flow**: both parameters are concatenated with no validation into `diagnosticCommand = "ping -n " + count + " " + host` (line 25), a single string.
- **Sink**: `new ProcessBuilder("cmd.exe", "/c", diagnosticCommand).start()` (line 28). `cmd.exe /c` re-parses that whole string as a shell command line, so shell metacharacters in either `count` or `host` (`&`, `|`, `&&`, `` ` ``, etc.) let an attacker append arbitrary commands - e.g. `host=127.0.0.1 & calc`.
- **Sink contract preserved by the fix**: the call returns a `Process` whose stdout is read line-by-line into `output`; stderr is never consumed (discarded, as originally); a non-zero exit code appends a note rather than throwing; `IOException`/`InterruptedException` remain declared and propagate unchanged. This is the "keep and execute safely" case from the CWE-78 guidance - `ping` has no Java library equivalent (`InetAddress.isReachable()` falls back to a TCP connect that reports live hosts as unreachable), so the fix keeps `ProcessBuilder` and removes the shell instead of replacing the call.

## Fix

No library substitute applies (see Source). The fix removes `cmd.exe /c` and the concatenated string, validates both parameters against an allowlist for the format the application already expects, and invokes `ping.exe` by absolute path with each argument as its own array element.

### File: DiagnosticController.java

```java
package com.example.support.diagnostics;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Support-desk diagnostic endpoint. Lets a helpdesk operator kick off a
 * network reachability check against a customer-reported host without
 * needing shell access to the Windows app server.
 */
@RestController
public class DiagnosticController {

    // Positive integer only, capped at 4 digits - matches the practical
    // range of a "-n" ping count and cannot begin with '-' or contain
    // whitespace/shell metacharacters.
    private static final Pattern COUNT_PATTERN = Pattern.compile("\\A[1-9][0-9]{0,3}\\z");

    // Hostname or IPv4/IPv6 literal: letters, digits, dots, colons and
    // internal hyphens only. Rejects a leading '-' (so the value cannot be
    // read as a flag by ping.exe), whitespace, and shell metacharacters.
    private static final Pattern HOST_PATTERN =
            Pattern.compile("\\A[A-Za-z0-9:][A-Za-z0-9.:-]{0,253}\\z");

    @GetMapping("/support/diagnostics/ping")
    public String runPingDiagnostic(@RequestParam("host") String host, @RequestParam("count") String count)
            throws IOException, InterruptedException {

        if (!COUNT_PATTERN.matcher(count).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "count must be a positive integer");
        }
        if (!HOST_PATTERN.matcher(host).matches()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "host must be a hostname or IP address with no shell characters");
        }

        // Invoke ping.exe by absolute path with a separate argument per
        // element - no shell (no cmd.exe /c, no concatenated command line).
        String systemRoot = System.getenv("SystemRoot");
        if (systemRoot == null || systemRoot.isEmpty()) {
            systemRoot = "C:\\Windows";
        }
        Path pingExecutable = Paths.get(systemRoot, "System32", "PING.EXE");

        Process process = new ProcessBuilder(pingExecutable.toString(), "-n", count, host).start();

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

The injection came from building one shell command-line string out of two untrusted parameters and handing it to `cmd.exe /c`, which re-parses it and treats shell metacharacters as command separators. The fix drops the shell entirely: `count` and `host` are each checked against a narrow allowlist for the format the application already expects (a positive integer; a hostname/IPv4/IPv6-style literal with no leading `-`, whitespace, or shell metacharacters), then `ping.exe` is invoked directly by its absolute path (`%SystemRoot%\System32\PING.EXE`, avoiding a writable-`PATH` substitution) with `-n`, `count`, and `host` as three separate `ProcessBuilder` argument-array elements. Because there is no shell in the call chain, no reparsing of a concatenated string ever happens, so shell metacharacters in either parameter have no special meaning even before the allowlist is considered; the allowlist is the second layer, and it also blocks a leading `-` on `host`, which would otherwise let the value be read as a `ping` flag (argument injection, CWE-88) since Windows `ping.exe` has no `--` end-of-options marker to insert instead. `ping` itself is kept rather than replaced, per the guidance: no JDK API performs an ICMP echo (`InetAddress.isReachable()` falls back to a TCP probe that misreports reachable hosts as down), so removing the call would be a regression, not a fix.

## Behaviour changes

- A `host` or `count` that fails its allowlist now short-circuits with `ResponseStatusException(400)` before any process starts, instead of reaching `cmd.exe`. This is a new failure path required by the fix; previously such input either reached `ping` in a broken form or, for the exploit case, executed attacker commands.
- `count` is now restricted to `1`-`9999` with no leading zero (e.g. `"01"` is now rejected). The application never specified a wider legitimate range, and this bound is the validation format the allowlist rule requires; it does not narrow any documented use of the endpoint.
- `host` is now restricted to hostname/IPv4/IPv6 characters (letters, digits, dots, colons, internal hyphens) and cannot start with `-` or contain whitespace. A DNS hostname or IP literal cannot begin with `-` anyway, so no legitimate value is excluded; this is the primary control that closes the injection, together with the shell removal below.
- `cmd.exe /c "<concatenated string>"` is replaced with a direct, shell-less invocation of `ping.exe` by absolute path, with `-n`, `count`, and `host` as separate argument-array elements. This is the mechanism that removes the sink's exposure to shell metacharacters.
- Unchanged: stdout is read the same way into the same `output` buffer; stderr is still never consumed (no new output surfaced); the non-zero-exit-code note is unchanged; the declared `throws IOException, InterruptedException` and the `String` return type/shape are unchanged.

**Verification**: Compiled with `javac` against minimal stub definitions of the Spring types used (`@RestController`, `@GetMapping`, `@RequestParam`, `ResponseStatusException`, `HttpStatus`) - zero errors or warnings, confirming the file is syntactically and referentially correct (every import resolves, every method/constructor call matches a real signature). The original file, compiled the same way with only its own imports, produces exclusively "package does not exist" errors for the same Spring classes, confirming those errors are a missing-classpath artifact and not evidence of a problem in the new code. The two allowlist regexes were additionally exercised standalone with `java` against representative inputs (hostnames, IPv4, IPv6 literals, shell-metacharacter payloads, boundary and malformed counts) and matched as intended in every case.

**Assumptions**: No build file is present in the case directory to confirm the exact Spring version; the annotations and `ResponseStatusException` used are unchanged from, or already implied by, the original file's own Spring Web imports, so no new dependency is introduced. The host allowlist admits `:` to avoid excluding legitimate IPv6 literals, per the guidance's caution against allowlists that reject valid values. The `count` upper bound of `9999` is an assumption about a reasonable operator-facing limit, not a value stated anywhere in the code or request.
