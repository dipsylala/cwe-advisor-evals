# CWE-78 Remediation - ProcessBuilderCmdWindows

## Verdict

Exploitable. The finding is a genuine OS command injection vulnerability. Untrusted user input (`host` and `count` parameters) is concatenated into a command string that is passed to `ProcessBuilder` with `cmd.exe /c`, which interprets the string as a shell command. An attacker can inject arbitrary shell metacharacters and commands.

**Example attack:**
- Request: `/support/diagnostics/ping?host=127.0.0.1%20%26%20calc.exe&count=1`
- Resulting command: `ping -n 1 127.0.0.1 & calc.exe`
- `cmd.exe /c` executes both the ping command and calc.exe

## Source

**Data source:** Request parameters `host` and `count` from line 20 in `DiagnosticController.java`

**Data flow:**
1. Line 20: `@RequestParam("host") String host` and `@RequestParam("count") String count` receive untrusted user input
2. Line 25: String concatenation builds a command: `"ping -n " + count + " " + host`
3. Line 28: The concatenated string is passed to `ProcessBuilder("cmd.exe", "/c", diagnosticCommand)` as the third argument

**Sink:** `ProcessBuilder.start()` at line 28

The vulnerability occurs because `cmd.exe /c` interprets its argument as a shell command string and parses shell metacharacters (`&`, `|`, `;`, `>`, `<`, etc.) and command substitution syntax. Since the user-controlled `host` and `count` values are part of that string, an attacker can break out of the intended ping command and execute arbitrary commands.

## Fix

**Vulnerable code (line 25-28):**
```java
String diagnosticCommand = "ping -n " + count + " " + host;

// SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
Process process = new ProcessBuilder("cmd.exe", "/c", diagnosticCommand).start();
```

**Fixed code:**
```java
// Validate count: must be a positive integer to prevent argument injection
int countValue;
try {
    countValue = Integer.parseInt(count);
    if (countValue <= 0 || countValue > 100) {
        return "Error: count must be between 1 and 100";
    }
} catch (NumberFormatException e) {
    return "Error: count must be a valid integer";
}

// Validate host: reject option injection (leading dash) and excessive length
if (host == null || host.isEmpty() || host.startsWith("-") || host.length() > 255) {
    return "Error: invalid host";
}

// Execute ping.exe directly without shell interpretation (no cmd.exe /c)
// Use absolute path to prevent PATH hijacking
Process process = new ProcessBuilder("C:\\Windows\\System32\\ping.exe", "-n",
        String.valueOf(countValue), host).start();
```

The rest of the output handling code (lines 30-44) remains unchanged.

## Explanation

The fix eliminates the vulnerability through three mechanisms:

1. **Remove shell invocation:** The primary fix replaces `ProcessBuilder("cmd.exe", "/c", diagnosticCommand)` with `ProcessBuilder("C:\\Windows\\System32\\ping.exe", "-n", String.valueOf(countValue), host)`. This invokes `ping.exe` directly as a native executable without going through a shell interpreter. `cmd.exe` is no longer in the chain, so shell metacharacters in the arguments are never parsed as command operators.

2. **Separate arguments (no string concatenation):** By passing `"-n"` and the host as separate array arguments to `ProcessBuilder`, instead of concatenating them into a single shell command string, we prevent shell metacharacter injection. `ProcessBuilder` without shell invocation passes arguments directly to the program without shell parsing.

3. **Input validation:** The fix adds secondary-layer validation on both parameters:
   - **`count` validation:** Parsed as an integer with a range check (1-100). This prevents both shell injection and argument injection via option flags (e.g., `-n` values that start with dash).
   - **`host` validation:** Rejects null/empty values, values starting with `-` (preventing option injection to ping.exe), and values exceeding 255 characters. This ensures the host parameter cannot be misinterpreted as a ping option or other command.

4. **Absolute path:** Using the full path `C:\\Windows\\System32\\ping.exe` prevents PATH hijacking vulnerabilities where a writable directory earlier in `PATH` could substitute a malicious executable named `ping.exe`.

The fix preserves the existing behavior: it still returns the output of the `ping` command to the caller with the same exit code reporting. No discarded output is recovered, and the contract of the method remains unchanged.

## Behaviour changes

**Input validation changes (security hardening, not a regression):**
- Invalid `count` values (non-integer, out of range 1-100) now return an error message instead of raising an exception. This is a controlled error path rather than a breaking change in behavior.
- Invalid `host` values (null, empty, starting with `-`, or longer than 255 characters) now return an error message instead of being passed to `ping.exe`. This is a practical hardening that rejects malformed input that would fail anyway.

**Process execution change:**
- The process is invoked directly as `ping.exe` (with absolute path) instead of through `cmd.exe /c`. This is the core fix that closes the vulnerability. The ping command output, return behavior, and exception contract are identical; only the invocation mechanism changed.

**No other changes:** All output handling (BufferedReader, StringBuilder, System.lineSeparator, exit code reporting) is preserved identically from the original code.

