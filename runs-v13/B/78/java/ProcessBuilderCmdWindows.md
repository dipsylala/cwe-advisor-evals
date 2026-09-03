## Verdict
Exploitable

## Source
HTTP request parameters `host` and `count` from the `@RequestParam` annotations on line 20.

## Fix

**Vulnerable Code (line 25-28):**
```java
String diagnosticCommand = "ping -n " + count + " " + host;
Process process = new ProcessBuilder("cmd.exe", "/c", diagnosticCommand).start();
```

**Fixed Code:**
```java
// Validate count is a positive integer
try {
    int packetCount = Integer.parseInt(count);
    if (packetCount <= 0 || packetCount > 100) {
        throw new IllegalArgumentException("count must be between 1 and 100");
    }
} catch (NumberFormatException e) {
    throw new IllegalArgumentException("count must be a positive integer", e);
}

// Validate host is a valid hostname or IP address (reject flags)
if (host.startsWith("-") || !host.matches("^[a-zA-Z0-9.:_-]+$") || host.length() > 255) {
    throw new IllegalArgumentException("Invalid hostname or IP address");
}

// Use ProcessBuilder with separate arguments instead of shell invocation
Process process = new ProcessBuilder("ping.exe", "-n", count, host).start();
```

## Explanation
The original code concatenated user-supplied `host` and `count` parameters into a shell command string, then passed it to `ProcessBuilder` with `cmd.exe /c`, which interprets the string as a Windows shell command. This allows command injection through shell metacharacters—an attacker could supply a host like `example.com & del /s /q C:\` to execute arbitrary commands. The fix eliminates shell invocation by passing ping.exe and its arguments directly to ProcessBuilder as a separate argument list, preventing shell interpretation. Input validation on both parameters acts as a secondary defense: `count` is restricted to a numeric range (1-100), and `host` is validated against a pattern that rejects option flags (starting with `-`) and dangerous characters, limiting the attack surface from argument injection (CWE-88). The code preserves the original behavior—ping is still invoked, output is still captured and returned—while eliminating the injection vulnerability.

## Behaviour changes
- ProcessBuilder now invokes `ping.exe` directly with separate arguments instead of routing through `cmd.exe /c`, preventing shell metacharacter interpretation
- Input validation rejects `count` values that are not positive integers or are outside the 1-100 range, with a specific exception message
- Input validation rejects `host` values that start with `-` (to prevent flag injection), contain invalid characters, or exceed 255 characters, with a specific exception message
- Invalid inputs now throw `IllegalArgumentException` instead of being silently passed to the subprocess; callers must handle this exception or let it propagate as an HTTP 500 response (this is a behavioral change that improves security by rejecting malformed input early)
