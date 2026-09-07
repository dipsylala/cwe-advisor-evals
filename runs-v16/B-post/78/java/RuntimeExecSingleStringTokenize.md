## Verdict

exploitable

## Source

HTTP request parameter `host` (line 23) via `request.getParameter("host")`

## Fix

**Vulnerable code (line 48-50):**
```java
String command = "ping -c " + PING_COUNT + " " + host;
// SAST FINDING: CWE-78
Process process = Runtime.getRuntime().exec(command);
```

**Fixed code:**
```java
// Validate host - reject values starting with dash (argument injection prevention)
// and allow only valid hostname/IP address characters
if (host.startsWith("-") || !host.matches("[a-zA-Z0-9.-]+")) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid host format");
    return;
}

// Use ProcessBuilder with separate arguments to prevent OS command injection
List<String> command = Arrays.asList("ping", "-c", String.valueOf(PING_COUNT), host);
Process process = new ProcessBuilder(command).start();
```

**Required import addition:**
```java
import java.util.Arrays;
import java.util.List;
```

## Explanation

The vulnerability occurs because the user-controlled `host` parameter is concatenated directly into a command string passed to `Runtime.getRuntime().exec()`. Although `exec(String)` tokenizes by whitespace rather than invoking a shell, the single-string overload is deprecated (since Java 18) and provides insufficient isolation of arguments. The fix replaces string concatenation with `ProcessBuilder` using separate argument arrays, which prevents the host value from being misinterpreted as shell syntax or additional options. Input validation is added as a secondary defence to reject values starting with `-` (preventing argument injection where the target `ping` command might interpret the value as a flag) and to restrict characters to valid hostname and IP address ranges (`[a-zA-Z0-9.-]+`). The `PING_COUNT` constant is safely converted to a string argument.

## Behaviour changes

- **Added input validation**: The endpoint now rejects host parameters that begin with a dash or contain characters outside the hostname/IP range. This is a correctness improvement that prevents both shell injection and argument injection, while remaining compatible with all valid hostnames and IPv4/IPv6 addresses expressed in standard notation.
- **Changed process execution API**: Replaced deprecated `Runtime.exec(String)` with `ProcessBuilder` using an explicit argument list. Both preserve the original stdout capture behavior and error handling contracts. ProcessBuilder provides clearer separation of command and arguments, making injection impossible through concatenation.
- **Added imports**: `java.util.Arrays` and `java.util.List` from the Java standard library; no external dependencies introduced.

## Verification

Compilation check on fixed code (standard library elements only):
- `java.util.Arrays` and `java.util.List`: confirmed present in Java standard library
- `Arrays.asList()`: standard variadic method producing `List<String>`
- `ProcessBuilder` constructor accepting `List<String>`: confirmed in Java SE documentation
- `ProcessBuilder.start()`: returns `Process` object as expected
- `String.valueOf()`: standard library method producing string representation of int
- Regex pattern `[a-zA-Z0-9.-]+`: valid Java regex syntax

All new APIs introduced are from `java.util` and `java.lang` standard library packages. No external dependencies. The fixed code maintains the same method signature, return type (`String`), and exception contract (`IOException`, `InterruptedException`) as the original, preserving the caller's error handling at lines 32-36.
