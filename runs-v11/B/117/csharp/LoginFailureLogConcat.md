## Verdict

exploitable

## Source

The `username` parameter at line 18 is untrusted user input from an ASP.NET Core POST form binding (`[FromForm] string username`). An attacker can supply values containing newlines, null bytes, or Unicode line separators (U+0085, U+2028, U+2029).

## Fix

**Vulnerable code:**
```csharp
_logger.LogWarning($"Failed login attempt for user: {username}");
```

**Fixed code:**
```csharp
using System.Text.Encodings.Web;

// In the Login method:
var encodedUsername = JavaScriptEncoder.Default.Encode(username);
_logger.LogWarning("Failed login attempt for user: {Username}", encodedUsername);
```

## Explanation

The original code interpolates untrusted user input directly into a log message via string interpolation (`$"...{username}"`). An attacker can inject newline characters or Unicode line separators to forge additional log entries or hide malicious activity from audit logs.

The fix applies two changes recommended by CWE-117 guidance for C#:

1. **Encode at the call site**: `JavaScriptEncoder.Default.Encode(username)` escapes the full set of problematic characters—ASCII control range (0x00-0x1F), DEL (0x7F), U+0085, U+2028, U+2029, and the backslash—so a literal `\n` and a real newline render differently in logs. This closes the finding regardless of what logging formatter the application is configured with.

2. **Use parameterized logging**: Replace string interpolation with a message template (`"Failed login attempt for user: {Username}"`) and pass the value as a parameter. This separates the template structure from data, allowing encoding-aware sinks to handle the value correctly and preventing injection through template manipulation.

## Behaviour changes

none

The fix preserves the `LogWarning` return value (void), log level, message template structure, and all existing behavior while eliminating the injection vector. The encoded value is indistinguishable from the original when displayed in logs (legitimate punctuation and non-ASCII text remain readable), and the message template maintains the same semantics as the original interpolation.

