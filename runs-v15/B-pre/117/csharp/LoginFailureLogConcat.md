## Verdict

CWE-117 confirmed. The `username` parameter flows directly from HTTP form input to a log message via string interpolation without encoding, allowing an attacker to inject newlines and control characters to forge log entries or break log parsing.

## Source

HTTP form parameter `username` (line 18, `[FromForm] string username`) flows untrusted into the log message at line 23.

## Fix

Add `using System.Text.Json;` to the imports, then replace line 23:

```csharp
// Vulnerable:
_logger.LogWarning($"Failed login attempt for user: {username}");

// Fixed:
var encodedUsername = JavaScriptEncoder.Default.Encode(username);
_logger.LogWarning("Failed login attempt for user: {Username}", encodedUsername);
```

## Explanation

The fix addresses the injection point in two ways: (1) encoding the username to escape ASCII control characters (0x00-0x1F), DEL (0x7F), U+0085, U+2028, U+2029, and backslash, so an attacker cannot inject log separators; and (2) replacing string interpolation with a parameterized message template, which separates the template from the value. The parametrized form alone does not encode, but it is required for a JSON-aware sink to encode correctly, and the explicit `JavaScriptEncoder` call closes the weakness under any formatter configuration (standard JSON formatter, Serilog, or plain text).

## Behaviour changes

Newlines, null bytes, and Unicode line separators in legitimate usernames are now escaped (e.g., `user\nname` renders as `user\nname` in the log, not split across two lines). The log message structure and timestamp/level behavior remain unchanged. No exception handling changes are needed; `JavaScriptEncoder` does not throw on valid string input.
