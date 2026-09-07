## Verdict

Confirmed. Line 23 writes untrusted user input (`username` from HTTP form data) directly into a log message via string interpolation, allowing log injection through newlines and control characters.

## Source

`username` parameter at line 18: `[FromForm] string username` - HTTP request form data, untrusted.

## Fix

Replace the string interpolation with a message template and encode the username to escape control characters, newlines, and Unicode line separators:

**Original (line 23):**
```csharp
_logger.LogWarning($"Failed login attempt for user: {username}");
```

**Fixed (add using statement and replace line 23):**

Add to usings:
```csharp
using System.Text.Encodings.Web;
```

Replace line 23 with:
```csharp
var encodedUsername = JavaScriptEncoder.Default.Encode(username);
_logger.LogWarning("Failed login attempt for user: {Username}", encodedUsername);
```

## Explanation

The original code concatenates untrusted `username` directly into the log string, allowing an attacker to inject newlines (`\n`), carriage returns (`\r`), and Unicode line separators (U+2028, U+2029) to forge false log entries or hide malicious activity.

The fix applies two controls: (1) `JavaScriptEncoder.Default.Encode()` escapes the full ASCII control range (0x00-0x1F), DEL (0x7F), and Unicode separators (U+0085, U+2028, U+2029), plus the backslash itself, so a literal backslash-n and a real newline render differently and cannot be confused; (2) replacing string interpolation with a message template (`{Username}` placeholder) separates the template from the value, allowing the logger framework to handle the value as data, not structure.

`JavaScriptEncoder` is part of `System.Text.Encodings.Web` (standard library in .NET Framework 4.5+, .NET Core 1.0+) and escapes the character ranges this CWE requires regardless of which logging formatter the application is configured with—this matters because Serilog's JSON formatters do not escape past ASCII controls, and plain-text sinks do not encode at all.

## Behaviour changes

**Before**: Attacker input containing `\n` or CR/LF characters appears in logs verbatim, forging new log entries on the same line or appearing on separate lines as if they were legitimate application events.

**After**: Input containing `\n` becomes the encoded string `
`, preserving the original username in the log while making it clear an injection attempt was made. Legitimate usernames containing ordinary punctuation or non-ASCII letters (e.g., `jérôme` or `user+tag`) still log correctly—encoding only affects control characters and line separators, not printable text.
