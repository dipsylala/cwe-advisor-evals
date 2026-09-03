## Verdict
exploitable

## Source
`Request.QueryString["q"]` (line 14) — untrusted query string parameter

## Fix

**Vulnerable code (line 18):**
```csharp
"var lastSearch = '" + searchTerm + "';" +
```

**Fixed code:**
```csharp
"var lastSearch = '" + HttpUtility.JavaScriptStringEncode(searchTerm) + "';" +
```

## Explanation
The `searchTerm` is embedded directly into a JavaScript string literal without encoding. An attacker can inject a payload like `?q=';alert('XSS');//` to break out of the string and execute arbitrary JavaScript in the victim's browser. The fix applies `HttpUtility.JavaScriptStringEncode()` to escape special characters (quotes, backslashes, line terminators) that have meaning in JavaScript string literals, rendering them safe for inclusion in script source code.

## Behaviour changes
None. The encoded value remains a valid string that `trackSearch()` receives correctly, with only special characters escaped. `Response.Write()` continues to output the script block exactly as before, but with neutralized content.
