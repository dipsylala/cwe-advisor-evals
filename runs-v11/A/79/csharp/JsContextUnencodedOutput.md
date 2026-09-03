## Verdict
Confirmed XSS vulnerability. Untrusted query string input is concatenated directly into a JavaScript string literal without encoding, allowing an attacker to inject arbitrary JavaScript by breaking out of the string context.

## Source
Line 23: `Response.Write(script);`

The script string is constructed on lines 16–20 by concatenating `searchTerm` (from `Request.QueryString["q"]`) directly into a JavaScript string literal without any encoding:
```
"var lastSearch = '" + searchTerm + "';"
```

An attacker can inject a single quote and arbitrary JavaScript code to break out of the string and execute code.

## Fix
Use `System.Web.HttpUtility.JavaScriptStringEncode()` to encode the `searchTerm` before inserting it into the JavaScript string:

```csharp
string encodedSearchTerm = HttpUtility.JavaScriptStringEncode(searchTerm);
string script =
    "<script>" +
    "var lastSearch = '" + encodedSearchTerm + "';" +
    "trackSearch(lastSearch);" +
    "</script>";
Response.Write(script);
```

`JavaScriptStringEncode()` escapes special characters (single quotes, double quotes, backslashes, newlines, etc.) so they are interpreted as literal string content rather than JavaScript syntax, preventing the attacker from breaking out of the string.

## Explanation
CWE-79 requires context-aware encoding. HTML encoding (e.g., `HttpUtility.HtmlEncode()`) is insufficient here because the output is inside a JavaScript string literal, not an HTML attribute or text node. JavaScript has its own escape rules: single and double quotes must be escaped or the string context is broken, allowing code injection.

The `JavaScriptStringEncode()` method handles all characters that have special meaning in JavaScript string contexts, ensuring that malicious input like `'; alert('XSS'); //` is safely rendered as the literal string content `\'; alert(\'XSS\'); //`, preventing script injection.
