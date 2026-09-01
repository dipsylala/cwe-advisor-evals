## Verdict
Confirmed. Untrusted query string input flows directly into a JavaScript string literal without encoding, allowing XSS injection.

## Source
Line 14: `string searchTerm = Request.QueryString["q"];` reads untrusted input from the request.
Line 23: `Response.Write(script);` outputs the unencoded value into a JavaScript context within a string literal.

## Fix
Replace lines 16–20 with:

```csharp
string encodedSearchTerm = HttpUtility.JavaScriptStringEncode(searchTerm);
string script =
    "<script>" +
    "var lastSearch = '" + encodedSearchTerm + "';" +
    "trackSearch(lastSearch);" +
    "</script>";
```

## Explanation
The original code concatenates the untrusted `searchTerm` directly into a JavaScript string literal without escaping. An attacker can supply input like `'); alert('XSS'); ('` which breaks out of the string and injects arbitrary JavaScript.

`HttpUtility.JavaScriptStringEncode()` escapes special characters (quotes, backslashes, newlines, etc.) so the input is treated as data within the string literal, preventing the injection. This ensures the searchTerm remains confined to the string context regardless of its content.
