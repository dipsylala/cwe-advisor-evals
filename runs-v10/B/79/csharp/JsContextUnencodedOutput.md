## Verdict
Exploitable

## Source
`Request.QueryString["q"]` (line 14) - untrusted user input from HTTP query string parameter

## Fix

**Vulnerable code:**
```csharp
string searchTerm = Request.QueryString["q"];

string script =
    "<script>" +
    "var lastSearch = '" + searchTerm + "';" +
    "trackSearch(lastSearch);" +
    "</script>";

Response.Write(script);
```

**Fixed code:**
```csharp
using System.Text.Encodings.Web;

// ... in Page_Load:
string searchTerm = Request.QueryString["q"];

string encodedSearchTerm = JavaScriptEncoder.Default.Encode(searchTerm);
string script =
    "<script>" +
    "var lastSearch = '" + encodedSearchTerm + "';" +
    "trackSearch(lastSearch);" +
    "</script>";

Response.Write(script);
```

## Explanation
The untrusted query string parameter `q` is concatenated directly into a JavaScript string literal without encoding. An attacker can inject JavaScript code such as `');alert('XSS');('` to break out of the string and execute arbitrary script. The fix applies `JavaScriptEncoder.Default.Encode()` to the untrusted value before placing it into the JavaScript context. This encodes special characters (including single quotes) so they cannot break out of the literal. The encoder transforms characters that have meaning in JavaScript strings, preventing context escape.

## Behaviour changes
None. `JavaScriptEncoder.Default.Encode()` preserves the semantic meaning of the value while neutralizing special characters - legitimate search terms containing quotes, backslashes, or other special characters are preserved and rendered correctly without breaking the JavaScript syntax.
