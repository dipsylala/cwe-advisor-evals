## Verdict

Exploitable. The `searchTerm` value from the untrusted query string parameter `Request.QueryString["q"]` flows directly into a JavaScript string context inside a `<script>` block via `Response.Write()` without encoding. An attacker can inject a quote character to break out of the string and execute arbitrary JavaScript.

## Source

`Request.QueryString["q"]` (line 14) — untrusted user input from the HTTP query string, used unencoded at the concatenation point (line 18) and rendered via the sink `Response.Write()` (line 23) into a JavaScript string literal.

## Fix

**Vulnerable Code (lines 16-23):**
```csharp
string script =
    "<script>" +
    "var lastSearch = '" + searchTerm + "';" +
    "trackSearch(lastSearch);" +
    "</script>";

Response.Write(script);
```

**Fixed Code:**
```csharp
string encodedSearchTerm = HttpUtility.JavaScriptStringEncode(searchTerm);
string script =
    "<script>" +
    "var lastSearch = '" + encodedSearchTerm + "';" +
    "trackSearch(lastSearch);" +
    "</script>";

Response.Write(script);
```

## Explanation

The fix applies JavaScript string encoding using `HttpUtility.JavaScriptStringEncode()` to the untrusted `searchTerm` before concatenating it into the JavaScript literal. This method escapes special characters (quotes, backslashes, line terminators) that would otherwise allow breaking out of the string and injecting arbitrary code. For example, an input of `'; alert('xss'); //` becomes `\'; alert(\'xss\'); //` after encoding, which renders as data within the string literal rather than executable code. The `HttpUtility` class is already available via the `System.Web` namespace imported at line 2, so no additional dependencies are required.

## Behaviour changes

None. The encoded value retains the semantic content of the original input — characters are escaped rather than stripped or transformed — so legitimate search terms containing quotes or backslashes continue to work as intended. The sink contract of `Response.Write()` remains unchanged: it still outputs the complete script string to the HTTP response body.
