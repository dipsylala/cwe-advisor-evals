## Verdict

exploitable (confidence: high)

CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-Site Scripting'), C#/ASP.NET Web Forms.

## Source

`Request.QueryString["q"]` (`JsContextUnencodedOutput.cs`, line 14) - the raw, attacker-controlled `q` query-string parameter, assigned to `searchTerm` with no validation or encoding.

## Fix

Vulnerable code (lines 16-23):

```csharp
string script =
    "<script>" +
    "var lastSearch = '" + searchTerm + "';" +
    "trackSearch(lastSearch);" +
    "</script>";

// SAST FINDING: CWE-79 reported here. Sink is the next statement.
Response.Write(script);
```

Fixed code:

```csharp
using System.Text.Encodings.Web;
// ...

string script =
    "<script>" +
    "var lastSearch = '" + JavaScriptEncoder.Default.Encode(searchTerm ?? string.Empty) + "';" +
    "trackSearch(lastSearch);" +
    "</script>";

Response.Write(script);
```

## Explanation

`searchTerm` flows unmodified from the query string into a single-quoted JavaScript string literal inside an inline `<script>` block, then straight to `Response.Write()`. A value such as `';alert(document.cookie);//` closes the literal and injects arbitrary script that executes in the victim's browser. `Response.Write()` performs no encoding of its own - it writes exactly the bytes it is given - so the responsibility sits entirely with the caller. Per the C# guidance, `<script>` is raw text to the browser, so HTML encoding is the wrong tool here (entities like `&#39;` are never decoded inside a script block and the value would still break out of the string); the correct context-specific encoder for a JS string-literal position is `JavaScriptEncoder.Default.Encode()` (`System.Text.Encodings.Web`), which escapes quotes, backslashes, angle brackets, and the U+2028/U+2029 line terminators that could otherwise terminate the literal or the statement. This is applied at the sink, matching the guidance's "encode at each output sink" principle, and uses the default (not `UnsafeRelaxedJsonEscaping`) encoder so `<`, `>`, and `&` remain escaped.

## Behaviour changes

- `?? string.Empty` was added around `searchTerm` before encoding. `JavaScriptEncoder.Default.Encode()` throws `ArgumentNullException` on a `null` input, whereas the original string concatenation (`"..." + searchTerm + "..."`) silently treated a missing `q` parameter as an empty string. The null-coalesce preserves the original sink's failure behaviour (no exception when `q` is absent) instead of introducing a new one. This is the only change beyond the encoding itself; the emitted markup, the `Response.Write()` call, its return value, and all other arguments are unchanged.
